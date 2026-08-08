use super::{
    color_enabled_for_stderr, color_enabled_for_stdout, format_timestamp, paint, print_json,
    AccessCommands, AnsiColor, ApiCommands, ApprovalCommands, ConfigCommands, McpCommands,
    VerbCommands, VerbCoverageCommands, EXIT_GUARD_ACCESS_DECISION_FAILED, EXIT_GUARD_DENIED,
    EXIT_GUARD_ERROR, EXIT_GUARD_HELD, JSON_SCHEMA_VERSION,
};
use crate::{client_config, daemon_client, defaults, mcp, server};
use anyhow::{Context, Result};
use guard::env::guard_env;
use std::collections::HashMap;
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;

/// Consequence-gating options parsed from `guard run` flags.
pub(crate) struct GatingOptions {
    pub(crate) revert: Option<String>,
    pub(crate) confirm_check: Option<String>,
    pub(crate) revert_control_path: Option<String>,
    pub(crate) confirm_within: Option<u64>,
    pub(crate) require_approval: bool,
    pub(crate) wait_approval: Option<u64>,
    pub(crate) reevaluate: bool,
}

pub(crate) struct RunInjections {
    pub(crate) env: HashMap<String, String>,
    pub(crate) secrets: HashMap<String, String>,
    pub(crate) secret_files: HashMap<String, String>,
}

/// CLI spelling of the ssh host-key mode. Kebab-case value names
/// (`only-existing`, `accept-new`, `accept-all`) are derived by clap.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum SshHostKeyCliMode {
    OnlyExisting,
    AcceptNew,
    AcceptAll,
}

fn client_config_error(message: impl Into<String>) -> serde_json::Value {
    serde_json::json!({
        "schema_version": JSON_SCHEMA_VERSION,
        "type": "client_config_error",
        "error": {
            "code": "invalid_client_config",
            "message": message.into(),
        },
    })
}

/// Load the client configuration without silently selecting a default
/// endpoint when a configured file is unreadable or malformed.
pub(crate) fn load_client_config(json: bool) -> Result<client_config::ClientConfig> {
    match client_config::ClientConfig::load().context("failed to load client config") {
        Ok(config) => Ok(config),
        Err(error) if json => {
            // Keep stdout machine-readable for commands that promised JSON.
            // If stdout itself is broken, there is no secondary human payload.
            let _ = print_json(&client_config_error(format!("{error:#}")));
            std::process::exit(EXIT_GUARD_ERROR);
        }
        Err(error) => Err(error),
    }
}

fn read_secret_input(prompt: &str) -> Result<String> {
    let value = if std::io::stdin().is_terminal() {
        rpassword::prompt_password(prompt)?
    } else {
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
    };
    if value.is_empty() {
        anyhow::bail!("secret value must not be empty");
    }
    Ok(value)
}

impl From<SshHostKeyCliMode> for server::SshHostKeyMode {
    fn from(value: SshHostKeyCliMode) -> Self {
        match value {
            SshHostKeyCliMode::OnlyExisting => Self::OnlyExisting,
            SshHostKeyCliMode::AcceptNew => Self::AcceptNew,
            SshHostKeyCliMode::AcceptAll => Self::AcceptAll,
        }
    }
}

/// Parse a `--revert "binary arg1 arg2"` string into a structured RevertSpec
/// (no shell is ever run; this only splits the operator's command into argv).
fn parse_revert(spec: &str) -> Result<server::RevertSpec> {
    let parts =
        shell_words::split(spec).map_err(|e| anyhow::anyhow!("invalid --revert command: {}", e))?;
    let mut it = parts.into_iter();
    let binary = it
        .next()
        .ok_or_else(|| anyhow::anyhow!("--revert command is empty"))?;
    Ok(server::RevertSpec::new(binary, it.collect()))
}

fn print_coverage(coverage: &Option<guard::gating::Coverage>) {
    let color = color_enabled_for_stderr();
    if let Some(c) = coverage {
        for line in &c.checked {
            eprintln!(
                "  {}     {}",
                paint("checked:", AnsiColor::Green, color),
                line
            );
        }
        for line in &c.not_checked {
            eprintln!(
                "  {} {}",
                paint("NOT checked:", AnsiColor::Yellow, color),
                line
            );
        }
    }
}

fn print_verb_guidance(response: &server::ExecuteResponse) {
    if response.verb_matches.is_empty() && response.verb_guidance.is_none() {
        return;
    }
    for matched in &response.verb_matches {
        eprintln!(
            "  matched verb: {} / {} ({:?}, {:?}, {}{})",
            matched.verb,
            matched.cell,
            matched.scope,
            matched.action,
            if matched.selected {
                "selected"
            } else {
                "not selected"
            },
            if matched.overridden {
                ", overridden"
            } else {
                ""
            }
        );
    }
    if let Some(guidance) = &response.verb_guidance {
        eprintln!("  guidance: {}", guidance);
    }
}

/// The `result:` and `window:` lines of a PROVISIONAL banner. The armed
/// deadline is the operative fact: without it the banner reads as an
/// indefinite hold, and the automatic rollback that follows looks like a
/// malfunction. A daemon that does not report the window falls back to the
/// deadline-free wording rather than inventing one.
fn provisional_window_lines(response: &server::ExecuteResponse) -> Vec<String> {
    let (Some(deadline), Some(window)) =
        (response.confirm_deadline_unix, response.confirm_window_secs)
    else {
        return vec!["result:  executed, auto-reverts unless confirmed".to_string()];
    };
    vec![
        format!(
            "result:  executed, auto-reverts in {window}s (at {}) unless confirmed",
            format_timestamp(deadline)
        ),
        "window:  set with --confirm-within SECONDS".to_string(),
    ]
}

fn print_provisional_window(response: &server::ExecuteResponse) {
    for line in provisional_window_lines(response) {
        eprintln!("  {line}");
    }
}

fn access_request_guidance_lines(response: &server::ExecuteResponse) -> Vec<String> {
    if !response.access_requests.is_empty() {
        return response
            .access_requests
            .iter()
            .flat_map(|request| {
                let mut lines = vec![format!("request: {}", request.reference)];
                lines.extend(
                    request
                        .approval_options
                        .iter()
                        .map(|command| format!("approve: {command}")),
                );
                lines.push(format!("inspect: guard access show {}", request.reference));
                lines
            })
            .collect();
    }

    let Some(reference) = response.handle.as_deref() else {
        return Vec::new();
    };
    let mut lines = vec![format!("request: {reference}")];
    lines.extend(
        response
            .approval_options
            .iter()
            .map(|command| format!("approve: {command}")),
    );
    lines.push(format!("inspect: guard access show {reference}"));
    lines
}

fn print_access_request_guidance(response: &server::ExecuteResponse) {
    for line in access_request_guidance_lines(response) {
        eprintln!("  {line}");
    }
}

pub(crate) async fn run_exec(
    binary: String,
    args: Vec<String>,
    injections: RunInjections,
    gating: GatingOptions,
    hostkey: server::SshHostKeyMode,
    json: bool,
    explain: bool,
) -> Result<()> {
    let config = load_client_config(json)?;

    let (socket_path, tcp_port, endpoint_source) =
        resolve_client_endpoint_with_source(None, &config);

    let mut revert = match gating.revert.as_deref() {
        Some(spec) => Some(parse_revert(spec)?),
        None => None,
    };
    if let Some(check) = gating.confirm_check.as_deref() {
        let parsed = parse_revert(check)?;
        let Some(revert) = revert.as_mut() else {
            anyhow::bail!("--confirm-check requires --revert");
        };
        revert.confirm_check = Some(server::CommandSpec {
            binary: parsed.binary,
            args: parsed.args,
        });
    }
    if let Some(control_path) = gating.revert_control_path {
        let Some(revert) = revert.as_mut() else {
            anyhow::bail!("--revert-control-path requires --revert");
        };
        revert.control_path = Some(control_path);
    }

    let mut client = daemon_client::Client::new(socket_path, tcp_port)
        .with_gating(
            revert,
            gating.confirm_within,
            gating.require_approval,
            gating.wait_approval,
        )
        .with_reevaluate(gating.reevaluate)
        .with_hostkey(hostkey);
    if let Some(token) = config.auth_token {
        client = client.with_auth(token);
    }
    tracing::info!(
        binary = %binary,
        endpoint = %client.endpoint_for_log(),
        "REQUEST"
    );
    let mut streamed_output = false;
    let RunInjections {
        env,
        secrets,
        secret_files,
    } = injections;
    let resp = if json {
        client
            .execute_with_injections(&binary, &args, env, secrets, secret_files)
            .await
    } else {
        client
            .execute_streaming_with_injections(
                &binary,
                &args,
                env,
                secrets,
                secret_files,
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
            .await
    }
    .map_err(|e| describe_connect_failure(e, &client, endpoint_source))?;

    if json {
        print_execute_response_json("run_result", &binary, &args, &resp)?;
        exit_for_execute_response(&resp);
    }

    // Consequence-gate outcomes: a held command did not run; a provisional ran
    // behind an auto-revert timer.
    match resp.status {
        Some(server::GateStatus::Held) => {
            let color = color_enabled_for_stderr();
            let handle = resp.handle.clone().unwrap_or_default();
            eprintln!(
                "{} for operator approval: {}",
                paint("HELD", AnsiColor::Yellow, color),
                resp.reason
            );
            eprintln!("  handle:  {}", handle);
            print_access_request_guidance(&resp);
            eprintln!("  result:  not executed until approved");
            print_coverage(&resp.coverage);
            print_verb_guidance(&resp);
            // Not executed; exit non-zero so callers do not treat it as success.
            std::process::exit(EXIT_GUARD_HELD);
        }
        Some(server::GateStatus::Provisional) => {
            let color = color_enabled_for_stderr();
            if !streamed_output {
                if let Some(stdout) = &resp.stdout {
                    print!("{}", stdout);
                }
                if let Some(stderr) = &resp.stderr {
                    eprint!("{}", stderr);
                }
            }
            let handle = resp.handle.clone().unwrap_or_default();
            eprintln!(
                "{} containment envelope: {}",
                paint("PROVISIONAL", AnsiColor::Yellow, color),
                resp.reason
            );
            eprintln!("  handle:  {}", handle);
            eprintln!("  confirm: guard confirm {}", handle);
            eprintln!("  inspect: guard provisionals");
            print_provisional_window(&resp);
            print_coverage(&resp.coverage);
            if let Some(code) = resp.exit_code {
                std::process::exit(code);
            }
            return Ok(());
        }
        Some(server::GateStatus::DryRun) => {
            let color = color_enabled_for_stdout();
            println!(
                "{} {}",
                paint("[DRY-RUN]", AnsiColor::Cyan, color),
                resp.reason
            );
            print_coverage(&resp.coverage);
            return Ok(());
        }
        _ => {}
    }

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
        if explain {
            print_verb_guidance(&resp);
            eprintln!("  decision source: {}", resp.decision_source);
        }
        if let Some(code) = resp.exit_code {
            std::process::exit(code);
        }
        Ok(())
    } else {
        let color = color_enabled_for_stderr();
        tracing::warn!(
            binary = %binary,
            reason = %resp.reason,
            "DENIED"
        );
        eprintln!(
            "{}: {}",
            paint("DENIED", AnsiColor::Red, color),
            resp.reason
        );
        print_access_request_guidance(&resp);
        print_verb_guidance(&resp);
        std::process::exit(EXIT_GUARD_DENIED);
    }
}

fn print_execute_response_json(
    kind: &str,
    binary: &str,
    args: &[String],
    response: &server::ExecuteResponse,
) -> Result<()> {
    print_json(&execute_response_envelope(kind, binary, args, response))
}

fn execute_response_envelope(
    kind: &str,
    binary: &str,
    args: &[String],
    response: &server::ExecuteResponse,
) -> serde_json::Value {
    serde_json::json!({
        "schema_version": JSON_SCHEMA_VERSION,
        "type": kind,
        "command": {
            "binary": binary,
            "args": args,
        },
        "response": response,
    })
}

fn exit_for_execute_response(response: &server::ExecuteResponse) -> ! {
    if response.status == Some(server::GateStatus::Held) {
        std::process::exit(EXIT_GUARD_HELD);
    }
    if !response.allowed {
        std::process::exit(EXIT_GUARD_DENIED);
    }
    // Executed child codes are intentionally propagated without translation.
    // In particular, child 1 and 75 must remain distinct from Guard's
    // operational, denial, and hold codes in the reserved 125..=127 range.
    std::process::exit(response.exit_code.unwrap_or(0));
}

/// Resolve the admin endpoint and build a client for a gate-control RPC.
/// Operator-side admin token resolution: stored config first, then the
/// environment, then a token file. GUARD_ADMIN_TOKEN must stay unset for
/// agent principals; it belongs only to the operator wrapper's context.
fn resolve_admin_token(config: &client_config::ClientConfig) -> Option<String> {
    config
        .admin_token
        .clone()
        .or_else(|| guard_env("ADMIN_TOKEN").filter(|token| !token.is_empty()))
        .or_else(|| {
            guard_env("ADMIN_TOKEN_FILE").and_then(|path| match std::fs::read_to_string(&path) {
                Ok(contents) => {
                    let token = contents.trim().to_string();
                    if token.is_empty() {
                        tracing::warn!("GUARD_ADMIN_TOKEN_FILE is empty: {}", path);
                        None
                    } else {
                        Some(token)
                    }
                }
                Err(error) => {
                    tracing::warn!("GUARD_ADMIN_TOKEN_FILE unreadable: {}: {}", path, error);
                    None
                }
            })
        })
}

fn gate_client(
    socket_override: Option<String>,
    json: bool,
) -> Result<(daemon_client::Client, EndpointSource)> {
    let config = load_client_config(json)?;
    let (socket_path, tcp_port, source) =
        resolve_client_endpoint_with_source(socket_override, &config);
    let mut client = daemon_client::Client::new(socket_path, tcp_port);
    if let Some(ref token) = config.auth_token {
        client = client.with_auth(token.clone());
    }
    if let Some(token) = resolve_admin_token(&config) {
        client = client.with_admin_token(token);
    }
    Ok((client, source))
}

pub(crate) async fn handle_api(command: ApiCommands) -> Result<()> {
    match command {
        ApiCommands::Kubeconfig { .. } => anyhow::bail!(
            "`guard api kubeconfig` has been removed because access-managed sessions are command-only; use approved kubectl or helm command verbs"
        ),
    }
}

pub(crate) async fn handle_provisionals(socket: Option<String>, json: bool) -> Result<()> {
    let (client, source) = gate_client(socket, json)?;
    match client
        .send_admin(server::AdminRequest::Provisionals)
        .await
        .map_err(|e| describe_connect_failure(e, &client, source))?
    {
        server::AdminResponse::Provisionals { items } => {
            if json {
                return print_json(&serde_json::json!({
                    "schema_version": JSON_SCHEMA_VERSION,
                    "type": "provisional_list",
                    "items": items,
                }));
            }
            if items.is_empty() {
                println!("(no provisional executions)");
            }
            let color = color_enabled_for_stdout();
            for p in &items {
                let status = paint(&p.status, AnsiColor::Yellow, color);
                println!(
                    "[{}] handle={} cmd={:?} revert={:?} check={:?} control_path={:?} session={} deadline={} reason={:?}{}",
                    status,
                    p.handle,
                    p.command,
                    p.revert_command,
                    p.confirm_check,
                    p.control_path,
                    p.session_fingerprint.as_deref().unwrap_or("none"),
                    format_timestamp(p.deadline_unix),
                    p.reason,
                    p.revert_detail
                        .as_ref()
                        .map(|d| format!(" revert_detail={:?}", d))
                        .unwrap_or_default(),
                );
            }
            Ok(())
        }
        server::AdminResponse::Error { message } => {
            eprintln!("error: {}", message);
            std::process::exit(1);
        }
        _ => {
            eprintln!("unexpected response");
            std::process::exit(1);
        }
    }
}

fn render_approval(item: &server::ApprovalSummary, include_transcript: bool) {
    println!(
        "[{}] handle={} cmd={:?} deadline={} reason={:?}",
        item.status,
        item.handle,
        item.command,
        format_timestamp(item.deadline_unix),
        item.decided_reason.as_deref().unwrap_or(&item.reason),
    );
    if include_transcript {
        if let Some(stdout) = item.stdout.as_deref() {
            print!("{stdout}");
            if item.stdout_truncated {
                println!("[guard stdout transcript truncated]");
            }
        }
        if let Some(stderr) = item.stderr.as_deref() {
            eprint!("{stderr}");
            if item.stderr_truncated {
                eprintln!("[guard stderr transcript truncated]");
            }
        }
        if let Some(exit_code) = item.exit_code {
            println!("exit_code={exit_code}");
        }
    }
}

pub(crate) async fn handle_approval(command: ApprovalCommands) -> Result<()> {
    let (socket, request, json, include_transcript) = match command {
        ApprovalCommands::List { socket, json } => {
            (socket, server::AdminRequest::ApprovalList, json, false)
        }
        ApprovalCommands::Show {
            handle,
            socket,
            json,
        } => (
            socket,
            server::AdminRequest::ApprovalShow { handle },
            json,
            true,
        ),
        ApprovalCommands::Note {
            handle,
            text,
            socket,
            json,
        } => (
            socket,
            server::AdminRequest::ApprovalNote { handle, text },
            json,
            true,
        ),
        ApprovalCommands::Withdraw {
            handle,
            socket,
            json,
        } => (
            socket,
            server::AdminRequest::ApprovalWithdraw { handle },
            json,
            false,
        ),
    };
    let (client, source) = gate_client(socket, json)?;
    let response = client
        .send_admin(request)
        .await
        .map_err(|error| describe_connect_failure(error, &client, source))?;
    match response {
        server::AdminResponse::Approvals { items } => {
            if json {
                return print_json(&serde_json::json!({
                    "schema_version": JSON_SCHEMA_VERSION,
                    "type": "approval_list",
                    "items": items,
                }));
            }
            if items.is_empty() {
                println!("(no held commands)");
            }
            for item in &items {
                render_approval(item, false);
            }
            Ok(())
        }
        server::AdminResponse::ApprovalShow { item } => {
            if json {
                return print_json(&serde_json::json!({
                    "schema_version": JSON_SCHEMA_VERSION,
                    "type": "approval",
                    "item": item,
                }));
            }
            render_approval(&item, include_transcript);
            Ok(())
        }
        server::AdminResponse::GateAction { message, .. } => {
            if json {
                return print_json(&serde_json::json!({
                    "schema_version": JSON_SCHEMA_VERSION,
                    "type": "approval_withdrawal",
                    "message": message,
                }));
            }
            println!("{message}");
            Ok(())
        }
        server::AdminResponse::Error { message } => anyhow::bail!(message),
        _ => anyhow::bail!("unexpected response from guard daemon"),
    }
}

fn resume_json_response(
    handle: &str,
    message: &str,
    exit_code: Option<i32>,
    stdout: Option<&str>,
    stderr: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "schema_version": JSON_SCHEMA_VERSION,
        "type": "resume_result",
        "handle": handle,
        "message": message,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
    })
}

/// Resume one held command as the kernel-authenticated requester and render its
/// captured output and exit status.
pub(crate) async fn handle_resume(
    socket: Option<String>,
    handle: String,
    json: bool,
) -> Result<()> {
    let config = load_client_config(json)?;
    let (socket_path, tcp_port, source) = resolve_client_endpoint_with_source(socket, &config);
    let mut client = daemon_client::Client::new(socket_path, tcp_port);
    if let Some(token) = config.auth_token {
        client = client.with_auth(token);
    }
    let response = client
        .send_admin(server::AdminRequest::Resume {
            handle: handle.clone(),
        })
        .await
        .map_err(|error| describe_connect_failure(error, &client, source))?;
    match response {
        server::AdminResponse::GateAction {
            message,
            exit_code,
            stdout,
            stderr,
        } => {
            if json {
                print_json(&resume_json_response(
                    &handle,
                    &message,
                    exit_code,
                    stdout.as_deref(),
                    stderr.as_deref(),
                ))?;
            } else {
                if let Some(stdout) = stdout.as_deref() {
                    print!("{stdout}");
                    std::io::stdout().flush()?;
                }
                if let Some(stderr) = stderr.as_deref() {
                    eprint!("{stderr}");
                    if !stderr.ends_with('\n') {
                        eprintln!();
                    }
                }
                match exit_code {
                    Some(code) => eprintln!("exit status: {code}"),
                    None => eprintln!("exit status: unavailable"),
                }
            }
            if let Some(code) = exit_code.filter(|code| *code != 0) {
                std::process::exit(code);
            }
            Ok(())
        }
        server::AdminResponse::Error { message } if json => {
            print_json(&serde_json::json!({
                "schema_version": JSON_SCHEMA_VERSION,
                "type": "resume_error",
                "handle": handle,
                "error": message,
            }))?;
            std::process::exit(EXIT_GUARD_ERROR);
        }
        server::AdminResponse::Error { message } => Err(anyhow::anyhow!(message)),
        other => Err(anyhow::anyhow!("unexpected admin response: {other:?}")),
    }
}

pub(crate) async fn handle_audit_verify(socket: Option<String>, json: bool) -> Result<()> {
    let (client, source) = gate_client(socket, json)?;
    match client
        .send_admin(server::AdminRequest::AuditVerify)
        .await
        .map_err(|e| describe_connect_failure(e, &client, source))?
    {
        server::AdminResponse::AuditVerification { path, verification } => {
            if json {
                return print_json(&serde_json::json!({
                    "schema_version": JSON_SCHEMA_VERSION,
                    "type": "audit_verification",
                    "path": path,
                    "intact": verification.intact,
                    "records": verification.records,
                    "broken_at_seq": verification.broken_at_seq,
                    "detail": verification.detail,
                }));
            }
            let color = color_enabled_for_stdout();
            if verification.intact {
                println!(
                    "{}: {} record(s) verified ({})",
                    paint("audit chain intact", AnsiColor::Green, color),
                    verification.records,
                    path
                );
                Ok(())
            } else {
                println!(
                    "{} at seq {}: {}",
                    paint("audit chain BROKEN", AnsiColor::Red, color),
                    verification
                        .broken_at_seq
                        .map(|seq| seq.to_string())
                        .unwrap_or_else(|| "?".to_string()),
                    verification.detail.as_deref().unwrap_or("unknown anomaly")
                );
                println!(
                    "{} record(s) verified before the break ({})",
                    verification.records, path
                );
                std::process::exit(1);
            }
        }
        server::AdminResponse::Error { message } => {
            eprintln!("error: {}", message);
            std::process::exit(1);
        }
        other => {
            eprintln!("unexpected response: {:?}", other);
            std::process::exit(1);
        }
    }
}

pub(crate) async fn handle_audit_tail(
    socket: Option<String>,
    n: Option<usize>,
    json: bool,
) -> Result<()> {
    let (client, source) = gate_client(socket, json)?;
    match client
        .send_admin(server::AdminRequest::AuditTail { limit: n })
        .await
        .map_err(|e| describe_connect_failure(e, &client, source))?
    {
        server::AdminResponse::AuditRecords { path, items } => {
            if json {
                return print_json(&serde_json::json!({
                    "schema_version": JSON_SCHEMA_VERSION,
                    "type": "audit_records",
                    "path": path,
                    "items": items,
                }));
            }
            if items.is_empty() {
                println!("(no audit records)");
            }
            for item in &items {
                match serde_json::from_value::<guard::audit::AuditRecord>(item.clone()) {
                    Ok(record) => println!(
                        "seq={} {} [AUDIT] {}",
                        record.seq,
                        format_timestamp(record.ts),
                        record.event.render_line()
                    ),
                    // A line that does not parse is shown raw rather than
                    // hidden, so a tampered tail stays visible in reads too.
                    Err(_) => println!("(unparseable) {}", item),
                }
            }
            Ok(())
        }
        server::AdminResponse::Error { message } => {
            eprintln!("error: {}", message);
            std::process::exit(1);
        }
        other => {
            eprintln!("unexpected response: {:?}", other);
            std::process::exit(1);
        }
    }
}

pub(crate) async fn handle_verb(subcommand: VerbCommands) -> Result<()> {
    match subcommand {
        VerbCommands::List { socket, json } => {
            let (client, source) = gate_client(socket, json)?;
            match client
                .send_admin(server::AdminRequest::VerbList)
                .await
                .map_err(|e| describe_connect_failure(e, &client, source))?
            {
                server::AdminResponse::Verbs { items } => {
                    if json {
                        return print_json(&serde_json::json!({
                            "schema_version": JSON_SCHEMA_VERSION,
                            "type": "verb_list",
                            "items": items,
                        }));
                    }
                    if items.is_empty() {
                        println!("(no verbs; start the daemon with --verbs <catalog.yaml>)");
                    }
                    for v in &items {
                        println!(
                            "{} [{}]{}{}{}{} - {}",
                            v.name,
                            v.consequence,
                            if v.baseline { "" } else { " session-scoped" },
                            if v.trusted { " trusted" } else { "" },
                            if v.has_revert { " revertable" } else { "" },
                            if v.auto_promoted {
                                " auto_promoted"
                            } else {
                                ""
                            },
                            v.description
                        );
                        for (p, pattern) in &v.params {
                            println!("    --param {}=<{}>", p, pattern);
                        }
                        if let Some(plan) = &v.credential_plan {
                            println!("    credential_plan: {}", plan);
                        }
                        for cell in &v.coverage {
                            println!(
                                "    coverage {}: {:?} required={:?} forbidden={:?} options={:?} target={:?} inventory={:?} namespace={:?} fanout={:?} override_marker={:?}",
                                cell.name,
                                cell.action,
                                cell.required_args,
                                cell.forbidden_args,
                                cell.options,
                                cell.target,
                                cell.inventory,
                                cell.namespace,
                                cell.fanout,
                                cell.override_marker,
                            );
                        }
                        if let Some(evidence) = &v.evidence {
                            println!("    evidence: {}", evidence);
                        }
                    }
                    Ok(())
                }
                server::AdminResponse::VerbMenu { items } => {
                    if json {
                        return print_json(&serde_json::json!({
                            "schema_version": JSON_SCHEMA_VERSION,
                            "type": "verb_list",
                            "projection": "agent_menu",
                            "items": items,
                        }));
                    }
                    if items.is_empty() {
                        println!("(no verbs; start the daemon with --verbs <catalog.yaml>)");
                    }
                    for verb in &items {
                        println!(
                            "{} [{}]{} - {}",
                            verb.name,
                            verb.consequence,
                            if verb.has_revert { " revertable" } else { "" },
                            verb.description
                        );
                        for parameter in &verb.params {
                            println!("    --param {parameter}=<value>");
                        }
                    }
                    Ok(())
                }
                server::AdminResponse::Error { message } => {
                    eprintln!("error: {}", message);
                    std::process::exit(1);
                }
                _ => {
                    eprintln!("unexpected response");
                    std::process::exit(1);
                }
            }
        }
        VerbCommands::Show { name, socket, json } => {
            let (client, source) = gate_client(socket, json)?;
            let response = client
                .send_admin(server::AdminRequest::VerbShow { name })
                .await
                .map_err(|error| describe_connect_failure(error, &client, source))?;
            match response {
                server::AdminResponse::VerbCreated { verb, .. } => {
                    if json {
                        print_json(&verb)
                    } else {
                        println!("{}", serde_json::to_string_pretty(&verb)?);
                        Ok(())
                    }
                }
                server::AdminResponse::Error { message } => Err(anyhow::anyhow!(message)),
                other => Err(anyhow::anyhow!("unexpected admin response: {other:?}")),
            }
        }
        VerbCommands::Delete { name, socket } => {
            let (client, source) = gate_client(socket, false)?;
            match client
                .send_admin(server::AdminRequest::VerbDelete { name })
                .await
                .map_err(|error| describe_connect_failure(error, &client, source))?
            {
                server::AdminResponse::Ok => {
                    println!("ok");
                    Ok(())
                }
                server::AdminResponse::Error { message } => Err(anyhow::anyhow!(message)),
                other => Err(anyhow::anyhow!("unexpected admin response: {other:?}")),
            }
        }
        VerbCommands::Amend {
            name,
            file,
            socket,
            json,
        } => {
            let yaml = std::fs::read_to_string(&file)
                .with_context(|| format!("failed to read verb file {}", file.display()))?;
            let replacement: guard::gating::verb::Verb = serde_yaml_ng::from_str(&yaml)
                .with_context(|| {
                    format!("failed to parse {} as one verb definition", file.display())
                })?;
            if replacement.name != name {
                anyhow::bail!(
                    "verb file names '{}', but amend targets '{}'; the name must be preserved",
                    replacement.name,
                    name
                );
            }

            let (client, source) = gate_client(socket, json)?;
            let current = client
                .send_admin(server::AdminRequest::VerbShow { name: name.clone() })
                .await
                .map_err(|error| describe_connect_failure(error, &client, source))?;
            let server::AdminResponse::VerbCreated { verb: current, .. } = current else {
                return match current {
                    server::AdminResponse::Error { message } => Err(anyhow::anyhow!(message)),
                    other => Err(anyhow::anyhow!("unexpected admin response: {other:?}")),
                };
            };
            let expected_digest = current.definition_digest();
            let response = client
                .send_admin(server::AdminRequest::VerbAmend {
                    name,
                    expected_digest,
                    replacement: Box::new(replacement),
                })
                .await
                .map_err(|error| describe_connect_failure(error, &client, source))?;
            match response {
                server::AdminResponse::VerbAmended {
                    verb,
                    previous_digest,
                    digest,
                } => {
                    if json {
                        print_json(&serde_json::json!({
                            "schema_version": JSON_SCHEMA_VERSION,
                            "type": "verb_amended",
                            "previous_digest": previous_digest,
                            "digest": digest,
                            "verb": verb,
                        }))
                    } else {
                        println!(
                            "Amended verb '{}' ({} -> {}).",
                            verb.name, previous_digest, digest
                        );
                        Ok(())
                    }
                }
                server::AdminResponse::Error { message } => Err(anyhow::anyhow!(message)),
                other => Err(anyhow::anyhow!("unexpected admin response: {other:?}")),
            }
        }
        VerbCommands::Run {
            name,
            params,
            confirm_within,
            wait_approval,
            socket,
            json,
            explain,
        } => {
            let config = load_client_config(json)?;
            let (socket_path, tcp_port, endpoint_source) =
                resolve_client_endpoint_with_source(socket, &config);
            let param_map: std::collections::BTreeMap<String, String> =
                params.into_iter().collect();
            let invocation = server::VerbInvocation {
                name: name.clone(),
                params: param_map.clone(),
            };
            let mut client = daemon_client::Client::new(socket_path, tcp_port)
                .with_verb(invocation)
                .with_gating(None, confirm_within, false, wait_approval);
            if let Some(token) = config.auth_token {
                client = client.with_auth(token);
            }
            // Verb binary/args are rendered server-side; the client sends empty.
            let mut streamed = false;
            let resp = if json {
                client
                    .execute_with_injections(
                        "",
                        &[],
                        HashMap::new(),
                        HashMap::new(),
                        HashMap::new(),
                    )
                    .await
            } else {
                client
                    .execute_streaming_with_injections(
                        "",
                        &[],
                        HashMap::new(),
                        HashMap::new(),
                        HashMap::new(),
                        |stream, data| {
                            streamed = true;
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
                    .await
            }
            .map_err(|e| describe_connect_failure(e, &client, endpoint_source))?;
            if json {
                print_json(&serde_json::json!({
                    "schema_version": JSON_SCHEMA_VERSION,
                    "type": "verb_run_result",
                    "command": {
                        "verb": name,
                        "params": param_map,
                    },
                    "response": resp,
                }))?;
                exit_for_execute_response(&resp);
            }
            render_gated_response(&resp, streamed, &name, explain)
        }
        VerbCommands::Create {
            prompt,
            binary,
            preview,
            from_preview,
            retries,
            yes,
            socket,
            json,
        } => {
            let config = load_client_config(json)?;
            let (socket_path, tcp_port, source) =
                resolve_client_endpoint_with_source(socket, &config);
            let client = admin_client(socket_path, tcp_port, &config);
            if let Some(reference) = from_preview {
                let response = client
                    .send_admin(server::AdminRequest::VerbCreateFromPreview { digest: reference })
                    .await
                    .map_err(|e| describe_connect_failure(e, &client, source))?;
                return render_verb_create_terminal(response, json);
            }
            let prompt = prompt.expect("clap requires --prompt without --from-preview");
            let retries = retries
                .or(config.verb_create_retries)
                .unwrap_or(VERB_CREATE_DEFAULT_RETRIES);
            let attempts = retries.saturating_add(1);
            let mut gate_feedback: Vec<String> = Vec::new();
            // Client-driven retry loop: each safety-gate complaint feeds the
            // next synthesis, and nothing touches the catalog until a candidate
            // passes, so Ctrl-C between attempts leaves no partial state.
            let response = loop {
                let attempt = gate_feedback.len() as u32 + 1;
                let response = client
                    .send_admin(server::AdminRequest::VerbCreate {
                        prose: prompt.clone(),
                        binary_hint: binary.clone(),
                        preview,
                        gate_feedback: gate_feedback.clone(),
                    })
                    .await
                    .map_err(|e| describe_connect_failure(e, &client, source))?;
                match response {
                    server::AdminResponse::Error { ref message }
                        if attempt < attempts && verb_create_rejection(message).is_some() =>
                    {
                        let reason = verb_create_rejection(message)
                            .expect("rejection matched in the guard")
                            .to_string();
                        eprintln!(
                            "synthesis attempt {attempt}/{attempts} rejected by the safety gate: {reason}; retrying"
                        );
                        gate_feedback.push(reason);
                    }
                    other => break other,
                }
            };
            let server::AdminResponse::VerbCreated {
                verb,
                persisted,
                preview_digest,
            } = response
            else {
                return render_verb_create_terminal(response, json);
            };
            if json {
                return print_json(&serde_json::json!({
                    "schema_version": JSON_SCHEMA_VERSION,
                    "type": "verb",
                    "persisted": persisted,
                    "preview_digest": preview_digest,
                    "verb": verb,
                }));
            }
            print_verb_create_human(&verb, persisted);
            let Some(digest) = preview_digest.filter(|_| !persisted) else {
                return Ok(());
            };
            let short = digest.get(..12).unwrap_or(&digest).to_string();
            println!();
            println!(
                "candidate: {}...",
                paint(&short, AnsiColor::Bold, color_enabled_for_stdout())
            );
            println!("  install: guard verb create --from-preview {short}");
            if yes || !access_review_is_interactive() {
                return Ok(());
            }
            if !prompt_verb_create_now(&short, color_enabled_for_stderr())? {
                return Ok(());
            }
            let response = client
                .send_admin(server::AdminRequest::VerbCreateFromPreview { digest })
                .await
                .map_err(|e| describe_connect_failure(e, &client, source))?;
            match response {
                server::AdminResponse::VerbCreated { verb, .. } => {
                    println!(
                        "Created verb '{}' and added it to the catalog (candidate {short}).",
                        verb.name
                    );
                    Ok(())
                }
                other => render_verb_create_terminal(other, false),
            }
        }
        VerbCommands::Coverage { command } => match command {
            VerbCoverageCommands::List { socket, json } => {
                let (client, source) = gate_client(socket, json)?;
                match client
                    .send_admin(server::AdminRequest::VerbCoverageList)
                    .await
                    .map_err(|e| describe_connect_failure(e, &client, source))?
                {
                    server::AdminResponse::VerbCoverage { items } => {
                        if json {
                            return print_json(&serde_json::json!({
                                "schema_version": JSON_SCHEMA_VERSION,
                                "type": "verb_coverage_list",
                                "items": items,
                            }));
                        }
                        if items.is_empty() {
                            println!("(no generated API verb coverage)");
                        }
                        for item in items {
                            let session = item
                                .session_fingerprint
                                .as_deref()
                                .map(|value| value.chars().take(12).collect::<String>())
                                .unwrap_or_else(|| "global".to_string());
                            let regime = item.regime.chars().take(12).collect::<String>();
                            println!(
                                "endpoint={} session={} {} {} {}/{} namespace={} decision={} provenance={:?} regime={} active={} expires={}",
                                item.endpoint,
                                session,
                                item.protocol,
                                item.verb,
                                if item.group.is_empty() { "core" } else { &item.group },
                                item.resource,
                                item.namespace.as_deref().unwrap_or("cluster"),
                                item.decision,
                                item.provenance,
                                regime,
                                item.active,
                                item.expires_at_unix
                                    .map(|value| value.to_string())
                                    .unwrap_or_else(|| "never".to_string())
                            );
                        }
                        Ok(())
                    }
                    server::AdminResponse::Error { message } => anyhow::bail!(message),
                    _ => anyhow::bail!("unexpected response"),
                }
            }
            VerbCoverageCommands::Clear { socket, json } => {
                let (client, source) = gate_client(socket, json)?;
                match client
                    .send_admin(server::AdminRequest::VerbCoverageClear)
                    .await
                    .map_err(|e| describe_connect_failure(e, &client, source))?
                {
                    server::AdminResponse::VerbCoverageCleared { removed } => {
                        if json {
                            print_json(&serde_json::json!({
                                "schema_version": JSON_SCHEMA_VERSION,
                                "type": "verb_coverage_clear",
                                "removed": removed,
                            }))
                        } else {
                            println!("Cleared {removed} generated API coverage bucket(s).");
                            Ok(())
                        }
                    }
                    server::AdminResponse::Error { message } => anyhow::bail!(message),
                    _ => anyhow::bail!("unexpected response"),
                }
            }
        },
    }
}

/// Automatic re-synthesis attempts after a safety-gate rejection when neither
/// `--retries` nor the client config chooses a count.
const VERB_CREATE_DEFAULT_RETRIES: u32 = 4;

/// The gate complaint inside a daemon verb-create rejection, or `None` for an
/// operational error (unreachable daemon, missing LLM key, empty prose) that a
/// re-synthesis cannot fix.
fn verb_create_rejection(message: &str) -> Option<&str> {
    [
        "synthesized verb rejected by the safety gate: ",
        "synthesized verb rejected by validation: ",
        "previewed verb rejected by the safety gate: ",
        "previewed verb rejected by validation: ",
    ]
    .iter()
    .find_map(|prefix| message.strip_prefix(prefix))
}

fn print_verb_create_human(verb: &guard::gating::verb::Verb, persisted: bool) {
    if persisted {
        println!("Created verb '{}' and added it to the catalog:", verb.name);
    } else {
        println!(
            "Preview of verb '{}' (NOT written). Install exactly this candidate with --from-preview; every created verb is non-trusted and re-validated by the safety gate.",
            verb.name
        );
    }
    if let Some(ev) = &verb.evidence {
        println!("  evidence: {}", ev);
    }
    println!();
    match serde_yaml_ng::to_string(verb) {
        Ok(y) => print!("{}", y),
        Err(_) => println!("{:#?}", verb),
    }
}

/// Terminal rendering for a verb-create response outside the interactive
/// preview flow: a persisted install (including --from-preview) or a final
/// error. A gate rejection gains one sentence telling the operator what to
/// change in their prose, since the model, not the operator, wrote the
/// rejected artifact.
fn render_verb_create_terminal(response: server::AdminResponse, json: bool) -> Result<()> {
    match response {
        server::AdminResponse::VerbCreated {
            verb,
            persisted,
            preview_digest,
        } => {
            if json {
                return print_json(&serde_json::json!({
                    "schema_version": JSON_SCHEMA_VERSION,
                    "type": "verb",
                    "persisted": persisted,
                    "preview_digest": preview_digest,
                    "verb": verb,
                }));
            }
            print_verb_create_human(&verb, persisted);
            Ok(())
        }
        server::AdminResponse::Error { message } => {
            match verb_create_rejection(&message)
                .and_then(guard::gating::verb::gate_rejection_guidance)
            {
                Some(guidance) => eprintln!("error: {message}; {guidance}"),
                None => eprintln!("error: {message}"),
            }
            std::process::exit(1);
        }
        _ => {
            eprintln!("unexpected response");
            std::process::exit(1);
        }
    }
}

/// Offer to install the just-previewed candidate. Same person-present contract
/// as the access review prompt: answers come from stdin and the prompt renders
/// on stderr, leaving stdout to the candidate itself.
fn prompt_verb_create_now(candidate: &str, colors: bool) -> Result<bool> {
    loop {
        eprint!(
            "{} [c]reate now / [q]uit: ",
            paint(candidate, AnsiColor::Bold, colors)
        );
        std::io::stderr().flush()?;
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line)? == 0 {
            // EOF on the terminal (Ctrl-D) declines the install.
            eprintln!();
            return Ok(false);
        }
        match parse_verb_create_choice(&line) {
            Some(create) => return Ok(create),
            None => eprintln!("answer c or q"),
        }
    }
}

fn parse_verb_create_choice(input: &str) -> Option<bool> {
    match input.trim().to_ascii_lowercase().as_str() {
        "c" | "create" | "y" | "yes" => Some(true),
        "q" | "quit" | "n" | "no" => Some(false),
        _ => None,
    }
}

pub(crate) async fn handle_access(command: AccessCommands) -> Result<()> {
    let (socket, request, json) = match command {
        AccessCommands::Request {
            intent,
            socket,
            json,
        } => (socket, server::AdminRequest::AccessRequest { intent }, json),
        AccessCommands::Approve {
            requests,
            yes,
            once,
            uses,
            socket,
            json,
        } => {
            let uses = if once { Some(1) } else { uses };
            if !json && !yes && access_review_is_interactive() {
                return handle_access_approve_interactive(requests, uses, socket).await;
            }
            (
                socket,
                server::AdminRequest::AccessApprove {
                    handles: requests,
                    uses,
                },
                json,
            )
        }
        AccessCommands::Deny {
            requests,
            reason,
            socket,
            json,
        } => (
            socket,
            server::AdminRequest::AccessDeny {
                handles: requests,
                reason,
            },
            json,
        ),
        AccessCommands::Revoke {
            target,
            socket,
            json,
        } => (socket, server::AdminRequest::AccessRevoke { target }, json),
        AccessCommands::Extend {
            target,
            intent,
            once,
            uses,
            socket,
            json,
        } => (
            socket,
            server::AdminRequest::AccessExtend {
                target,
                intent,
                uses: if once { Some(1) } else { uses },
            },
            json,
        ),
        AccessCommands::List { socket, json } => (socket, server::AdminRequest::AccessList, json),
        AccessCommands::Show {
            reference,
            socket,
            json,
        } => (socket, server::AdminRequest::AccessShow { reference }, json),
        AccessCommands::Status {
            reference,
            socket,
            json,
        } => (
            socket,
            server::AdminRequest::AccessStatus { reference },
            json,
        ),
    };
    let config = load_client_config(json)?;
    let (socket_path, tcp_port, source) = resolve_client_endpoint_with_source(socket, &config);
    let client = admin_client(socket_path, tcp_port, &config);
    let response = match client.send_admin(request).await {
        Ok(response) => response,
        Err(error) => {
            let error = describe_connect_failure(error, &client, source);
            if json {
                exit_access_json_error(error.to_string());
            }
            return Err(error);
        }
    };
    let decision_failed = access_decision_failed(&response);
    if json {
        let document = match access_json_response(&response) {
            Ok(document) => document,
            Err(message) => exit_access_json_error(message),
        };
        print_json(&document)?;
        if decision_failed {
            std::process::exit(EXIT_GUARD_ACCESS_DECISION_FAILED);
        }
        return Ok(());
    }
    match response {
        server::AdminResponse::AccessItems { items } => {
            if items.is_empty() {
                println!("(no access requests or sessions)");
            }
            for item in items {
                println!(
                    "{} requester={} target={} scope={} expiry={} uses={} state={} next={}",
                    item.reference,
                    item.requester,
                    item.target,
                    if item.effective_scope.is_empty() {
                        "(none)".to_string()
                    } else {
                        item.effective_scope.join(",")
                    },
                    item.expires_unix
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    if item.use_policy == "bounded" {
                        item.remaining_uses
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "0".to_string())
                    } else {
                        item.use_policy.clone()
                    },
                    item.state,
                    item.next_action,
                );
            }
        }
        server::AdminResponse::AccessItem { item } => {
            println!("{}", access_item_human(&item));
        }
        server::AdminResponse::AccessDecisions { items } => {
            print_access_decision_lines(&items);
        }
        server::AdminResponse::SessionStatus {
            report,
            approvals,
            provisionals,
            requests,
        } => {
            render_access_status(&report, &approvals, &provisionals, &requests);
        }
        server::AdminResponse::Error { message } => anyhow::bail!(message),
        other => anyhow::bail!("unexpected access response: {other:?}"),
    }
    if decision_failed {
        std::process::exit(EXIT_GUARD_ACCESS_DECISION_FAILED);
    }
    Ok(())
}

fn access_json_error(message: impl Into<String>) -> serde_json::Value {
    serde_json::json!({
        "schema_version": JSON_SCHEMA_VERSION,
        "type": "access_error",
        "error": message.into(),
    })
}

fn access_json_response(response: &server::AdminResponse) -> Result<serde_json::Value, String> {
    let kind = match response {
        server::AdminResponse::AccessItems { .. } => "access_list",
        server::AdminResponse::AccessItem { .. } => "access_item",
        server::AdminResponse::AccessDecisions { .. } => "access_decisions",
        server::AdminResponse::SessionStatus { .. } => "access_status",
        server::AdminResponse::Error { message } => return Err(message.clone()),
        other => return Err(format!("unexpected access response: {other:?}")),
    };
    Ok(serde_json::json!({
        "schema_version": JSON_SCHEMA_VERSION,
        "type": kind,
        "response": response,
    }))
}

fn render_access_status(
    report: &crate::session::SessionReport,
    approvals: &[server::ApprovalSummary],
    provisionals: &[server::ProvisionalSummary],
    requests: &[crate::grant_profile::GrantRequest],
) {
    println!("access session status");
    if let Some(active) = &report.active {
        println!(
            "  session: {}",
            active.scope.label.as_deref().unwrap_or("(unlabeled)")
        );
        println!(
            "  expiry: {}",
            active
                .expires_at
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!("  owner: {:?}", active.owner);
        println!(
            "  verbs: {}",
            if active.activated_verbs.is_empty() {
                "(none)".to_string()
            } else {
                active.activated_verbs.join(",")
            }
        );
    }
    println!(
        "  activity: total={} allowed={} denied={} completed={} failed={} held={}",
        report.stats.total,
        report.stats.allowed,
        report.stats.denied,
        report.stats.completed,
        report.stats.exec_failed,
        report.stats.holds,
    );
    println!(
        "  related: requests={} approvals={} provisionals={} recent={}",
        requests.len(),
        approvals.len(),
        provisionals.len(),
        report.recent.len(),
    );
    for interaction in &report.recent {
        println!(
            "  [{}] allowed={} source={} status={:?} command={:?} reason={:?}",
            interaction.at_unix,
            interaction.allowed,
            interaction.source.as_str(),
            interaction.exec_status,
            interaction.command,
            interaction.reason,
        );
    }
    for approval in approvals {
        render_approval(approval, true);
    }
    for provisional in provisionals {
        println!(
            "[{}] handle={} cmd={:?} deadline={} reason={:?}",
            provisional.status,
            provisional.handle,
            provisional.command,
            format_timestamp(provisional.deadline_unix),
            provisional.reason,
        );
    }
}

fn any_decision_failed(items: &[server::AccessDecisionResult]) -> bool {
    items.iter().any(|item| !item.success)
}

fn access_decision_failed(response: &server::AdminResponse) -> bool {
    matches!(
        response,
        server::AdminResponse::AccessDecisions { items } if any_decision_failed(items)
    )
}

fn exit_access_json_error(message: impl Into<String>) -> ! {
    // A broken stdout cannot carry the promised JSON document. Suppress a
    // second, human-formatted diagnostic so machine consumers never receive
    // mixed output from an access command in JSON mode.
    let _ = print_json(&access_json_error(message));
    std::process::exit(EXIT_GUARD_ERROR);
}

fn access_item_human(item: &server::AccessItem) -> String {
    let scope = if item.effective_scope.is_empty() {
        "none".to_string()
    } else {
        item.effective_scope.join(",")
    };
    let expiry = item
        .expires_unix
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_string());
    let uses = use_budget_display(&item.use_policy, item.remaining_uses);
    let mut lines = vec![
        format!(
            "access {} {}",
            card_text(&item.kind),
            card_text(&item.reference)
        ),
        format!("state: {}", card_text(&item.state)),
        format!("requester: {}", card_text(&item.requester)),
        format!("target: {}", card_text(&item.target)),
        format!("scope: {}", card_text(&scope)),
        format!("expiry: {expiry}"),
        format!("uses: {uses}"),
    ];
    if let Some(intent) = &item.intent {
        lines.push(format!("intent: {}", card_text(intent)));
    }
    if let Some(reason) = &item.decided_reason {
        lines.push(format!("reason: {}", card_text(reason)));
    }
    if !item.capabilities.is_empty() {
        lines.push("capabilities:".to_string());
        for capability in &item.capabilities {
            lines.push(format!(
                "  {}: {} consequence={} baseline={} trusted={} revert={}",
                card_text(&capability.verb),
                card_text(&capability.description),
                card_text(&capability.consequence),
                capability.baseline,
                capability.trusted,
                if capability.has_revert {
                    "available"
                } else {
                    "none"
                },
            ));
            if !capability.baseline {
                let matcher = serde_json::to_string(&capability.matcher)
                    .expect("serde_json::Value serialization cannot fail");
                lines.push(format!("    matcher: {}", card_text(&matcher)));
                lines.push(format!(
                    "    matcher_digest: {}",
                    card_text(&capability.matcher_digest)
                ));
            }
            if let Some(plan) = &capability.credential_plan {
                lines.push(format!("    credential_plan: {}", card_text(plan)));
            }
            if let Some(evidence) = &capability.evidence {
                lines.push(format!("    evidence: {}", card_text(evidence)));
            }
        }
    }
    lines.push(format!("next: {}", card_text(&item.next_action)));
    for command in &item.approval_options {
        lines.push(format!("approval: {}", card_text(command)));
    }
    lines.join("\n")
}

fn use_budget_display(use_policy: &str, remaining_uses: Option<u64>) -> String {
    if use_policy == "bounded" {
        remaining_uses
            .map(|value| value.to_string())
            .unwrap_or_else(|| "0".to_string())
    } else {
        use_policy.to_string()
    }
}

fn print_access_decision_lines(items: &[server::AccessDecisionResult]) {
    for item in items {
        println!(
            "{} success={} state={} target={} uses={} message={}",
            item.request,
            item.success,
            item.state,
            item.target.as_deref().unwrap_or("none"),
            use_budget_display(&item.use_policy, item.remaining_uses),
            item.message,
        );
    }
}

/// The review prompt engages only when a person is present on every stream it
/// uses: answers come from stdin, cards and prompts render on stderr, and
/// decision lines land on stdout. Redirecting any of them keeps the immediate,
/// prompt-free contract instead of blocking on an invisible prompt.
fn access_review_is_interactive() -> bool {
    access_review_enabled(
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
        std::io::stderr().is_terminal(),
    )
}

fn access_review_enabled(stdin_tty: bool, stdout_tty: bool, stderr_tty: bool) -> bool {
    stdin_tty && stdout_tty && stderr_tty
}

/// Escape server-supplied text for terminal display. Request intent and verb
/// metadata originate from agent input; rendering them raw would let a crafted
/// request repaint or hide card lines with control sequences at the moment of
/// decision.
fn card_text(value: &str) -> String {
    guard::redact::audit_escape(value).into_owned()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessReviewChoice {
    Approve,
    Deny,
    Skip,
    Quit,
}

fn parse_access_review_choice(input: &str) -> Option<AccessReviewChoice> {
    match input.trim().to_ascii_lowercase().as_str() {
        "a" | "approve" | "y" | "yes" => Some(AccessReviewChoice::Approve),
        "d" | "deny" | "n" | "no" => Some(AccessReviewChoice::Deny),
        "s" | "skip" => Some(AccessReviewChoice::Skip),
        "q" | "quit" => Some(AccessReviewChoice::Quit),
        _ => None,
    }
}

fn access_state_color(state: &str) -> AnsiColor {
    match state {
        "pending" | "approving" => AnsiColor::Yellow,
        "approved" | "active" => AnsiColor::Green,
        "denied" | "withdrawn" | "revoked" | "expired" | "exhausted" | "exec_failed" => {
            AnsiColor::Red
        }
        _ => AnsiColor::Cyan,
    }
}

fn consequence_color(consequence: &str) -> AnsiColor {
    match consequence {
        "irreversible" => AnsiColor::Red,
        "recoverable" => AnsiColor::Yellow,
        _ => AnsiColor::Green,
    }
}

/// One reviewable card for the interactive approve prompt. Same facts as
/// `access_item_human`, arranged for a person deciding rather than a script
/// parsing: consequence classes are colored, timestamps are readable, and the
/// exact reviewed matcher stays visible for non-baseline capabilities. Every
/// server-supplied string passes through `card_text` before painting.
fn access_item_card(item: &server::AccessItem, colors: bool) -> Vec<String> {
    let scope = if item.effective_scope.is_empty() {
        "none".to_string()
    } else {
        item.effective_scope.join(",")
    };
    let expiry = item
        .expires_unix
        .map(format_timestamp)
        .unwrap_or_else(|| "none".to_string());
    let uses = use_budget_display(&item.use_policy, item.remaining_uses);
    let mut lines = vec![
        format!(
            "{} {}",
            paint(
                format!("access {}", card_text(&item.kind)),
                AnsiColor::Bold,
                colors
            ),
            paint(card_text(&item.reference), AnsiColor::Cyan, colors),
        ),
        format!(
            "  state:     {}",
            paint(
                card_text(&item.state),
                access_state_color(&item.state),
                colors
            )
        ),
        format!("  requester: {}", card_text(&item.requester)),
        format!("  target:    {}", card_text(&item.target)),
    ];
    if let Some(intent) = &item.intent {
        lines.push(format!(
            "  intent:    {}",
            paint(card_text(intent), AnsiColor::Bold, colors)
        ));
    }
    lines.push(format!("  scope:     {}", card_text(&scope)));
    lines.push(format!("  uses:      {uses}"));
    lines.push(format!("  expiry:    {expiry}"));
    if let Some(reason) = &item.decided_reason {
        lines.push(format!("  reason:    {}", card_text(reason)));
    }
    if !item.capabilities.is_empty() {
        lines.push("  grants:".to_string());
        for capability in &item.capabilities {
            lines.push(format!(
                "    {} {}: {} trusted={} revert={}",
                paint(
                    card_text(&capability.consequence),
                    consequence_color(&capability.consequence),
                    colors,
                ),
                paint(card_text(&capability.verb), AnsiColor::Bold, colors),
                card_text(&capability.description),
                capability.trusted,
                if capability.has_revert {
                    "available"
                } else {
                    "none"
                },
            ));
            if !capability.baseline {
                let matcher = serde_json::to_string(&capability.matcher)
                    .expect("serde_json::Value serialization cannot fail");
                lines.push(format!("      matcher: {}", card_text(&matcher)));
                lines.push(format!(
                    "      matcher_digest: {}",
                    card_text(&capability.matcher_digest)
                ));
            }
            if let Some(plan) = &capability.credential_plan {
                lines.push(format!("      credential_plan: {}", card_text(plan)));
            }
            if let Some(evidence) = &capability.evidence {
                lines.push(format!("      evidence: {}", card_text(evidence)));
            }
        }
    }
    lines.push(format!("  next:      {}", card_text(&item.next_action)));
    for command in &item.approval_options {
        lines.push(format!("  approval:  {}", card_text(command)));
    }
    lines
}

fn prompt_access_review_choice(reference: &str, colors: bool) -> Result<AccessReviewChoice> {
    loop {
        eprint!(
            "{} [a]pprove / [d]eny / [s]kip / [q]uit: ",
            paint(reference, AnsiColor::Bold, colors)
        );
        std::io::stderr().flush()?;
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line)? == 0 {
            // EOF on the terminal (Ctrl-D) abandons the rest of the batch.
            eprintln!();
            return Ok(AccessReviewChoice::Quit);
        }
        match parse_access_review_choice(&line) {
            Some(choice) => return Ok(choice),
            None => eprintln!("answer a, d, s, or q"),
        }
    }
}

fn prompt_access_deny_reason() -> Result<Option<String>> {
    eprint!("deny reason (optional): ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let reason = line.trim();
    Ok((!reason.is_empty()).then(|| reason.to_string()))
}

/// Review each request on the operator's terminal before deciding. Cards and
/// prompts go to stderr; stdout carries only the decision lines the
/// non-interactive path already prints, one batch item at a time so an
/// abandoned review never undoes a decision already sent.
async fn handle_access_approve_interactive(
    requests: Vec<String>,
    uses: Option<u64>,
    socket: Option<String>,
) -> Result<()> {
    let config = load_client_config(false)?;
    let (socket_path, tcp_port, source) = resolve_client_endpoint_with_source(socket, &config);
    let client = admin_client(socket_path, tcp_port, &config);
    let colors = color_enabled_for_stderr();
    let mut any_failed = false;
    let mut skipped: Vec<String> = Vec::new();
    let mut queue = requests.into_iter();
    while let Some(reference) = queue.next() {
        let item = match client
            .send_admin(server::AdminRequest::AccessShow {
                reference: reference.clone(),
            })
            .await
            .map_err(|error| describe_connect_failure(error, &client, source))?
        {
            server::AdminResponse::AccessItem { item } => item,
            server::AdminResponse::Error { message } => {
                any_failed = true;
                eprintln!("{reference}: {message}");
                skipped.push(reference);
                continue;
            }
            other => anyhow::bail!("unexpected access response: {other:?}"),
        };
        eprintln!();
        for line in access_item_card(&item, colors) {
            eprintln!("{line}");
        }
        if item.approval_options.is_empty() {
            eprintln!(
                "no approval action available (state: {})",
                card_text(&item.state)
            );
            any_failed = true;
            skipped.push(reference);
            continue;
        }
        // A consequence hold executes one immutable snapshot and accepts only a
        // one-time approval; the daemon offers exactly that form.
        let hold_only_once = item
            .approval_options
            .iter()
            .all(|option| option.ends_with("--once"));
        let effective_uses = if hold_only_once { Some(1) } else { uses };
        eprintln!(
            "an approve grants: {}",
            match effective_uses {
                None => "unlimited uses".to_string(),
                Some(1) if hold_only_once => "1 use (held snapshot, one-time only)".to_string(),
                Some(1) => "1 use".to_string(),
                Some(n) => format!("{n} uses"),
            }
        );
        let decision = match prompt_access_review_choice(&reference, colors)? {
            AccessReviewChoice::Approve => Some(server::AdminRequest::AccessApprove {
                handles: vec![reference.clone()],
                uses: effective_uses,
            }),
            AccessReviewChoice::Deny => Some(server::AdminRequest::AccessDeny {
                handles: vec![reference.clone()],
                reason: prompt_access_deny_reason()?,
            }),
            AccessReviewChoice::Skip => None,
            AccessReviewChoice::Quit => {
                skipped.push(reference);
                skipped.extend(queue.by_ref());
                break;
            }
        };
        let Some(decision) = decision else {
            skipped.push(reference);
            continue;
        };
        match client
            .send_admin(decision)
            .await
            .map_err(|error| describe_connect_failure(error, &client, source))?
        {
            server::AdminResponse::AccessDecisions { items } => {
                if any_decision_failed(&items) {
                    any_failed = true;
                    skipped.extend(
                        items
                            .iter()
                            .filter(|result| !result.success)
                            .map(|result| result.request.clone()),
                    );
                }
                print_access_decision_lines(&items);
            }
            server::AdminResponse::Error { message } => {
                any_failed = true;
                eprintln!("{reference}: {message}");
                skipped.push(reference);
            }
            other => anyhow::bail!("unexpected access response: {other:?}"),
        }
    }
    if !skipped.is_empty() {
        eprintln!("undecided: {}", skipped.join(", "));
    }
    if any_failed {
        std::process::exit(EXIT_GUARD_ACCESS_DECISION_FAILED);
    }
    Ok(())
}

fn render_gated_response(
    resp: &server::ExecuteResponse,
    streamed: bool,
    label: &str,
    explain: bool,
) -> Result<()> {
    match resp.status {
        Some(server::GateStatus::Held) => {
            let color = color_enabled_for_stderr();
            let handle = resp.handle.clone().unwrap_or_default();
            eprintln!(
                "{} for operator approval: {}",
                paint("HELD", AnsiColor::Yellow, color),
                resp.reason
            );
            eprintln!("  handle:  {}", handle);
            print_access_request_guidance(resp);
            print_verb_guidance(resp);
            eprintln!("  result:  not executed until approved");
            print_coverage(&resp.coverage);
            std::process::exit(EXIT_GUARD_HELD);
        }
        Some(server::GateStatus::Provisional) => {
            let color = color_enabled_for_stderr();
            if !streamed {
                if let Some(out) = &resp.stdout {
                    print!("{}", out);
                }
                if let Some(err) = &resp.stderr {
                    eprint!("{}", err);
                }
            }
            let handle = resp.handle.clone().unwrap_or_default();
            eprintln!(
                "{} containment envelope: {}",
                paint("PROVISIONAL", AnsiColor::Yellow, color),
                resp.reason
            );
            eprintln!("  handle:  {}", handle);
            eprintln!("  confirm: guard confirm {}", handle);
            eprintln!("  inspect: guard provisionals");
            print_provisional_window(resp);
            print_coverage(&resp.coverage);
            if let Some(code) = resp.exit_code {
                std::process::exit(code);
            }
            Ok(())
        }
        Some(server::GateStatus::DryRun) => {
            let color = color_enabled_for_stdout();
            println!(
                "{} {}",
                paint("[DRY-RUN]", AnsiColor::Cyan, color),
                resp.reason
            );
            print_coverage(&resp.coverage);
            Ok(())
        }
        _ => {
            if resp.allowed {
                if !streamed {
                    if let Some(out) = &resp.stdout {
                        print!("{}", out);
                    }
                    if let Some(err) = &resp.stderr {
                        eprint!("{}", err);
                    }
                }
                if explain {
                    print_verb_guidance(resp);
                    eprintln!("  decision source: {}", resp.decision_source);
                }
                if let Some(code) = resp.exit_code {
                    std::process::exit(code);
                }
                Ok(())
            } else {
                let color = color_enabled_for_stderr();
                eprintln!(
                    "{} ({}): {}",
                    paint("DENIED", AnsiColor::Red, color),
                    label,
                    resp.reason
                );
                print_access_request_guidance(resp);
                print_verb_guidance(resp);
                std::process::exit(EXIT_GUARD_DENIED);
            }
        }
    }
}

pub(crate) async fn handle_gate_action(
    socket: Option<String>,
    action: &str,
    handle: String,
) -> Result<()> {
    let (client, source) = gate_client(socket, false)?;
    let request = match action {
        "confirm" => server::AdminRequest::Confirm { handle },
        "revert" => server::AdminRequest::Revert { handle },
        _ => unreachable!("unknown gate action"),
    };
    match client
        .send_admin(request)
        .await
        .map_err(|e| describe_connect_failure(e, &client, source))?
    {
        server::AdminResponse::GateAction {
            message,
            exit_code,
            stdout,
            stderr,
        } => {
            println!("{}", message);
            if let Some(out) = &stdout {
                print!("{}", out);
            }
            if let Some(err) = &stderr {
                eprint!("{}", err);
            }
            if let Some(code) = exit_code {
                std::process::exit(code);
            }
            Ok(())
        }
        server::AdminResponse::Error { message } => {
            eprintln!("error: {}", message);
            std::process::exit(1);
        }
        _ => {
            eprintln!("unexpected response");
            std::process::exit(1);
        }
    }
}

pub(crate) async fn run_mcp(subcommand: McpCommands) -> Result<()> {
    match subcommand {
        McpCommands::Serve {
            socket,
            tcp_port,
            tool_name,
            http,
        } => {
            let config = load_client_config(false)?;
            let (mut socket_path, mut resolved_tcp_port) = resolve_client_endpoint(socket, &config);
            if let Some(port) = tcp_port {
                socket_path = None;
                resolved_tcp_port = Some(port);
            }
            let auth_token = resolve_mcp_daemon_token(&config);
            let session_token = std::env::var("GUARD_SESSION")
                .ok()
                .filter(|value| !value.is_empty());
            let http_addr = match http {
                Some(addr) => Some(
                    addr.parse::<std::net::SocketAddr>()
                        .with_context(|| format!("invalid --http address '{addr}'"))?,
                ),
                None => None,
            };
            // HTTP MCP credentials never enter argv. validate() rejects HTTP
            // mode unless GUARD_MCP_TOKEN supplies a nonempty bearer.
            let http_token = guard_env("MCP_TOKEN").filter(|token| !token.is_empty());

            let mcp_config = mcp::McpConfig {
                socket_path,
                tcp_port: resolved_tcp_port,
                auth_token,
                session_token,
                tool_name,
                http_addr,
                http_token,
            };

            mcp::serve(mcp_config).await
        }
    }
}

fn resolve_mcp_daemon_token(config: &client_config::ClientConfig) -> Option<String> {
    config.auth_token.clone()
}

/// Where the resolved endpoint came from. Decides the remediation hint
/// attached to connect failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndpointSource {
    Flag,
    Env,
    Config,
    Default,
}

/// Resolve the client endpoint from explicit override > env var > client
/// config > platform default. Returns (socket, tcp_port). At most one
/// of the two will be Some.
pub(crate) fn resolve_client_endpoint(
    socket_override: Option<String>,
    config: &client_config::ClientConfig,
) -> (Option<PathBuf>, Option<u16>) {
    let (socket, tcp_port, _) = resolve_client_endpoint_with_source(socket_override, config);
    (socket, tcp_port)
}

/// `resolve_client_endpoint`, also reporting where the endpoint came from
/// so connect failures can carry the right remediation hint.
pub(crate) fn resolve_client_endpoint_with_source(
    socket_override: Option<String>,
    config: &client_config::ClientConfig,
) -> (Option<PathBuf>, Option<u16>, EndpointSource) {
    resolve_endpoint(
        socket_override,
        std::env::var("GUARD_TCP_PORT").ok(),
        std::env::var("GUARD_SOCKET").ok(),
        config,
        default_client_socket_exists(),
    )
}

#[cfg(unix)]
fn default_client_socket_exists() -> bool {
    std::path::Path::new(defaults::SYSTEM_SOCKET).exists()
}

#[cfg(not(unix))]
fn default_client_socket_exists() -> bool {
    false
}

/// Endpoint resolution core, kept pure (env values and the system-socket
/// probe are inputs) so the precedence order is unit-testable.
fn resolve_endpoint(
    socket_override: Option<String>,
    env_tcp_port: Option<String>,
    env_socket: Option<String>,
    config: &client_config::ClientConfig,
    default_socket_exists: bool,
) -> (Option<PathBuf>, Option<u16>, EndpointSource) {
    if let Some(s) = socket_override {
        return (Some(PathBuf::from(s)), None, EndpointSource::Flag);
    }
    if let Some(port) = env_tcp_port {
        if let Ok(port) = port.parse::<u16>() {
            return (None, Some(port), EndpointSource::Env);
        }
    }
    if let Some(s) = env_socket {
        if !s.is_empty() {
            // A named pipe on Windows, a UNIX domain socket on Unix.
            return (Some(PathBuf::from(s)), None, EndpointSource::Env);
        }
    }
    if let Some(port) = config.server_tcp_port {
        return (None, Some(port), EndpointSource::Config);
    }
    // A configured socket is a named pipe on Windows, a UNIX domain socket on
    // Unix; either way it takes precedence over the platform default below.
    if let Some(ref s) = config.server_socket {
        return (Some(PathBuf::from(s)), None, EndpointSource::Config);
    }
    #[cfg(windows)]
    {
        let _ = default_socket_exists;
        (
            None,
            Some(defaults::DEFAULT_TCP_PORT),
            EndpointSource::Default,
        )
    }
    // Nothing configured anywhere: prefer the system socket (the systemd
    // RuntimeDirectory layout) when it exists, else the home-dir socket a
    // no-flag `guard server start` binds. Existence decides because the
    // two layouts are indistinguishable client-side any other way.
    #[cfg(unix)]
    {
        if default_socket_exists {
            (
                Some(PathBuf::from(defaults::SYSTEM_SOCKET)),
                None,
                EndpointSource::Default,
            )
        } else {
            let socket =
                defaults::home_socket().unwrap_or_else(|| PathBuf::from(defaults::SYSTEM_SOCKET));
            (Some(socket), None, EndpointSource::Default)
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = default_socket_exists;
        (
            None,
            Some(defaults::DEFAULT_TCP_PORT),
            EndpointSource::Default,
        )
    }
}

/// Attach the attempted endpoint and a one-line remediation hint to a
/// connect failure; every other error passes through untouched.
/// `endpoint_for_log()` never contains tokens.
fn describe_connect_failure(
    err: anyhow::Error,
    client: &daemon_client::Client,
    source: EndpointSource,
) -> anyhow::Error {
    let connect_failed = err
        .chain()
        .any(|cause| cause.to_string() == "failed to connect to guard server");
    if !connect_failed {
        return err;
    }
    let hint = match source {
        EndpointSource::Default => "is the daemon running? Start it with `guard server start`",
        EndpointSource::Flag => "check the --socket value against the daemon's listen endpoint",
        EndpointSource::Env => "check the GUARD_SOCKET/GUARD_TCP_PORT overrides",
        EndpointSource::Config => {
            "check `guard config show` or the GUARD_SOCKET/GUARD_TCP_PORT overrides"
        }
    };
    err.context(format!(
        "cannot reach guard server at {}; {}",
        client.endpoint_for_log(),
        hint
    ))
}

pub(crate) fn admin_client(
    socket_path: Option<PathBuf>,
    tcp_port: Option<u16>,
    config: &client_config::ClientConfig,
) -> daemon_client::Client {
    let client = daemon_client::Client::new(socket_path, tcp_port);
    if let Some(token) = resolve_admin_token(config) {
        client.with_admin_token(token)
    } else {
        client
    }
}

/// Normalize a `config set-server` value before persisting it. A TCP
/// host:port passes through unchanged; a filesystem socket path is
/// absolutized so a later `guard run` from another directory resolves the
/// same socket. On Windows the value names a pipe, not a path, and passes
/// through unchanged.
fn normalize_server_socket_value(value: String) -> String {
    if looks_like_tcp_endpoint(&value) {
        return value;
    }
    #[cfg(unix)]
    {
        absolute_path(&value)
    }
    #[cfg(not(unix))]
    {
        value
    }
}

/// A host:port endpoint: nonempty host, valid u16 port.
fn looks_like_tcp_endpoint(value: &str) -> bool {
    value
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok())
}

/// Resolve a possibly-relative path against the client's working directory. The
/// daemon canonicalizes again server-side; making it absolute here ensures the
/// server resolves the file the caller meant, not one relative to the daemon CWD.
#[cfg(unix)]
fn absolute_path(path: &str) -> String {
    let p = PathBuf::from(path);
    if p.is_absolute() {
        return path.to_string();
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(p).display().to_string(),
        Err(_) => path.to_string(),
    }
}

pub(crate) async fn handle_status(socket: Option<String>, json: bool) -> Result<()> {
    let config = load_client_config(json)?;
    let (socket_path, tcp_port, source) = resolve_client_endpoint_with_source(socket, &config);
    let client = admin_client(socket_path.clone(), tcp_port, &config);

    // Client info first - useful even when the daemon is unreachable.
    if !json {
        println!("Client:");
        println!(
            "  version        {} ({}, {}{})",
            env!("CARGO_PKG_VERSION"),
            env!("GUARD_GIT_COMMIT"),
            env!("GUARD_GIT_BRANCH"),
            option_env!("GUARD_GIT_TAG")
                .map(|t| format!(", tag {t}"))
                .unwrap_or_default()
        );
        println!("  endpoint       {}", client.endpoint_for_log());
        println!();
    }

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
            eprintln!("Server: ping refused - {}", message);
            std::process::exit(1);
        }
        Ok(other) => {
            eprintln!("Server: unexpected ping response: {:?}", other);
            std::process::exit(1);
        }
        Err(e) => {
            let e = describe_connect_failure(e, &client, source);
            eprintln!("Server: unreachable - {:#}", e);
            std::process::exit(1);
        }
    };

    let (version, uptime, mode, dry_run) = ping;
    if !json {
        println!("Server:");
        println!("  version        {}", version);
        println!("  uptime         {}s", uptime);
        println!("  mode           {}", mode);
        println!("  dry_run        {}", dry_run);
        if version != env!("CARGO_PKG_VERSION") {
            eprintln!(
                "warning: guard client {} differs from server {}",
                env!("CARGO_PKG_VERSION"),
                version
            );
        }
    }

    // Try the full Status RPC. It succeeds only with operator authority for
    // the active transport.
    match client.send_admin(server::AdminRequest::Status).await {
        Ok(server::AdminResponse::Status { status }) => {
            if json {
                return print_json(&serde_json::json!({
                    "schema_version": JSON_SCHEMA_VERSION,
                    "type": "status",
                    "client": {
                        "version": env!("CARGO_PKG_VERSION"),
                        "git_commit": env!("GUARD_GIT_COMMIT"),
                        "git_branch": env!("GUARD_GIT_BRANCH"),
                        "git_tag": option_env!("GUARD_GIT_TAG"),
                        "endpoint": client.endpoint_for_log(),
                    },
                    "server": {
                        "version": version,
                        "uptime_secs": uptime,
                        "mode": mode,
                        "dry_run": dry_run,
                        "version_mismatch": version != env!("CARGO_PKG_VERSION"),
                        "full_restricted": false,
                        "full": status,
                    },
                }));
            }
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
                "  learning       enabled={} candidates={}",
                status.learning_enabled, status.learned_rule_count
            );
            println!(
                "  learn_deny     enabled={} shapes={}",
                status.deny_learning_enabled, status.deny_shape_count
            );
            println!(
                "  learn_allow    enabled={} observations={}",
                status.allow_promotion_enabled, status.allow_promotion_observation_count
            );
            println!("  verb_catalog  {}", status.verb_catalog_hash);
            if let Some(changed) = status.verb_catalog_changed_unix {
                println!("  verb_changed  {}", format_timestamp(changed));
            }
            println!(
                "  queues         approvals={} provisionals={}",
                status.pending_approvals, status.pending_provisionals
            );
            println!(
                "  command_load   handlers={}/{} rejected={} evaluators={}/{} rate_limited={} circuit_rejected={} errors={}",
                status.command_admission.handler_admitted,
                status.command_admission.handler_attempted,
                status.command_admission.handler_rejected,
                status.command_admission.evaluator_admitted,
                status.command_admission.evaluator_attempted,
                status.command_admission.evaluator_rate_limited,
                status.command_admission.evaluator_circuit_rejections,
                status.command_admission.evaluator_errors,
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
            if json {
                return print_json(&serde_json::json!({
                    "schema_version": JSON_SCHEMA_VERSION,
                    "type": "status",
                    "client": {
                        "version": env!("CARGO_PKG_VERSION"),
                        "git_commit": env!("GUARD_GIT_COMMIT"),
                        "git_branch": env!("GUARD_GIT_BRANCH"),
                        "git_tag": option_env!("GUARD_GIT_TAG"),
                        "endpoint": client.endpoint_for_log(),
                    },
                    "server": {
                        "version": version,
                        "uptime_secs": uptime,
                        "mode": mode,
                        "dry_run": dry_run,
                        "version_mismatch": version != env!("CARGO_PKG_VERSION"),
                        "full_restricted": true,
                        "full": null,
                    },
                }));
            }
            // Expected when the caller lacks operator authority. Hide the rest.
            println!();
            println!("(full server config requires operator authority)");
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

pub(crate) async fn handle_config(subcommand: ConfigCommands) -> Result<()> {
    // Surface load errors loudly for every subcommand - this catches the
    // relative-XDG_CONFIG_HOME case that can otherwise fall through silently
    // and risked writing to the default path instead of the intended one.
    match subcommand {
        ConfigCommands::Show { json } => {
            let config = load_client_config(json)?;
            if json {
                return print_json(&serde_json::json!({
                    "schema_version": JSON_SCHEMA_VERSION,
                    "type": "client_config",
                    "server_socket": config.server_socket,
                    "server_tcp_port": config.server_tcp_port,
                    "default_user": config.default_user,
                    "auth_token_configured": config.auth_token.is_some(),
                    "admin_token_configured": config.admin_token.is_some(),
                }));
            }
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
            let mut config = load_client_config(false)?;
            let socket = normalize_server_socket_value(socket);
            config.server_socket = Some(socket.clone());
            config.server_tcp_port = None;
            config.save()?;
            println!("Server socket set to {}", socket);
        }
        ConfigCommands::SetPort { port } => {
            let mut config = load_client_config(false)?;
            config.server_tcp_port = Some(port);
            config.server_socket = None;
            config.save()?;
            println!("Server port set");
        }
        ConfigCommands::SetToken => {
            let mut config = load_client_config(false)?;
            config.auth_token = Some(read_secret_input("Execution token: ")?);
            config.save()?;
            println!("Token set");
        }
        ConfigCommands::SetAdminToken => {
            let mut config = load_client_config(false)?;
            config.admin_token = Some(read_secret_input("Admin token: ")?);
            config.save()?;
            println!("Admin token set");
        }
        ConfigCommands::SetUser { user } => {
            let mut config = load_client_config(false)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(socket: Option<&str>, port: Option<u16>) -> client_config::ClientConfig {
        client_config::ClientConfig {
            server_socket: socket.map(str::to_string),
            server_tcp_port: port,
            ..Default::default()
        }
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
                        "guard access approve gr-11111111111111111111111111111111 --once"
                            .to_string(),
                    ],
                },
                server::AccessRequestGuidance {
                    reference: "gr-22222222222222222222222222222222".to_string(),
                    approval_options: vec![
                        "guard access approve gr-22222222222222222222222222222222 --uses 3"
                            .to_string(),
                    ],
                },
            ],
            coverage: None,
            verb_matches: Vec::new(),
            verb_guidance: Some("request access".to_string()),
            confirm_deadline_unix: None,
            confirm_window_secs: None,
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
                    message: "approved".to_string(),
                },
                server::AccessDecisionResult {
                    request: "request-failed".to_string(),
                    success: false,
                    state: "failed".to_string(),
                    target: None,
                    remaining_uses: None,
                    use_policy: "unavailable".to_string(),
                    message: "not found".to_string(),
                },
            ],
        };
        let document = access_json_response(&response).unwrap();
        assert_eq!(document["schema_version"], JSON_SCHEMA_VERSION);
        assert_eq!(document["type"], "access_decisions");
        assert_eq!(
            document["response"]["items"].as_array().map(Vec::len),
            Some(2)
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
                message: "not found".to_string(),
            }],
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
                message: "approved".to_string(),
            }],
        };
        assert!(!access_decision_failed(&all_succeeded));
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

    #[test]
    fn access_item_card_shows_decision_facts_and_reviewed_matcher() {
        let item = server::AccessItem {
            reference: "gr-11111111111111111111111111111111".to_string(),
            kind: "request".to_string(),
            requester: "uid:1004".to_string(),
            target: "agent:1004".to_string(),
            effective_scope: vec!["helm-upgrade".to_string()],
            expires_unix: Some(1_753_000_000),
            remaining_uses: Some(3),
            use_policy: "bounded".to_string(),
            state: "pending".to_string(),
            next_action: "approve or deny".to_string(),
            approval_options: vec![
                "guard access approve gr-11111111111111111111111111111111".to_string()
            ],
            intent: Some("upgrade the netdata release".to_string()),
            capabilities: vec![server::AccessCapability {
                verb: "helm-upgrade".to_string(),
                description: "Upgrade one release".to_string(),
                matcher: serde_json::json!({"binary": "helm"}),
                matcher_digest: "digest".to_string(),
                consequence: "recoverable".to_string(),
                credential_plan: None,
                baseline: false,
                trusted: false,
                has_revert: true,
                evidence: Some("rollback validated".to_string()),
            }],
            decided_reason: None,
        };
        let card = access_item_card(&item, false).join("\n");
        assert!(!card.contains('\u{1b}'), "colors off must emit no ANSI");
        for fact in [
            "access request gr-11111111111111111111111111111111",
            "state:     pending",
            "requester: uid:1004",
            "intent:    upgrade the netdata release",
            "uses:      3",
            "recoverable helm-upgrade: Upgrade one release trusted=false revert=available",
            "matcher: {\"binary\":\"helm\"}",
            "matcher_digest: digest",
            "evidence: rollback validated",
            "next:      approve or deny",
            "approval:  guard access approve gr-11111111111111111111111111111111",
        ] {
            assert!(card.contains(fact), "card is missing {fact:?}:\n{card}");
        }
        let colored = access_item_card(&item, true).join("\n");
        assert!(colored.contains('\u{1b}'), "colors on must emit ANSI");
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
            state: "pending".to_string(),
            next_action: "approve or deny".to_string(),
            approval_options: vec!["\u{1b}[1A\u{1b}[2Kguard access approve x".to_string()],
            intent: Some("\u{1b}[2J\u{1b}[H\nintent:    read one log file".to_string()),
            capabilities: Vec::new(),
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
        let human = access_item_human(&item);
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
        let (socket, port, source) =
            resolve_endpoint(None, None, None, &config_with(None, None), true);
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
}
