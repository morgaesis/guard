use super::*;

/// Consequence-gating options parsed from `guard run` flags.
pub(crate) struct GatingOptions {
    pub(crate) revert: Option<String>,
    pub(crate) confirm_within: Option<u64>,
    pub(crate) require_approval: bool,
    pub(crate) wait_approval: Option<u64>,
    pub(crate) reevaluate: bool,
}

/// CLI spelling of the ssh host-key mode. Kebab-case value names
/// (`only-existing`, `accept-new`, `accept-all`) are derived by clap.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum SshHostKeyCliMode {
    OnlyExisting,
    AcceptNew,
    AcceptAll,
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
    Ok(server::RevertSpec {
        binary,
        args: it.collect(),
    })
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

pub(crate) async fn run_exec(
    binary: String,
    args: Vec<String>,
    env_vars: HashMap<String, String>,
    secret_vars: HashMap<String, String>,
    gating: GatingOptions,
    hostkey: server::SshHostKeyMode,
    json: bool,
) -> Result<()> {
    let config = client_config::ClientConfig::load().ok().unwrap_or_default();

    let (socket_path, tcp_port, endpoint_source) =
        resolve_client_endpoint_with_source(None, &config);

    let revert = match gating.revert.as_deref() {
        Some(spec) => Some(parse_revert(spec)?),
        None => None,
    };

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
    let resp = if json {
        client
            .execute_with_injections(&binary, &args, env_vars, secret_vars)
            .await
    } else {
        client
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
                "{} for daemon-principal approval: {}",
                paint("HELD", AnsiColor::Yellow, color),
                resp.reason
            );
            eprintln!("  handle:  {}", handle);
            eprintln!("  approve: guard approve {}", handle);
            eprintln!("  poll:    guard approvals {}", handle);
            eprintln!("  result:  not executed until approved");
            print_coverage(&resp.coverage);
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
            eprintln!("  result:  executed, auto-reverts unless confirmed");
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
    std::process::exit(response.exit_code.unwrap_or(0));
}

/// Resolve the admin endpoint and build a client for a gate-control RPC.
fn gate_client(socket_override: Option<String>) -> (daemon_client::Client, EndpointSource) {
    let config = client_config::ClientConfig::load().ok().unwrap_or_default();
    let (socket_path, tcp_port, source) =
        resolve_client_endpoint_with_source(socket_override, &config);
    let mut client = daemon_client::Client::new(socket_path, tcp_port);
    if let Some(token) = config.auth_token {
        client = client.with_auth(token);
    }
    (client, source)
}

pub(crate) async fn handle_provisionals(socket: Option<String>, json: bool) -> Result<()> {
    let (client, source) = gate_client(socket);
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
                    "[{}] handle={} cmd={:?} revert={:?} deadline={} reason={:?}{}",
                    status,
                    p.handle,
                    p.command,
                    p.revert_command,
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

pub(crate) async fn handle_approval_note_cmd(
    socket: Option<String>,
    handle: String,
    text: String,
) -> Result<()> {
    let (client, source) = gate_client(socket);
    match client
        .send_admin(server::AdminRequest::ApprovalNote { handle, text })
        .await
        .map_err(|e| describe_connect_failure(e, &client, source))?
    {
        server::AdminResponse::ApprovalShow { item } => {
            let color = color_enabled_for_stdout();
            println!(
                "[{}] handle={} cmd={:?}",
                paint(&item.status, AnsiColor::Yellow, color),
                item.handle,
                item.command
            );
            for n in &item.notes {
                println!(
                    "  note [{}] {}: {}",
                    format_timestamp(n.at_unix),
                    n.author,
                    n.text
                );
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

pub(crate) async fn handle_approvals(
    socket: Option<String>,
    handle: Option<String>,
    json: bool,
) -> Result<()> {
    let (client, source) = gate_client(socket);
    let request = match handle {
        Some(h) => server::AdminRequest::ApprovalShow { handle: h },
        None => server::AdminRequest::ApprovalList,
    };
    match client
        .send_admin(request)
        .await
        .map_err(|e| describe_connect_failure(e, &client, source))?
    {
        server::AdminResponse::Approvals { items } => {
            if json {
                return print_json(&serde_json::json!({
                    "schema_version": JSON_SCHEMA_VERSION,
                    "type": "approval_list",
                    "items": items,
                }));
            }
            if items.is_empty() {
                println!("(no approvals)");
            }
            let color = color_enabled_for_stdout();
            for a in &items {
                let status_color = match a.status.as_str() {
                    "approved" => AnsiColor::Green,
                    "denied" | "expired" | "exec_failed" => AnsiColor::Red,
                    _ => AnsiColor::Yellow,
                };
                println!(
                    "[{}] handle={} risk={:?} class={:?} created={} deadline={} cmd={:?} fp={} reason={:?}",
                    paint(&a.status, status_color, color),
                    a.handle,
                    a.risk,
                    a.reversibility,
                    format_timestamp(a.created_unix),
                    format_timestamp(a.deadline_unix),
                    a.command,
                    a.fingerprint,
                    a.reason
                );
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
            let color = color_enabled_for_stdout();
            println!(
                "[{}] handle={} risk={:?} class={:?} created={} deadline={} cmd={:?} fp={}",
                paint(&item.status, AnsiColor::Yellow, color),
                item.handle,
                item.risk,
                item.reversibility,
                format_timestamp(item.created_unix),
                format_timestamp(item.deadline_unix),
                item.command,
                item.fingerprint
            );
            if let Some(code) = item.exit_code {
                println!("exit_code={}", code);
            }
            if let Some(out) = &item.stdout {
                print!("{}", out);
            }
            if let Some(err) = &item.stderr {
                eprint!("{}", err);
            }
            if let Some(reason) = &item.decided_reason {
                println!("decision: {}", reason);
            }
            for n in &item.notes {
                println!(
                    "  note [{}] {}: {}",
                    format_timestamp(n.at_unix),
                    n.author,
                    n.text
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

pub(crate) async fn handle_verb(subcommand: VerbCommands) -> Result<()> {
    match subcommand {
        VerbCommands::List { socket, json } => {
            let (client, source) = gate_client(socket);
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
                            "{} [{}]{}{}{} - {}",
                            v.name,
                            v.consequence,
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
                        if let Some(evidence) = &v.evidence {
                            println!("    evidence: {}", evidence);
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
        VerbCommands::Run {
            name,
            params,
            confirm_within,
            wait_approval,
            socket,
            json,
        } => {
            let config = client_config::ClientConfig::load().ok().unwrap_or_default();
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
            if let Ok(session) = std::env::var("GUARD_SESSION") {
                if !session.is_empty() {
                    client = client.with_session(session);
                }
            }
            // Verb binary/args are rendered server-side; the client sends empty.
            let mut streamed = false;
            let resp = if json {
                client
                    .execute_with_injections("", &[], HashMap::new(), HashMap::new())
                    .await
            } else {
                client
                    .execute_streaming_with_injections(
                        "",
                        &[],
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
            render_gated_response(&resp, streamed, &name)
        }
        VerbCommands::Create {
            prompt,
            binary,
            preview,
            socket,
            json,
        } => {
            let (client, source) = gate_client(socket);
            let req = server::AdminRequest::VerbCreate {
                prose: prompt,
                binary_hint: binary,
                preview,
            };
            match client
                .send_admin(req)
                .await
                .map_err(|e| describe_connect_failure(e, &client, source))?
            {
                server::AdminResponse::VerbCreated { verb, persisted } => {
                    if json {
                        return print_json(&serde_json::json!({
                            "schema_version": JSON_SCHEMA_VERSION,
                            "type": "verb",
                            "persisted": persisted,
                            "verb": verb,
                        }));
                    }
                    if persisted {
                        println!("Created verb '{}' and added it to the catalog:", verb.name);
                    } else {
                        println!(
                            "Preview of verb '{}' (NOT written). Creating synthesizes again and may differ; every created verb is non-trusted and re-validated by the safety gate.",
                            verb.name
                        );
                    }
                    if let Some(ev) = &verb.evidence {
                        println!("  evidence: {}", ev);
                    }
                    println!();
                    match serde_yaml_ng::to_string(&verb) {
                        Ok(y) => print!("{}", y),
                        Err(_) => println!("{:#?}", verb),
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
    }
}

/// Print a gated response (shared by `guard run` and `guard verb run`).
fn render_gated_response(
    resp: &server::ExecuteResponse,
    streamed: bool,
    label: &str,
) -> Result<()> {
    match resp.status {
        Some(server::GateStatus::Held) => {
            let color = color_enabled_for_stderr();
            let handle = resp.handle.clone().unwrap_or_default();
            eprintln!(
                "{} for daemon-principal approval: {}",
                paint("HELD", AnsiColor::Yellow, color),
                resp.reason
            );
            eprintln!("  handle:  {}", handle);
            eprintln!("  approve: guard approve {}", handle);
            eprintln!("  poll:    guard approvals {}", handle);
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
            eprintln!("  result:  executed, auto-reverts unless confirmed");
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
    let (client, source) = gate_client(socket);
    let request = match action {
        "confirm" => server::AdminRequest::Confirm { handle },
        "revert" => server::AdminRequest::Revert { handle },
        "approve" => server::AdminRequest::Approve { handle },
        "deny" => server::AdminRequest::Deny { handle },
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
            token,
            tool_name,
            http,
            http_token,
        } => {
            let config = client_config::ClientConfig::load().ok().unwrap_or_default();
            let (mut socket_path, mut resolved_tcp_port) = resolve_client_endpoint(socket, &config);
            if let Some(port) = tcp_port {
                socket_path = None;
                resolved_tcp_port = Some(port);
            }
            let auth_token = token.or(config.auth_token);

            let http_addr = match http {
                Some(addr) => Some(
                    addr.parse::<std::net::SocketAddr>()
                        .with_context(|| format!("invalid --http address '{addr}'"))?,
                ),
                None => None,
            };
            // Bearer source: --http-token wins, else GUARD_MCP_TOKEN. Only
            // meaningful with --http; validate() rejects --http without a token.
            let http_token = http_token
                .filter(|t| !t.is_empty())
                .or_else(|| guard_env("MCP_TOKEN").filter(|t| !t.is_empty()));

            let mcp_config = mcp::McpConfig {
                socket_path,
                tcp_port: resolved_tcp_port,
                auth_token,
                tool_name,
                http_addr,
                http_token,
            };

            mcp::serve(mcp_config).await
        }
    }
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
    if let Some(token) = config.admin_token.clone() {
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
    let config = client_config::ClientConfig::load().ok().unwrap_or_default();
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

    // Try the full Status RPC. Succeeds for daemon-UID Unix callers or
    // TCP callers with the configured admin token.
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
                format!("\"{}...\"", preview)
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
    let now = guard::env::now_unix();
    Ok(now.saturating_sub(n.saturating_mul(multiplier)))
}

/// Mint a 128-bit session token as 32 lowercase hex chars. Uniqueness
/// collision is the only failure mode and is statistically irrelevant
/// at any plausible grant volume.
fn generate_session_token() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn top_level_grant_to_session_command(
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
            .is_some_and(|value| !looks_like_session_token(value));

    // A lone positional shaped like a session token (32 lowercase hex chars)
    // targets that session (Grant); anything else (absent, multi-word, or a
    // plain word like `readonly`) is prose that starts a New session.
    match token_or_prose {
        Some(token) if !single_positional_prose => SessionCommands::Grant {
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
        },
        other => {
            let prose = prose.or(other);
            SessionCommands::New {
                prose,
                profile: None,
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

/// Session tokens minted by `generate_session_token` are exactly 32 lowercase
/// hex characters; anything else in the positional slot is grant prose.
fn looks_like_session_token(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) async fn handle_session(subcommand: SessionCommands) -> Result<()> {
    let config = client_config::ClientConfig::load().ok().unwrap_or_default();

    // `session new` is special: it mints a token before deciding what to
    // send. If no grant flags are present we just print and exit; otherwise
    // we send a SessionGrant for the freshly-minted token.
    if let SessionCommands::New {
        prose,
        profile,
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
            || profile.is_some()
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

            let (socket_path, tcp_port, source) =
                resolve_client_endpoint_with_source(socket.clone(), &config);
            let client = admin_client(socket_path, tcp_port, &config);
            let request = server::AdminRequest::SessionGrant {
                token: token.clone(),
                allow: allow.clone(),
                deny: deny.clone(),
                ttl_secs: *ttl,
                prompt_append,
                prose: prose.clone(),
                profile: profile.clone(),
                static_only: *static_only,
                auto_amend,
            };
            match client
                .send_admin(request)
                .await
                .map_err(|e| describe_connect_failure(e, &client, source))?
            {
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
    let mut json_output = false;

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
                    profile: None,
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
            json,
        } => {
            json_output = json;
            let self_token = std::env::var("GUARD_SESSION")
                .ok()
                .filter(|value| !value.is_empty());
            let target = token.or_else(|| self_token.clone()).ok_or_else(|| {
                anyhow::anyhow!(
                    "guard session show needs a <token> argument or GUARD_SESSION to be set"
                )
            })?;
            (
                socket,
                server::AdminRequest::SessionShow {
                    token: target,
                    limit: Some(limit),
                    caller_token: self_token,
                },
            )
        }
        SessionCommands::List {
            history,
            since,
            full,
            socket,
            json,
        } => {
            json_output = json;
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
                    visible_token: std::env::var("GUARD_SESSION")
                        .ok()
                        .filter(|value| !value.is_empty()),
                },
            )
        }
    };

    let (socket_path, tcp_port, source) =
        resolve_client_endpoint_with_source(socket_override, &config);
    let client = admin_client(socket_path, tcp_port, &config);

    match client
        .send_admin(request)
        .await
        .map_err(|e| describe_connect_failure(e, &client, source))?
    {
        server::AdminResponse::Ok => {
            println!("ok");
        }
        server::AdminResponse::Error { message } => {
            eprintln!("error: {}", message);
            std::process::exit(1);
        }
        server::AdminResponse::SessionList {
            mut grants,
            mut history,
        } => {
            if json_output {
                if !print_full_prompt {
                    for grant in &mut grants {
                        truncate_prompt(&mut grant.prompt_append);
                    }
                    for entry in &mut history {
                        truncate_prompt(&mut entry.prompt_append);
                    }
                }
                return print_json(&serde_json::json!({
                    "schema_version": JSON_SCHEMA_VERSION,
                    "type": "session_list",
                    "active": grants,
                    "history": history,
                }));
            }
            if grants.is_empty() && history.is_empty() {
                println!("(no session grants)");
            } else {
                let color = color_enabled_for_stdout();
                for g in &grants {
                    let label = paint("[active]", AnsiColor::Green, color);
                    println!(
                        "{}  token={} allow={:?} deny={:?} allow_exact={:?} deny_exact={:?} static_only={} auto_amend={} granted_at={} expires_at={} prompt={} notes={:?}",
                        label,
                        g.token,
                        g.allow,
                        g.deny,
                        g.allow_exact,
                        g.deny_exact,
                        g.static_only,
                        g.auto_amend,
                        format_timestamp(g.granted_at),
                        format_optional_timestamp(g.expires_at),
                        format_prompt(g.prompt_append.as_deref(), print_full_prompt),
                        g.generated_notes,
                    );
                }
                for h in &history {
                    let label = match h.status {
                        server::HistoricalStatus::Revoked => {
                            paint("[revoked]", AnsiColor::Yellow, color)
                        }
                        server::HistoricalStatus::Expired => {
                            paint("[expired]", AnsiColor::Red, color)
                        }
                    };
                    println!(
                        "{} token={} allow={:?} deny={:?} allow_exact={:?} deny_exact={:?} static_only={} auto_amend={} granted_at={} ended_at={} expires_at={} prompt={} notes={:?}",
                        label,
                        h.token,
                        h.allow,
                        h.deny,
                        h.allow_exact,
                        h.deny_exact,
                        h.static_only,
                        h.auto_amend,
                        format_timestamp(h.granted_at),
                        format_timestamp(h.ended_at),
                        format_optional_timestamp(h.expires_at),
                        format_prompt(h.prompt_append.as_deref(), print_full_prompt),
                        h.generated_notes,
                    );
                }
            }
        }
        server::AdminResponse::SessionShow { report } => {
            if json_output {
                return print_json(&serde_json::json!({
                    "schema_version": JSON_SCHEMA_VERSION,
                    "type": "session",
                    "report": report,
                }));
            }
            if let Some(active) = report.active {
                println!(
                    "token={} status=active static_only={} auto_amend={} granted_at={} expires_at={} allow={:?} deny={:?} allow_exact={:?} deny_exact={:?}",
                    active.token,
                    active.static_only,
                    active.auto_amend,
                    format_timestamp(active.granted_at),
                    format_optional_timestamp(active.expires_at),
                    active.allow,
                    active.deny,
                    active.allow_exact,
                    active.deny_exact,
                );
                println!(
                    "prompt={}",
                    format_prompt(active.prompt_append.as_deref(), true)
                );
                println!("notes={:?}", active.generated_notes);
            } else {
                println!("status=inactive");
            }

            for entry in &report.history {
                let label = match entry.status {
                    server::HistoricalStatus::Revoked => "revoked",
                    server::HistoricalStatus::Expired => "expired",
                };
                println!(
                    "history status={} static_only={} auto_amend={} granted_at={} ended_at={} expires_at={} allow={:?} deny={:?} allow_exact={:?} deny_exact={:?} prompt={} notes={:?}",
                    label,
                    entry.static_only,
                    entry.auto_amend,
                    format_timestamp(entry.granted_at),
                    format_timestamp(entry.ended_at),
                    format_optional_timestamp(entry.expires_at),
                    entry.allow,
                    entry.deny,
                    entry.allow_exact,
                    entry.deny_exact,
                    format_prompt(entry.prompt_append.as_deref(), true),
                    entry.generated_notes,
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
                let color = color_enabled_for_stdout();
                for interaction in &report.recent {
                    let exec = match interaction.exec_status {
                        session::SessionExecStatus::NotAttempted => "not_attempted",
                        session::SessionExecStatus::Completed => "completed",
                        session::SessionExecStatus::Failed => "failed",
                        session::SessionExecStatus::DryRun => "dry_run",
                        session::SessionExecStatus::Held => "held",
                        session::SessionExecStatus::Provisional => "provisional",
                    };
                    let allowed = if interaction.allowed {
                        paint("true", AnsiColor::Green, color)
                    } else {
                        paint("false", AnsiColor::Red, color)
                    };
                    println!(
                        "recent at={} allowed={} source={:?} risk={} exec={} cmd={:?} reason={:?}",
                        format_timestamp(interaction.at_unix),
                        allowed,
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
        | server::AdminResponse::SecretListDetailed { .. }
        | server::AdminResponse::GateAction { .. }
        | server::AdminResponse::Provisionals { .. }
        | server::AdminResponse::Approvals { .. }
        | server::AdminResponse::ApprovalShow { .. }
        | server::AdminResponse::Verbs { .. }
        | server::AdminResponse::VerbCreated { .. } => {
            // session subcommands never request these response variants.
            eprintln!("unexpected response from session admin call");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn truncate_prompt(prompt: &mut Option<String>) {
    let Some(value) = prompt else {
        return;
    };
    if value.chars().count() > 60 {
        *value = format!("{}...", value.chars().take(60).collect::<String>());
    }
}

pub(crate) async fn handle_config(subcommand: ConfigCommands) -> Result<()> {
    // Surface load errors loudly for every subcommand - this catches the
    // relative-XDG_CONFIG_HOME case that can otherwise fall through silently
    // and risked writing to the default path instead of the intended one.
    match subcommand {
        ConfigCommands::Show { json } => {
            let config =
                client_config::ClientConfig::load().context("failed to load client config")?;
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
            let mut config =
                client_config::ClientConfig::load().context("failed to load client config")?;
            let socket = normalize_server_socket_value(socket);
            config.server_socket = Some(socket.clone());
            config.server_tcp_port = None;
            config.save()?;
            println!("Server socket set to {}", socket);
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
            coverage: None,
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

    #[test]
    fn json_session_list_prompt_truncation_matches_human_default() {
        let mut prompt = Some("x".repeat(61));
        truncate_prompt(&mut prompt);
        assert_eq!(prompt, Some(format!("{}...", "x".repeat(60))));

        let mut short = Some("short".to_string());
        truncate_prompt(&mut short);
        assert_eq!(short.as_deref(), Some("short"));
    }
}
