use crate::daemon_client;
use crate::injection::{collect_unique_pairs, derive_env_name};
use crate::server;
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{header, HeaderMap, Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

const JSONRPC_VERSION: &str = "2.0";
const DEFAULT_TOOL_NAME: &str = "guard_run";
const VERB_LIST_TOOL_NAME: &str = "guard_verbs";
const ACCESS_REQUEST_TOOL_NAME: &str = "guard_access_request";
const APPROVAL_LIST_TOOL_NAME: &str = "guard_access_list";
const EVALUATE_BATCH_TOOL_NAME: &str = "guard_evaluate_batch";
const ACCESS_SHOW_TOOL_NAME: &str = "guard_access_show";
const ACCESS_STATUS_TOOL_NAME: &str = "guard_access_status";
const APPROVAL_SHOW_TOOL_NAME: &str = "guard_approval_show";
const APPROVAL_RESUME_TOOL_NAME: &str = "guard_approval_resume";
const BUILT_IN_TOOL_NAMES: &[&str] = &[
    DEFAULT_TOOL_NAME,
    VERB_LIST_TOOL_NAME,
    ACCESS_REQUEST_TOOL_NAME,
    APPROVAL_LIST_TOOL_NAME,
    EVALUATE_BATCH_TOOL_NAME,
    ACCESS_SHOW_TOOL_NAME,
    ACCESS_STATUS_TOOL_NAME,
    APPROVAL_SHOW_TOOL_NAME,
    APPROVAL_RESUME_TOOL_NAME,
];
const TOOL_SCHEMA_VERSION: u64 = 1;
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-03-26", "2024-11-05"];

/// Cap the HTTP request body we will buffer. The MCP request payloads are
/// small JSON-RPC envelopes; this bounds the memory a single connection can
/// force us to allocate from an unauthenticated peer before the bearer check.
const MAX_HTTP_BODY: usize = 1024 * 1024;
const MAX_HTTP_SESSIONS: usize = 1024;
const MAX_MCP_REQUEST_IDS: usize = 16 * 1024;
const HTTP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MCP_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
pub struct McpConfig {
    pub socket_path: Option<PathBuf>,
    pub tcp_port: Option<u16>,
    pub auth_token: Option<String>,
    /// Session bearer owned by this MCP process, sourced from GUARD_SESSION.
    pub session_token: Option<String>,
    pub tool_name: String,
    /// When set, serve MCP over HTTP on this address instead of stdio.
    pub http_addr: Option<SocketAddr>,
    /// Bearer token required on every HTTP request. Mandatory whenever
    /// `http_addr` is set; there is no unauthenticated network transport.
    pub http_token: Option<String>,
}

impl McpConfig {
    pub fn validate(&self) -> Result<()> {
        if self.socket_path.is_none() && self.tcp_port.is_none() {
            bail!("no guard server configured for MCP (set a socket or TCP port)");
        }

        if self.socket_path.is_some() && self.tcp_port.is_some() {
            bail!("configure exactly one MCP daemon endpoint (socket or TCP port)");
        }

        if self
            .socket_path
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            bail!("MCP socket path cannot be empty");
        }

        if self.tcp_port == Some(0) {
            bail!("MCP TCP port must be non-zero");
        }

        if self.tool_name.trim().is_empty() {
            bail!("MCP tool name cannot be empty");
        }

        if self.tool_name != DEFAULT_TOOL_NAME
            && BUILT_IN_TOOL_NAMES.contains(&self.tool_name.as_str())
        {
            bail!(
                "MCP tool name '{}' is reserved by a built-in tool",
                self.tool_name
            );
        }

        if self.http_addr.is_some()
            && self
                .http_token
                .as_deref()
                .map(str::trim)
                .map(str::is_empty)
                .unwrap_or(true)
        {
            bail!(
                "--http requires a bearer token from GUARD_MCP_TOKEN; \
                 refusing to start an unauthenticated network MCP server"
            );
        }

        if self
            .http_addr
            .is_some_and(|address| !address.ip().is_loopback())
        {
            bail!("--http must bind to a loopback address");
        }

        Ok(())
    }
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            socket_path: None,
            tcp_port: None,
            auth_token: None,
            session_token: None,
            tool_name: DEFAULT_TOOL_NAME.to_string(),
            http_addr: None,
            http_token: None,
        }
    }
}

// The untrusted MCP request shapes (JSON-RPC envelope and typed tool
// arguments) live in the library crate (`guard::wire::mcp`) so their parsing
// surface can be fuzzed.
use guard::wire::mcp::{
    parse_jsonrpc_envelope, AccessShowArgs, ApprovalArgs, EvaluateBatchArgs, GuardToolArgs,
    JsonRpcEnvelopeError, ToolCallParams, WaitApproval,
};

#[derive(Debug, Clone)]
struct GuardToolResponse {
    allowed: bool,
    reason: String,
    exit_code: Option<i32>,
    stdout: Option<String>,
    stderr: Option<String>,
    /// Consequence-gate outcome: "executed", "held", "provisional", etc.
    status: Option<String>,
    /// Handle for a held/provisional command.
    handle: Option<String>,
    confirm_deadline_unix: Option<u64>,
    confirm_window_secs: Option<u64>,
    auto_revert_durable: Option<bool>,
    containment_failure: Option<server::ContainmentFailure>,
    approval_options: Vec<String>,
    access_requests: Vec<server::AccessRequestGuidance>,
    /// Honest statement of what the gate checked and did not check.
    coverage: Option<guard::gating::Coverage>,
    verb_matches: Vec<server::VerbMatchInfo>,
    guidance: Option<String>,
    decision_source: String,
}

#[derive(Debug, Deserialize)]
struct AccessRequestArgs {
    intent: String,
}

impl From<server::ExecuteResponse> for GuardToolResponse {
    fn from(response: server::ExecuteResponse) -> Self {
        Self {
            allowed: response.allowed,
            reason: response.reason,
            exit_code: response.exit_code,
            stdout: response.stdout,
            stderr: response.stderr,
            coverage: response.coverage.clone(),
            status: response.status.map(|s| {
                match s {
                    server::GateStatus::Executed => "executed",
                    server::GateStatus::Provisional => "provisional",
                    server::GateStatus::Held => "held",
                    server::GateStatus::Reverted => "reverted",
                    server::GateStatus::DryRun => "dry_run",
                }
                .to_string()
            }),
            handle: response.handle,
            confirm_deadline_unix: response.confirm_deadline_unix,
            confirm_window_secs: response.confirm_window_secs,
            auto_revert_durable: response.auto_revert_durable,
            containment_failure: response.containment_failure,
            approval_options: response.approval_options,
            access_requests: response.access_requests,
            verb_matches: response.verb_matches,
            guidance: response.verb_guidance,
            decision_source: response.decision_source,
        }
    }
}

#[async_trait]
trait GuardExecutor: Send + Sync {
    async fn execute(&self, args: GuardToolArgs) -> Result<GuardToolResponse>;
}

/// Read-only proxy for the daemon's admin RPCs that the catalog/approval MCP
/// tools surface. These map one-to-one onto existing `AdminRequest` variants;
/// they self-scope inside the daemon by caller uid/handle ownership and never
/// bypass the gate (no command runs through this path).
#[async_trait]
trait GuardAdmin: Send + Sync {
    async fn send_admin(&self, request: server::AdminRequest) -> Result<server::AdminResponse>;
}

#[derive(Clone)]
struct ClientExecutor {
    socket_path: Option<PathBuf>,
    tcp_port: Option<u16>,
    auth_token: Option<String>,
    session_token: Option<String>,
}

impl ClientExecutor {
    /// Build a daemon client without operator authority. On a local socket the
    /// kernel-authenticated MCP process principal scopes self-service reads. A
    /// TCP endpoint refuses these RPCs instead of silently upgrading every MCP
    /// bearer holder to the configured daemon administrator.
    fn admin_client(&self) -> daemon_client::Client {
        let mut client = daemon_client::Client::new(self.socket_path.clone(), self.tcp_port);
        if let Some(token) = &self.auth_token {
            client = client.with_auth(token.clone());
        }
        client
    }
}

#[async_trait]
impl GuardAdmin for ClientExecutor {
    async fn send_admin(&self, request: server::AdminRequest) -> Result<server::AdminResponse> {
        self.admin_client()
            .send_admin(request)
            .await
            .context("failed to query guard daemon")
    }
}

#[async_trait]
impl GuardExecutor for ClientExecutor {
    async fn execute(&self, args: GuardToolArgs) -> Result<GuardToolResponse> {
        if args.verb.is_none() && args.binary.trim().is_empty() {
            bail!("either `binary` or `verb` is required");
        }
        let env = collect_unique_pairs(args.env, "environment variable injection", "value")
            .map_err(anyhow::Error::msg)?;
        let secrets = guard_tool_secret_map(&args.secrets, args.secret_env)?;

        let mut revert = match args.revert.as_deref() {
            Some(spec) => {
                let parts = shell_words::split(spec)
                    .map_err(|e| anyhow::anyhow!("invalid revert command: {}", e))?;
                let mut it = parts.into_iter();
                let binary = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("revert command is empty"))?;
                Some(server::RevertSpec::new(binary, it.collect()))
            }
            None => None,
        };
        if let Some(check) = args.confirm_check.as_deref() {
            let parts = shell_words::split(check)
                .map_err(|e| anyhow::anyhow!("invalid confirm-check command: {}", e))?;
            let mut it = parts.into_iter();
            let binary = it
                .next()
                .ok_or_else(|| anyhow::anyhow!("confirm-check command is empty"))?;
            let Some(revert) = revert.as_mut() else {
                anyhow::bail!("confirmCheck requires revert");
            };
            revert.confirm_check = Some(server::CommandSpec {
                binary,
                args: it.collect(),
            });
        }
        if let Some(control_path) = args.revert_control_path {
            let Some(revert) = revert.as_mut() else {
                anyhow::bail!("revertControlPath requires revert");
            };
            revert.control_path = Some(control_path);
        }

        let mut client = daemon_client::Client::new(self.socket_path.clone(), self.tcp_port)
            .with_gating(
                revert,
                args.confirm_within,
                args.require_approval,
                args.wait_approval.and_then(WaitApproval::into_secs),
            )
            .with_reevaluate(args.reevaluate);
        if let Some(mode) = args.hostkey {
            client = client.with_hostkey(mode.into());
        }
        if let Some(token) = &self.auth_token {
            client = client.with_auth(token.clone());
        }
        if let Some(token) = &self.session_token {
            client = client.with_session(token.clone());
        }
        if let Some(verb) = args.verb {
            client = client.with_verb(server::VerbInvocation {
                name: verb.name,
                params: verb.params,
            });
        }

        let response = client
            .execute_with_injections(&args.binary, &args.args, env, secrets, args.secret_files)
            .await
            .context("failed to execute command through guard server")?;

        Ok(response.into())
    }
}

fn guard_tool_secret_map(
    bare_secrets: &[String],
    explicit_secret_env: HashMap<String, String>,
) -> Result<HashMap<String, String>> {
    let mut pairs = Vec::with_capacity(bare_secrets.len() + explicit_secret_env.len());
    for secret_name in bare_secrets {
        let env_name = derive_env_name(secret_name).map_err(anyhow::Error::msg)?;
        pairs.push((env_name, secret_name.clone()));
    }
    pairs.extend(explicit_secret_env);
    collect_unique_pairs(pairs, "secret injection", "secret").map_err(anyhow::Error::msg)
}

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

pub async fn serve(config: McpConfig) -> Result<()> {
    config.validate()?;

    let executor = Arc::new(ClientExecutor {
        socket_path: config.socket_path.clone(),
        tcp_port: config.tcp_port,
        auth_token: config.auth_token.clone(),
        session_token: config.session_token.clone(),
    });
    let surface = probe_mcp_surface(&executor, &config).await;
    let server = McpServer::new(executor.clone(), executor, config.tool_name)
        .with_caller_token(config.session_token)
        .with_endpoint_available(surface.endpoint_available)
        .with_admin_tools(surface.admin_tools)
        .with_execute_admin_tools(surface.execute_admin_tools)
        .with_approval_consequence_tools(surface.approval_consequence_tools)
        .with_http_transport(config.http_addr.is_some())
        .with_tcp_backend(config.tcp_port.is_some())
        .with_diagnostics(surface.diagnostics);

    match config.http_addr {
        Some(addr) => {
            let token = config
                .http_token
                .clone()
                .expect("validate() guarantees a token when http_addr is set");
            serve_http(server, addr, token).await
        }
        None => serve_stdio(server).await,
    }
}

const APPROVAL_CONSEQUENCES_CAPABILITY: &str = "approval-consequences-v1";

#[derive(Clone)]
struct McpSurface {
    endpoint_available: bool,
    admin_tools: bool,
    execute_admin_tools: bool,
    approval_consequence_tools: bool,
    diagnostics: McpDiagnostics,
}

#[derive(Clone)]
struct McpDiagnostics {
    capability_membership: &'static str,
    capability_state: &'static str,
    detected_version: Option<String>,
    detected_capabilities: Vec<String>,
    endpoint_state: &'static str,
    endpoint_reason: &'static str,
    admin_state: &'static str,
    admin_reason: &'static str,
}

impl McpDiagnostics {
    fn record(&self) {
        tracing::debug!(
            capability_membership = self.capability_membership,
            capability_state = self.capability_state,
            detected_version = self.detected_version.as_deref().unwrap_or("null"),
            detected_capabilities = ?self.detected_capabilities,
            endpoint_state = self.endpoint_state,
            endpoint_reason = self.endpoint_reason,
            admin_state = self.admin_state,
            admin_reason = self.admin_reason,
            "cached MCP daemon probe"
        );
    }
}

async fn probe_mcp_surface<A: GuardAdmin>(executor: &A, config: &McpConfig) -> McpSurface {
    let ping = tokio::time::timeout(
        MCP_PROBE_TIMEOUT,
        executor.send_admin(server::AdminRequest::Ping),
    )
    .await;
    let ping_valid = matches!(&ping, Ok(Ok(server::AdminResponse::Ping { .. })));
    let (capability, mut diagnostics) = match ping {
        Ok(Ok(server::AdminResponse::Ping {
            version,
            capabilities,
            ..
        })) => {
            let capability = capabilities
                .iter()
                .any(|value| value == APPROVAL_CONSEQUENCES_CAPABILITY);
            (
                capability,
                McpDiagnostics {
                    capability_membership: if capability { "member" } else { "absent" },
                    capability_state: if capability {
                        "capable"
                    } else {
                        "capability_absent"
                    },
                    detected_version: Some(version),
                    detected_capabilities: capabilities,
                    endpoint_state: "reachable",
                    endpoint_reason: "endpoint_reachable",
                    admin_state: "unsupported_tcp",
                    admin_reason: "tcp_mcp_admin_unsupported",
                },
            )
        }
        Ok(Ok(_)) => (
            false,
            McpDiagnostics {
                capability_membership: "unknown",
                capability_state: "ping_malformed",
                detected_version: Some("unknown".to_string()),
                detected_capabilities: Vec::new(),
                endpoint_state: "reachable",
                endpoint_reason: "endpoint_reachable",
                admin_state: "endpoint_unavailable",
                admin_reason: "endpoint_unavailable",
            },
        ),
        Ok(Err(_)) => (
            false,
            McpDiagnostics {
                capability_membership: "unknown",
                capability_state: "ping_unavailable",
                detected_version: None,
                detected_capabilities: Vec::new(),
                endpoint_state: "unavailable",
                endpoint_reason: "sole_endpoint_unavailable",
                admin_state: "endpoint_unavailable",
                admin_reason: "endpoint_unavailable",
            },
        ),
        Err(_) => (
            false,
            McpDiagnostics {
                capability_membership: "unknown",
                capability_state: "ping_unavailable",
                detected_version: None,
                detected_capabilities: Vec::new(),
                endpoint_state: "unavailable",
                endpoint_reason: "sole_endpoint_unavailable",
                admin_state: "endpoint_unavailable",
                admin_reason: "endpoint_unavailable",
            },
        ),
    };

    if !ping_valid {
        diagnostics.record();
        return McpSurface {
            endpoint_available: false,
            admin_tools: false,
            execute_admin_tools: false,
            approval_consequence_tools: false,
            diagnostics,
        };
    }

    if config.tcp_port.is_some() {
        diagnostics.record();
        return McpSurface {
            endpoint_available: true,
            admin_tools: false,
            execute_admin_tools: false,
            approval_consequence_tools: false,
            diagnostics,
        };
    }

    let admin_probe = tokio::time::timeout(
        MCP_PROBE_TIMEOUT,
        executor.send_admin(server::AdminRequest::AccessList),
    )
    .await;
    let admin_tools = matches!(
        admin_probe,
        Ok(Ok(server::AdminResponse::AccessItems { .. }))
    );

    diagnostics.admin_state = if admin_tools {
        "reachable"
    } else {
        "endpoint_unavailable"
    };
    diagnostics.admin_reason = if admin_tools {
        "unix_admin_handshake"
    } else {
        "unix_admin_probe_failed"
    };
    diagnostics.record();

    McpSurface {
        // A failed Unix self-scoped probe produces an empty surface even when
        // the preceding Ping reached the socket. Keep the endpoint and admin
        // failure indistinguishable to callers, as required by the MCP
        // contract.
        endpoint_available: admin_tools,
        admin_tools,
        // Resuming a hold executes an operator-approved snapshot. The daemon
        // authenticates this MCP process's peer credentials, not the HTTP
        // caller's bearer, so this remains stdio-only.
        execute_admin_tools: admin_tools && config.http_addr.is_none() && capability,
        approval_consequence_tools: admin_tools && capability,
        diagnostics,
    }
}

async fn serve_stdio<E: GuardExecutor, A: GuardAdmin>(mut server: McpServer<E, A>) -> Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let mut lines = BufReader::new(stdin).lines();
    let mut writer = BufWriter::new(stdout);

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Value>(&line) {
            Ok(message) => server.handle_message(message).await,
            Err(error) => Some(jsonrpc_error_response(
                Value::Null,
                -32700,
                format!("parse error: {error}"),
                None,
            )),
        };

        if let Some(response) = response {
            let payload = serde_json::to_string(&response)?;
            writer.write_all(payload.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
        }
    }

    Ok(())
}

/// Cap on the buffered read/write buffer hyper keeps per HTTP/1 connection,
/// which also bounds the request head (request line + headers). Combined with
/// the body cap, this bounds the total bytes an unauthenticated peer can make
/// the server buffer for one request.
const MAX_HTTP_HEADER_SECTION: usize = 64 * 1024;

/// Bound the time spent reading one request (headers via hyper's header read
/// timeout, body via an explicit timeout around the capped body read) so a
/// stalled (slowloris-style) connection cannot hold a task open indefinitely
/// before the bearer check.
const HTTP_REQUEST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Minimal MCP Streamable HTTP transport: a single endpoint that pipes the
/// JSON-RPC body through the same request handler the stdio path uses. Every
/// request must carry `Authorization: Bearer <token>`; there is no server-side
/// SSE streaming. Initialize creates an opaque MCP session so lifecycle state
/// survives connection reuse, reconnects, and HTTP/2 connection sharing.
async fn serve_http<E: GuardExecutor + 'static, A: GuardAdmin + 'static>(
    server: McpServer<E, A>,
    addr: SocketAddr,
    token: String,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind MCP HTTP listener on {addr}"))?;
    let bound = listener.local_addr().unwrap_or(addr);

    if !bound.ip().is_loopback() {
        bail!("MCP HTTP transport must bind to a loopback address, got {bound}");
    }
    tracing::info!(address = %bound, "MCP HTTP transport listening");

    serve_http_on(listener, server, token).await
}

struct HttpSession<E: GuardExecutor, A: GuardAdmin> {
    connection: Arc<Mutex<McpServer<E, A>>>,
    expires_at: Instant,
}

type HttpSessionTable<E, A> = HashMap<String, HttpSession<E, A>>;

fn prune_expired_http_sessions<E: GuardExecutor, A: GuardAdmin>(
    sessions: &mut HttpSessionTable<E, A>,
    now: Instant,
) {
    sessions.retain(|_, session| session.expires_at > now);
}

/// Accept loop over an already-bound listener: each connection is served by
/// hyper (keep-alive, chunked transfer encoding, and HTTP/2 over prior
/// knowledge come from the shared `auto` connection builder the api-proxy also
/// uses).
async fn serve_http_on<E: GuardExecutor + 'static, A: GuardAdmin + 'static>(
    listener: TcpListener,
    server: McpServer<E, A>,
    token: String,
) -> Result<()> {
    let server = Arc::new(server);
    let token = Arc::new(token);
    let sessions: Arc<Mutex<HttpSessionTable<E, A>>> = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(error = %error, "MCP HTTP accept failed");
                continue;
            }
        };
        let server = server.clone();
        let token = token.clone();
        let sessions = sessions.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let server = server.clone();
                let token = token.clone();
                let sessions = sessions.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(
                        handle_http_request(request, &server, &sessions, &token).await,
                    )
                }
            });
            let mut builder = auto::Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(HTTP_REQUEST_READ_TIMEOUT)
                .max_buf_size(MAX_HTTP_HEADER_SECTION);
            if let Err(error) = builder
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                tracing::debug!(error = %error, "MCP HTTP connection ended with error");
            }
        });
    }
}

/// Serve one HTTP request. Auth is enforced before the body is read; the body
/// read is bounded in both size (`MAX_HTTP_BODY`, which covers chunked bodies
/// with no Content-Length) and time.
async fn handle_http_request<E: GuardExecutor, A: GuardAdmin>(
    request: Request<Incoming>,
    server: &McpServer<E, A>,
    sessions: &Mutex<HttpSessionTable<E, A>>,
    token: &str,
) -> Response<Full<Bytes>> {
    if !origin_is_loopback(request.headers()) {
        return http_error_response(StatusCode::FORBIDDEN, "invalid Origin header");
    }

    // Reject a declared oversized body up front, before any other check, so
    // the bound applies even to unauthenticated peers.
    let declared_length = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok());
    if declared_length.is_some_and(|length| length > MAX_HTTP_BODY as u64) {
        return http_error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
    }

    if !path_is_mcp_endpoint(request.uri().path()) {
        return http_error_response(StatusCode::NOT_FOUND, "not found");
    }

    if !bearer_matches(request.headers(), token) {
        return http_error_response(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
    }

    if request.method() == Method::DELETE {
        let Some(session_id) = request
            .headers()
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok())
            .filter(|value| valid_mcp_session_id(value))
        else {
            return http_error_response(
                StatusCode::BAD_REQUEST,
                "missing or invalid Mcp-Session-Id",
            );
        };
        let mut session_table = sessions.lock().await;
        prune_expired_http_sessions(&mut session_table, Instant::now());
        if session_table.remove(session_id).is_none() {
            return http_error_response(StatusCode::NOT_FOUND, "unknown MCP session");
        }
        return empty_response(StatusCode::NO_CONTENT);
    }

    if request.method() != Method::POST {
        return http_error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed; POST a JSON-RPC request",
        );
    }

    if !accepts_mcp_response_types(request.headers()) {
        return http_error_response(
            StatusCode::NOT_ACCEPTABLE,
            "Accept must list application/json and text/event-stream",
        );
    }

    if !mcp_protocol_version_is_supported(request.headers()) {
        return http_error_response(StatusCode::BAD_REQUEST, "unsupported MCP-Protocol-Version");
    }

    let presented_session = request
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    let body = match tokio::time::timeout(
        HTTP_REQUEST_READ_TIMEOUT,
        Limited::new(request.into_body(), MAX_HTTP_BODY).collect(),
    )
    .await
    {
        Ok(Ok(collected)) => collected.to_bytes(),
        Ok(Err(error)) if error.is::<http_body_util::LengthLimitError>() => {
            return http_error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
        }
        Ok(Err(_)) => {
            return http_error_response(StatusCode::BAD_REQUEST, "failed to read request body");
        }
        Err(_) => {
            return http_error_response(StatusCode::REQUEST_TIMEOUT, "request timeout");
        }
    };

    let message: Value = match serde_json::from_slice(&body) {
        Ok(message) => message,
        Err(error) => {
            let payload =
                jsonrpc_error_response(Value::Null, -32700, format!("parse error: {error}"), None);
            return json_response(StatusCode::BAD_REQUEST, &payload);
        }
    };

    let parsed_envelope = match parse_jsonrpc_envelope(&message) {
        Ok(envelope) => envelope,
        Err(_) => {
            let mut connection = server.fresh_connection();
            let response = connection.handle_message(message).await;
            return response
                .map(|response| json_response(StatusCode::OK, &response))
                .unwrap_or_else(|| empty_response(StatusCode::ACCEPTED));
        }
    };
    let is_initialize = parsed_envelope.method == "initialize";

    let (response, response_session) = if is_initialize {
        if presented_session.is_some() {
            return http_error_response(
                StatusCode::BAD_REQUEST,
                "initialize must not carry Mcp-Session-Id",
            );
        }
        if parsed_envelope.id.is_none() {
            return http_error_response(
                StatusCode::BAD_REQUEST,
                "initialize must be a JSON-RPC request with a non-null id",
            );
        }

        let mut connection = server.fresh_connection();
        let response = connection.handle_message(message).await;
        let initialized = connection.initialize_seen
            && response
                .as_ref()
                .is_some_and(|response| response["result"].is_object());
        if !initialized {
            return response
                .map(|response| json_response(StatusCode::OK, &response))
                .unwrap_or_else(|| empty_response(StatusCode::ACCEPTED));
        }

        let mut session_table = sessions.lock().await;
        let now = Instant::now();
        prune_expired_http_sessions(&mut session_table, now);
        if session_table.len() >= MAX_HTTP_SESSIONS {
            return http_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "MCP session capacity reached",
            );
        }
        let session_id = loop {
            let candidate = new_mcp_session_id();
            if !session_table.contains_key(&candidate) {
                break candidate;
            }
        };
        session_table.insert(
            session_id.clone(),
            HttpSession {
                connection: Arc::new(Mutex::new(connection)),
                expires_at: now + HTTP_SESSION_IDLE_TIMEOUT,
            },
        );
        (response, Some(session_id))
    } else {
        let Some(session_id) = presented_session.filter(|value| valid_mcp_session_id(value)) else {
            return http_error_response(
                StatusCode::BAD_REQUEST,
                "missing or invalid Mcp-Session-Id",
            );
        };
        let connection = {
            let mut session_table = sessions.lock().await;
            let now = Instant::now();
            prune_expired_http_sessions(&mut session_table, now);
            let Some(session) = session_table.get_mut(&session_id) else {
                return http_error_response(StatusCode::NOT_FOUND, "unknown MCP session");
            };
            session.expires_at = now + HTTP_SESSION_IDLE_TIMEOUT;
            session.connection.clone()
        };
        let response = connection.lock().await.handle_message(message).await;
        (response, Some(session_id))
    };

    // A JSON-RPC notification (no id) produces no response value. The MCP
    // Streamable-HTTP shape answers such a POST with 202 Accepted and no body.
    match response {
        Some(response) => {
            json_response_with_session(StatusCode::OK, &response, response_session.as_deref())
        }
        None => empty_response(StatusCode::ACCEPTED),
    }
}

fn new_mcp_session_id() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn valid_mcp_session_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn path_is_mcp_endpoint(path: &str) -> bool {
    path == "/" || path == "/mcp"
}

fn origin_is_loopback(headers: &HeaderMap) -> bool {
    let mut origins = headers.get_all(header::ORIGIN).iter();
    let Some(origin) = origins.next() else {
        return true;
    };
    if origins.next().is_some() {
        return false;
    }
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    let Ok(uri) = origin.parse::<hyper::Uri>() else {
        return false;
    };
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || uri.path() != "/"
        || uri.query().is_some()
    {
        return false;
    }
    let Some(authority) = uri.authority() else {
        return false;
    };
    if authority.as_str().contains('@') {
        return false;
    }
    let host = authority.host();
    host.eq_ignore_ascii_case("localhost")
        || host == "[::1]"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn accepts_mcp_response_types(headers: &HeaderMap) -> bool {
    let accepted = headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| value.split(';').next())
        .map(str::trim)
        .collect::<Vec<_>>();
    accepted.contains(&"application/json") && accepted.contains(&"text/event-stream")
}

fn mcp_protocol_version_is_supported(headers: &HeaderMap) -> bool {
    let mut versions = headers.get_all("mcp-protocol-version").iter();
    let Some(version) = versions.next() else {
        // MCP defines 2025-03-26 as the compatibility default when no header
        // or other negotiated-version signal is available.
        return true;
    };
    if versions.next().is_some() {
        return false;
    }
    version
        .to_str()
        .is_ok_and(|version| SUPPORTED_PROTOCOL_VERSIONS.contains(&version))
}

/// Bearer comparison via the shared constant-time helper: reject on length
/// mismatch, then compare every byte without early exit so the check does not
/// leak a prefix match through timing.
fn bearer_matches(headers: &HeaderMap, expected: &str) -> bool {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Some(presented) = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
    else {
        return false;
    };
    crate::server::constant_time_eq(presented.as_bytes(), expected.as_bytes())
}

fn error_body(message: &str) -> Value {
    json!({ "error": message })
}

fn json_response(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    json_response_with_session(status, body, None)
}

fn json_response_with_session(
    status: StatusCode,
    body: &Value,
    session_id: Option<&str>,
) -> Response<Full<Bytes>> {
    let payload = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(session_id) = session_id {
        builder = builder.header("mcp-session-id", session_id);
    }
    builder
        .body(Full::new(Bytes::from(payload)))
        .expect("static response parts are valid")
}

fn http_error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    json_response(status, &error_body(message))
}

/// A response with no body (used for 202 Accepted on a JSON-RPC notification).
fn empty_response(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .expect("static response parts are valid")
}

struct McpServer<E: GuardExecutor, A: GuardAdmin> {
    executor: Arc<E>,
    admin: Arc<A>,
    tool_name: String,
    admin_tools: bool,
    execute_admin_tools: bool,
    approval_consequence_tools: bool,
    endpoint_available: bool,
    http_transport: bool,
    tcp_backend: bool,
    diagnostics: McpDiagnostics,
    initialize_seen: bool,
    seen_request_ids: HashSet<String>,
    caller_token: Option<String>,
}

impl<E: GuardExecutor, A: GuardAdmin> McpServer<E, A> {
    fn new(executor: Arc<E>, admin: Arc<A>, tool_name: String) -> Self {
        Self {
            executor,
            admin,
            tool_name,
            admin_tools: true,
            execute_admin_tools: true,
            approval_consequence_tools: true,
            endpoint_available: true,
            http_transport: false,
            tcp_backend: false,
            diagnostics: McpDiagnostics {
                capability_membership: "member",
                capability_state: "capable",
                detected_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                detected_capabilities: vec![APPROVAL_CONSEQUENCES_CAPABILITY.to_string()],
                endpoint_state: "reachable",
                endpoint_reason: "endpoint_reachable",
                admin_state: "reachable",
                admin_reason: "unix_admin_handshake",
            },
            initialize_seen: false,
            seen_request_ids: HashSet::new(),
            caller_token: None,
        }
    }

    fn with_caller_token(mut self, caller_token: Option<String>) -> Self {
        self.caller_token = caller_token.filter(|token| !token.is_empty());
        self
    }

    fn with_admin_tools(mut self, admin_tools: bool) -> Self {
        self.admin_tools = admin_tools;
        self
    }

    fn with_execute_admin_tools(mut self, execute_admin_tools: bool) -> Self {
        self.execute_admin_tools = execute_admin_tools;
        self
    }

    fn with_approval_consequence_tools(mut self, enabled: bool) -> Self {
        self.approval_consequence_tools = enabled;
        self
    }

    fn with_endpoint_available(mut self, available: bool) -> Self {
        self.endpoint_available = available;
        self
    }

    fn with_http_transport(mut self, http_transport: bool) -> Self {
        self.http_transport = http_transport;
        self
    }

    fn with_tcp_backend(mut self, tcp_backend: bool) -> Self {
        self.tcp_backend = tcp_backend;
        self
    }

    fn with_diagnostics(mut self, diagnostics: McpDiagnostics) -> Self {
        self.diagnostics = diagnostics;
        self
    }

    fn fresh_connection(&self) -> Self {
        Self {
            executor: self.executor.clone(),
            admin: self.admin.clone(),
            tool_name: self.tool_name.clone(),
            admin_tools: self.admin_tools,
            execute_admin_tools: self.execute_admin_tools,
            approval_consequence_tools: self.approval_consequence_tools,
            endpoint_available: self.endpoint_available,
            http_transport: self.http_transport,
            tcp_backend: self.tcp_backend,
            diagnostics: self.diagnostics.clone(),
            initialize_seen: false,
            seen_request_ids: HashSet::new(),
            caller_token: self.caller_token.clone(),
        }
    }

    async fn handle_message(&mut self, message: Value) -> Option<Value> {
        let envelope = match parse_jsonrpc_envelope(&message) {
            Ok(envelope) => envelope,
            Err(JsonRpcEnvelopeError::NotAnObject) => {
                return Some(jsonrpc_error_response(
                    Value::Null,
                    -32600,
                    "invalid request: JSON-RPC message must be an object".to_string(),
                    None,
                ));
            }
            Err(JsonRpcEnvelopeError::Invalid { id, message }) => {
                return Some(jsonrpc_error_response(
                    id.unwrap_or(Value::Null),
                    -32600,
                    format!("invalid request: {message}"),
                    None,
                ));
            }
        };

        if let Some(id) = envelope.id {
            if self.seen_request_ids.len() >= MAX_MCP_REQUEST_IDS {
                return Some(jsonrpc_error_response(
                    id,
                    -32600,
                    "invalid request: MCP session request limit reached".to_string(),
                    None,
                ));
            }
            let request_id_key = serde_json::to_string(&id).expect("validated JSON-RPC id");
            if !self.seen_request_ids.insert(request_id_key) {
                return Some(jsonrpc_error_response(
                    id,
                    -32600,
                    "invalid request: id was already used in this session".to_string(),
                    None,
                ));
            }
            return self
                .handle_request(id, &envelope.method, envelope.params)
                .await;
        }

        self.handle_notification(&envelope.method, envelope.params);
        None
    }

    async fn handle_request(&mut self, id: Value, method: &str, params: Value) -> Option<Value> {
        let response = match method {
            "initialize" => {
                if self.initialize_seen {
                    return Some(jsonrpc_error_response(
                        id,
                        -32600,
                        "invalid request: initialize was already completed".to_string(),
                        None,
                    ));
                }
                if let Err(error) = validate_initialize_params(&params) {
                    return Some(jsonrpc_error_response(id, -32602, error.to_string(), None));
                }
                self.initialize_seen = true;
                jsonrpc_result_response(id, self.initialize_result(&params))
            }
            "ping" => jsonrpc_result_response(id, json!({})),
            "tools/list" => {
                if let Err(error) = ensure_initialized(self.initialize_seen, method) {
                    return Some(jsonrpc_error_response(id, -32600, error.to_string(), None));
                }
                jsonrpc_result_response(id, self.list_tools_result())
            }
            "tools/call" => {
                if let Err(error) = ensure_initialized(self.initialize_seen, method) {
                    return Some(jsonrpc_error_response(id, -32600, error.to_string(), None));
                }
                let tool_call = match parse_tool_call(params) {
                    Ok(tool_call) => tool_call,
                    Err(error) => {
                        return Some(jsonrpc_error_response(
                            id,
                            -32602,
                            format!("{error:#}"),
                            None,
                        ));
                    }
                };
                if self.endpoint_available && tool_call.name == self.tool_name {
                    let result = self.call_tool(tool_call.arguments).await;
                    jsonrpc_result_response(id, result)
                } else if self.admin_tools && tool_call.name == VERB_LIST_TOOL_NAME {
                    let result = self.call_verb_list().await;
                    jsonrpc_result_response(id, result)
                } else if self.admin_tools && tool_call.name == ACCESS_REQUEST_TOOL_NAME {
                    let result = self.call_access_request(tool_call.arguments).await;
                    jsonrpc_result_response(id, result)
                } else if self.admin_tools && tool_call.name == APPROVAL_LIST_TOOL_NAME {
                    let result = self.call_approval_list().await;
                    jsonrpc_result_response(id, result)
                } else if self.admin_tools && tool_call.name == EVALUATE_BATCH_TOOL_NAME {
                    let result = self.call_evaluate_batch(tool_call.arguments).await;
                    jsonrpc_result_response(id, result)
                } else if self.admin_tools && tool_call.name == ACCESS_SHOW_TOOL_NAME {
                    let result = self.call_access_show(tool_call.arguments).await;
                    jsonrpc_result_response(id, result)
                } else if self.admin_tools
                    && !self.http_transport
                    && tool_call.name == ACCESS_STATUS_TOOL_NAME
                {
                    let result = self.call_session_status(tool_call.arguments).await;
                    jsonrpc_result_response(id, result)
                } else if self.admin_tools
                    && self.approval_consequence_tools
                    && !self.http_transport
                    && tool_call.name == APPROVAL_SHOW_TOOL_NAME
                {
                    let result = self.call_approval_show(tool_call.arguments).await;
                    jsonrpc_result_response(id, result)
                } else if self.execute_admin_tools
                    && self.admin_tools
                    && self.approval_consequence_tools
                    && tool_call.name == APPROVAL_RESUME_TOOL_NAME
                {
                    let result = self.call_approval_resume(tool_call.arguments).await;
                    jsonrpc_result_response(id, result)
                } else {
                    self.unavailable_tool_response(id, &tool_call.name)
                }
            }
            _ => jsonrpc_error_response(id, -32601, format!("method not found: {method}"), None),
        };

        Some(response)
    }

    fn handle_notification(&mut self, method: &str, _params: Value) {
        if method == "notifications/initialized" && !self.initialize_seen {
            tracing::warn!("received initialized notification before initialize request");
        }
    }

    fn unavailable_tool_response(&self, id: Value, tool_name: &str) -> Value {
        let (code, diagnostic, fallback) = if !self.endpoint_available {
            let diagnostic = if self.diagnostics.endpoint_state == "reachable"
                && self.diagnostics.admin_state == "endpoint_unavailable"
                && self.diagnostics.admin_reason == "unix_admin_probe_failed"
            {
                "unix_admin_probe_failed"
            } else {
                "endpoint_unavailable"
            };
            (
                "endpoint_unavailable",
                diagnostic,
                json!({
                    "mode": "cli_only",
                    "limitations": ["no MCP tools"]
                }),
            )
        } else if self.tcp_backend && !self.admin_tools && tool_name != self.tool_name {
            (
                "feature_unavailable",
                self.diagnostics.admin_reason,
                json!({
                    "mode": "cli_only",
                    "command": "guard approval show <handle>",
                    "limitations": ["no MCP status tool", "no MCP transcript", "no MCP wait", "no MCP resume"]
                }),
            )
        } else if self.http_transport
            && matches!(
                tool_name,
                ACCESS_STATUS_TOOL_NAME | APPROVAL_SHOW_TOOL_NAME | APPROVAL_RESUME_TOOL_NAME
            )
        {
            (
                "feature_unavailable",
                "tool_not_available_for_transport",
                json!({
                    "mode": "cli_only",
                    "limitations": ["no MCP status tool", "no MCP transcript", "no MCP resume"]
                }),
            )
        } else if matches!(
            tool_name,
            APPROVAL_SHOW_TOOL_NAME | APPROVAL_RESUME_TOOL_NAME
        ) && !self.approval_consequence_tools
        {
            (
                "feature_unavailable",
                self.diagnostics.capability_state,
                json!({
                    "mode": "cli_only",
                    "command": "guard approval show <handle>",
                    "limitations": ["no MCP wait", "no MCP resume"]
                }),
            )
        } else {
            (
                "feature_unavailable",
                "tool_not_available_for_transport",
                json!({
                    "mode": "cli_only",
                    "limitations": ["tool is not listed on this MCP surface"]
                }),
            )
        };
        jsonrpc_error_response(
            id,
            -32601,
            "requested MCP tool is unavailable".to_string(),
            Some(json!({
                "code": code,
                "diagnostic": diagnostic,
                "fallback": fallback,
            })),
        )
    }

    fn initialize_result(&self, params: &Value) -> Value {
        let requested = params
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or("2025-03-26");
        let negotiated = negotiate_protocol_version(requested);

        json!({
            "protocolVersion": negotiated,
            "capabilities": {
                "tools": {
                    "listChanged": false
                }
            },
            "serverInfo": {
                "name": "guard",
                "title": "guard MCP",
                "version": env!("CARGO_PKG_VERSION"),
                "description": "Policy-gated command execution through MCP tools."
            },
            "instructions": format!(
                "Use the {} tool to execute commands through the guard daemon. Commands are evaluated against security policy before execution. Denials come back as normal tool results with allowed=false so the model can revise the request without treating the tool itself as broken. Secret references name stored guard secrets; the daemon resolves the values server-side and never exposes them to the client.",
                self.tool_name
            )
        })
    }

    fn list_tools_result(&self) -> Value {
        if !self.endpoint_available {
            return json!({ "tools": [] });
        }
        let containment_failure_schema = json!({
            "type": ["object", "null"],
            "description": "Typed failure detail when containment could not truthfully report an armed timer.",
            "properties": {
                "kind": { "type": "string", "enum": ["forward_nonzero_exit", "forward_no_exit_code", "persistence_failure"] },
                "command_may_have_run": { "type": "boolean" },
                "forward_exit_code": { "type": ["integer", "null"] }
            },
            "required": ["kind", "command_may_have_run"]
        });
        let mut result = json!({
            "tools": [
                {
                    "name": self.tool_name,
                    "title": "Run Command Through Guard",
                    "description": "Execute a command through the guard daemon. Provide binary (with optional args) for a raw command, or verb for a catalog verb invocation; one of the two is required. The command is evaluated against security policy before execution. Plain environment overrides and named secret references are optional; secret values are resolved by the daemon and never exposed to the client. Branch on `status`, not on `allowed`: `held` and `provisional` are both `allowed: true` because the request was authorized, and `held` means it has not executed. A held command waits for an operator; retrieve its outcome with guard_approval_show.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "binary": {
                                "type": "string",
                                "description": "Binary to execute (e.g. ssh, kubectl, helm, aws). Required unless `verb` is provided."
                            },
                            "args": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Arguments to pass to the binary. Only meaningful with `binary`; omit for a verb invocation."
                            },
                            "hostkey": {
                                "type": "string",
                                "enum": ["only-existing", "accept-new", "accept-all"],
                                "description": "SSH host-key policy for guarded ssh commands. only-existing (default) keeps ssh's strict checking; accept-new trusts a new host on first contact but rejects a changed key; accept-all gives up host verification."
                            },
                            "env": {
                                "type": "object",
                                "additionalProperties": { "type": "string" },
                                "description": "Optional plain environment variables to inject for this command."
                            },
                            "secrets": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Optional stored secret names to inject using their derived environment-variable names."
                            },
                            "secretEnv": {
                                "type": "object",
                                "additionalProperties": { "type": "string" },
                                "description": "Optional explicit environment-variable to stored-secret mappings."
                            },
                            "secretFiles": {
                                "type": "object",
                                "additionalProperties": { "type": "string" },
                                "description": "Optional environment-variable to stored-secret mappings. Each variable receives a daemon-private child-lifetime file path."
                            },
                            "verb": {
                                "type": "object",
                                "description": "Invoke an operator-defined verb instead of a raw binary (omit binary/args). Provide name and params; the daemon renders the typed template.",
                                "properties": {
                                    "name": { "type": "string" },
                                    "params": { "type": "object", "additionalProperties": { "type": "string" } }
                                },
                                "required": ["name"]
                            },
                            "revert": {
                                "type": "string",
                                "description": "Optional rollback command (single string) for a recoverable action under consequence gating. The complete containment envelope is assessed before the action is armed."
                            },
                            "confirmCheck": {
                                "type": "string",
                                "description": "Independent command run at the containment deadline. Exit zero confirms; every other outcome runs the rollback. Requires revert."
                            },
                            "revertControlPath": {
                                "type": "string",
                                "description": "Authority and transport required for the confirmation check and rollback. Requires revert."
                            },
                            "confirmWithin": {
                                "type": "integer",
                                "description": "Optional auto-revert window in seconds for the containment envelope."
                            },
                            "requireApproval": {
                                "type": "boolean",
                                "description": "Optional: force this command onto the operator-approval (hold) path."
                            },
                            "waitApproval": {
                                "type": ["integer", "boolean"],
                                "description": "Optional: block for an operator decision on a held command and return the real result inline. An integer waits up to that many seconds; true waits without bound (the CLI's bare --wait-approval); false is the same as omitting it."
                            },
                            "reevaluate": {
                                "type": "boolean",
                                "description": "Optional: skip the daemon's generated deny-shape fast path and force a fresh evaluator look at this command. Never skips operator-authored deny coverage. Use this if generated coverage blocked something that should be allowed."
                            }
                        }
                    },
                    "outputSchema": {
                        "type": "object",
                        "properties": {
                            "schema_version": { "type": "integer", "const": TOOL_SCHEMA_VERSION },
                            "type": { "type": "string", "enum": ["execution_result", "error"] },
                            "allowed": { "type": "boolean" },
                            "reason": { "type": "string" },
                            "exit_code": { "type": ["integer", "null"] },
                            "stdout": { "type": ["string", "null"] },
                            "stderr": { "type": ["string", "null"] },
                            "status": { "type": ["string", "null"], "description": "Consequence-gate outcome: executed, provisional, held, reverted, or dry_run. Null also covers a typed containment failure." },
                            "handle": { "type": ["string", "null"], "description": "A denied or held durable request, provisional containment, or resolvable containment-recovery handle when applicable." },
                            "approval_options": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Exact operator commands for a denied or held request. A held command exposes the one-shot approval command; a denied request may expose ordinary, one-time, and bounded-use approval commands."
                            },
                            "access_requests": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "reference": { "type": "string" },
                                        "approval_options": {
                                            "type": "array",
                                            "items": { "type": "string" }
                                        }
                                    },
                                    "required": ["reference", "approval_options"]
                                },
                                "description": "Every durable access request created by the decision, with exact operator commands for each independently scoped request."
                            },
                            "coverage": { "type": ["object", "null"], "description": "What the gate checked and deliberately did NOT check (checked / not_checked arrays). Surfaced for held/provisional/dry-run outcomes." },
                            "verb_matches": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "verb": { "type": "string" },
                                        "cell": { "type": "string" },
                                        "scope": { "type": "string", "enum": ["baseline", "session"] },
                                        "action": { "type": "string" },
                                        "features": { "type": "array", "items": { "type": "string" } },
                                        "selected": { "type": "boolean" },
                                        "overridden": { "type": "boolean" }
                                    },
                                    "required": ["verb", "cell", "scope", "action", "selected", "overridden"]
                                },
                                "description": "Every applicable typed-verb coverage cell, including the selected and overridden cells."
                            },
                            "guidance": { "type": ["string", "null"], "description": "Actionable typed-verb or access guidance for a denied or held decision." },
                            "decision_source": { "type": "string", "description": "Stable source label for the admission decision, such as static_policy, typed_verb, evaluator, or validation." }
                        },
                        "required": ["schema_version", "type", "allowed", "reason", "exit_code", "stdout", "stderr", "status", "handle", "approval_options", "access_requests", "coverage", "verb_matches", "guidance", "decision_source"]
                    },
                    "annotations": {
                        "readOnlyHint": false,
                        "destructiveHint": true,
                        "idempotentHint": false,
                        "openWorldHint": true
                    }
                },
                {
                    "name": VERB_LIST_TOOL_NAME,
                    "title": "List Operator Verb Catalog",
                    "description": "List the operator-defined verb catalog (the agent's allow-listed menu). Each verb names a binary, its consequence class, and validated parameters. Invoke a verb with the run tool's `verb` argument; this tool only reads the catalog and never executes anything.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": false
                    },
                    "outputSchema": admin_output_schema(
                        "verb_list",
                        "verbs",
                        json!({ "type": "array", "items": { "type": "object" } })
                    ),
                    "annotations": {
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false
                    }
                },
                {
                    "name": ACCESS_REQUEST_TOOL_NAME,
                    "title": "Request Access",
                    "description": "Submit an access request for the daemon-authenticated caller. The intent describes the operation the caller needs to perform.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "intent": { "type": "string" }
                        },
                        "required": ["intent"],
                        "additionalProperties": false
                    },
                    "outputSchema": admin_output_schema(
                        "access_request",
                        "item",
                        json!({ "type": "object" })
                    ),
                    "annotations": {
                        "readOnlyHint": false,
                        "destructiveHint": false,
                        "idempotentHint": false,
                        "openWorldHint": true
                    }
                },
                {
                    "name": APPROVAL_LIST_TOOL_NAME,
                    "title": "List Access State",
                    "description": "List the caller's access requests, held operations, and active access sessions. The daemon scopes the result to the authenticated caller. Read-only; it does not approve, confirm, execute, or prune anything.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": false
                    },
                    "outputSchema": admin_output_schema(
                        "access_list",
                        "items",
                        json!({ "type": "array", "items": { "type": "object" } })
                    ),
                    "annotations": {
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false
                    }
                },
                {
                    "name": EVALUATE_BATCH_TOOL_NAME,
                    "title": "Evaluate a Command Batch",
                    "description": "Evaluate 1 to 64 command shapes without executing them. Results share the active saved-grant revision cache context.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "session": { "type": "string" },
                            "commands": {
                                "type": "array",
                                "minItems": 1,
                                "maxItems": 64,
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "binary": { "type": "string" },
                                        "args": { "type": "array", "items": { "type": "string" } }
                                    },
                                    "required": ["binary"]
                                }
                            }
                        },
                        "required": ["commands"]
                    },
                    "outputSchema": admin_output_schema(
                        "evaluation_batch",
                        "items",
                        json!({ "type": "array", "items": { "type": "object" } })
                    ),
                    "annotations": {
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": true
                    }
                },
                {
                    "name": ACCESS_SHOW_TOOL_NAME,
                    "title": "Show Access State",
                    "description": "Show one caller-visible access request, hold, or session by its stable reference.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "reference": { "type": "string" } },
                        "required": ["reference"]
                    },
                    "outputSchema": admin_output_schema(
                        "access_show",
                        "item",
                        json!({ "type": "object" })
                    ),
                    "annotations": {
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false
                    }
                },
                {
                    "name": ACCESS_STATUS_TOOL_NAME,
                    "title": "Show Access Session Status",
                    "description": "Show requester-scoped activity, decisions, holds, and provisionals for one access-managed session.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "reference": { "type": "string" } },
                        "required": ["reference"]
                    },
                    "outputSchema": admin_output_schema(
                        "access_status",
                        "report",
                        json!({ "type": "object" })
                    ),
                    "annotations": {
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false
                    }
                }
            ]
        });
        let output = &mut result["tools"][0]["outputSchema"];
        let properties = output["properties"]
            .as_object_mut()
            .expect("execution output properties");
        properties.insert(
            "confirm_deadline_unix".to_string(),
            json!({
                "type": ["integer", "null"],
                "description": "Unix deadline for a durably armed provisional containment window."
            }),
        );
        properties.insert(
            "confirm_window_secs".to_string(),
            json!({
                "type": ["integer", "null"],
                "description": "Configured duration of a durably armed provisional containment window."
            }),
        );
        properties.insert(
            "auto_revert_durable".to_string(),
            json!({
                "type": ["boolean", "null"],
                "description": "Whether the daemon durably recorded the armed auto-revert outcome."
            }),
        );
        properties.insert(
            "containment_failure".to_string(),
            containment_failure_schema,
        );
        output["required"]
            .as_array_mut()
            .expect("execution output required fields")
            .extend([
                json!("confirm_deadline_unix"),
                json!("confirm_window_secs"),
                json!("auto_revert_durable"),
                json!("containment_failure"),
            ]);
        let tools = result["tools"]
            .as_array_mut()
            .expect("tools result is an array");
        tools.push(approval_show_tool());
        tools.push(approval_resume_tool());
        if !self.admin_tools {
            tools.truncate(1);
        } else {
            if !self.approval_consequence_tools {
                tools.retain(|tool| {
                    tool["name"] != APPROVAL_SHOW_TOOL_NAME
                        && tool["name"] != APPROVAL_RESUME_TOOL_NAME
                });
            }
            if !self.execute_admin_tools || self.http_transport {
                tools.retain(|tool| tool["name"] != APPROVAL_RESUME_TOOL_NAME);
            }
            if self.http_transport {
                tools.retain(|tool| {
                    tool["name"] != ACCESS_STATUS_TOOL_NAME
                        && tool["name"] != APPROVAL_SHOW_TOOL_NAME
                });
            }
        }
        result
    }

    async fn call_tool(&self, arguments: Value) -> Value {
        let args: GuardToolArgs = match serde_json::from_value(arguments) {
            Ok(args) => args,
            Err(error) => {
                return tool_error_result(format!("invalid tool arguments: {error}"));
            }
        };

        match self.executor.execute(args).await {
            Ok(result) => tool_result(result),
            Err(error) => tool_error_result(format!("{error:#}")),
        }
    }

    /// Proxy AdminRequest::VerbList: surface the operator verb catalog as a
    /// read-only tool result. No command runs through this path.
    async fn call_verb_list(&self) -> Value {
        match self.admin.send_admin(server::AdminRequest::VerbList).await {
            Ok(server::AdminResponse::Verbs { items }) => {
                let structured = json!({ "verbs": items });
                admin_tool_result("verb_list", render_verbs_text(&items), structured)
            }
            Ok(server::AdminResponse::VerbMenu { items }) => {
                let text = items
                    .iter()
                    .map(|verb| {
                        let params = if verb.params.is_empty() {
                            String::new()
                        } else {
                            format!("\n    params: {}", verb.params.join(", "))
                        };
                        format!(
                            "{} [{}]{} - {}{}",
                            verb.name,
                            verb.consequence,
                            if verb.has_revert { " revertable" } else { "" },
                            verb.description,
                            params
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                let structured = json!({ "verbs": items, "projection": "agent_menu" });
                admin_tool_result("verb_list", text, structured)
            }
            Ok(server::AdminResponse::Error { message }) => tool_error_result(message),
            Ok(_) => tool_error_result("unexpected response from guard daemon".to_string()),
            Err(error) => tool_error_result(format!("{error:#}")),
        }
    }

    async fn call_access_request(&self, arguments: Value) -> Value {
        let args: AccessRequestArgs = match serde_json::from_value(arguments) {
            Ok(args) => args,
            Err(error) => return tool_error_result(format!("invalid tool arguments: {error}")),
        };
        match self
            .admin
            .send_admin(server::AdminRequest::AccessRequest {
                intent: args.intent,
            })
            .await
        {
            Ok(server::AdminResponse::AccessItem { item }) => admin_tool_result(
                "access_request",
                render_access_text(std::slice::from_ref(&item)),
                json!({ "item": item }),
            ),
            Ok(server::AdminResponse::Error { message }) => tool_error_result(message),
            Ok(_) => tool_error_result("unexpected response from guard daemon".to_string()),
            Err(error) => tool_error_result(format!("{error:#}")),
        }
    }

    /// Surface the caller's complete access state without mutating it.
    async fn call_approval_list(&self) -> Value {
        match self
            .admin
            .send_admin(server::AdminRequest::AccessList)
            .await
        {
            Ok(server::AdminResponse::AccessItems { items }) => {
                let structured = json!({ "items": items });
                admin_tool_result("access_list", render_access_text(&items), structured)
            }
            Ok(server::AdminResponse::Error { message }) => tool_error_result(message),
            Ok(_) => tool_error_result("unexpected response from guard daemon".to_string()),
            Err(error) => tool_error_result(format!("{error:#}")),
        }
    }

    async fn call_evaluate_batch(&self, arguments: Value) -> Value {
        let args: EvaluateBatchArgs = match serde_json::from_value(arguments) {
            Ok(args) => args,
            Err(error) => return tool_error_result(format!("invalid tool arguments: {error}")),
        };
        match self
            .admin
            .send_admin(server::AdminRequest::EvaluateBatch {
                session_token: args.session,
                caller_token: self.caller_token.clone(),
                commands: args.commands,
            })
            .await
        {
            Ok(server::AdminResponse::EvaluationBatch { items }) => {
                let text = items
                    .iter()
                    .map(|item| {
                        format!(
                            "{} allowed={} risk={:?} reason={}",
                            item.command, item.allowed, item.risk, item.reason
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                admin_tool_result("evaluation_batch", text, json!({ "items": items }))
            }
            Ok(server::AdminResponse::Error { message }) => tool_error_result(message),
            Ok(_) => tool_error_result("unexpected response from guard daemon".to_string()),
            Err(error) => tool_error_result(format!("{error:#}")),
        }
    }

    async fn call_access_show(&self, arguments: Value) -> Value {
        let args: AccessShowArgs = match serde_json::from_value(arguments) {
            Ok(args) => args,
            Err(error) => return tool_error_result(format!("invalid tool arguments: {error}")),
        };
        match self
            .admin
            .send_admin(server::AdminRequest::AccessShow {
                reference: args.reference,
            })
            .await
        {
            Ok(server::AdminResponse::AccessItem { item }) => admin_tool_result(
                "access_show",
                render_access_text(std::slice::from_ref(&item)),
                json!({ "item": item }),
            ),
            Ok(server::AdminResponse::Error { message }) => tool_error_result(message),
            Ok(_) => tool_error_result("unexpected response from guard daemon".to_string()),
            Err(error) => tool_error_result(format!("{error:#}")),
        }
    }

    /// Proxy `ApprovalShow`, or `ApprovalWait` when the caller asked to block.
    /// This is the path by which an agent retrieves the outcome of a command it
    /// did not hold a connection open for. The daemon scopes it to the hold's
    /// owner (or the operator) and returns the same not-found for anyone else,
    /// so this tool grants no read authority the caller did not already have.
    async fn call_approval_show(&self, arguments: Value) -> Value {
        let args: ApprovalArgs = match serde_json::from_value(arguments) {
            Ok(args) => args,
            Err(error) => return tool_error_result(format!("invalid tool arguments: {error}")),
        };
        let request = match args.wait {
            Some(timeout_secs) => server::AdminRequest::ApprovalWait {
                handle: args.reference,
                timeout_secs,
            },
            None => server::AdminRequest::ApprovalShow {
                handle: args.reference,
            },
        };
        match self.admin.send_admin(request).await {
            Ok(server::AdminResponse::ApprovalShow { item }) => admin_tool_result(
                "approval_show",
                render_approval_text(&item),
                json!({ "item": item }),
            ),
            Ok(server::AdminResponse::Error { message }) => tool_error_result(message),
            Ok(_) => tool_error_result("unexpected response from guard daemon".to_string()),
            Err(error) => tool_error_result(format!("{error:#}")),
        }
    }

    /// Proxy `AdminRequest::Resume`. This is an execute verb, exposed only over
    /// stdio; see `expose_execute_admin_tools`.
    async fn call_approval_resume(&self, arguments: Value) -> Value {
        let args: AccessShowArgs = match serde_json::from_value(arguments) {
            Ok(args) => args,
            Err(error) => return tool_error_result(format!("invalid tool arguments: {error}")),
        };
        match self
            .admin
            .send_admin(server::AdminRequest::Resume {
                handle: args.reference,
            })
            .await
        {
            Ok(server::AdminResponse::GateAction {
                message,
                exit_code,
                stdout,
                stderr,
            }) => {
                let text = format!(
                    "{message}\n{}{}",
                    stdout.as_deref().unwrap_or_default(),
                    stderr.as_deref().unwrap_or_default()
                );
                admin_tool_result(
                    "approval_resume",
                    text,
                    json!({
                        "result": {
                            "message": message,
                            "exit_code": exit_code,
                            "stdout": stdout,
                            "stderr": stderr,
                        }
                    }),
                )
            }
            Ok(server::AdminResponse::Error { message }) => tool_error_result(message),
            Ok(_) => tool_error_result("unexpected response from guard daemon".to_string()),
            Err(error) => tool_error_result(format!("{error:#}")),
        }
    }

    async fn call_session_status(&self, arguments: Value) -> Value {
        let args: AccessShowArgs = match serde_json::from_value(arguments) {
            Ok(args) => args,
            Err(error) => return tool_error_result(format!("invalid tool arguments: {error}")),
        };
        match self
            .admin
            .send_admin(server::AdminRequest::AccessStatus {
                reference: args.reference,
            })
            .await
        {
            Ok(server::AdminResponse::SessionStatus {
                report,
                approvals,
                provisionals,
                requests,
            }) => admin_tool_result(
                "access_status",
                format!(
                    "session activity: total={} allowed={} denied={}; requests={} approvals={} provisionals={}",
                    report.stats.total,
                    report.stats.allowed,
                    report.stats.denied,
                    requests.len(),
                    approvals.len(),
                    provisionals.len(),
                ),
                json!({
                    "report": report,
                    "approvals": approvals,
                    "provisionals": provisionals,
                    "requests": requests,
                }),
            ),
            Ok(server::AdminResponse::Error { message }) => tool_error_result(message),
            Ok(_) => tool_error_result("unexpected response from guard daemon".to_string()),
            Err(error) => tool_error_result(format!("{error:#}")),
        }
    }
}

fn render_verbs_text(items: &[server::VerbSummary]) -> String {
    if items.is_empty() {
        return "(no verbs configured)".to_string();
    }
    let mut lines = Vec::with_capacity(items.len());
    for v in items {
        let mut line = format!(
            "{} [{}]{}{} - {}",
            v.name,
            v.consequence,
            if v.trusted { " trusted" } else { "" },
            if v.has_revert { " revertable" } else { "" },
            v.description
        );
        for (param, pattern) in &v.params {
            line.push_str(&format!("\n    {param}=<{pattern}>"));
        }
        lines.push(line);
    }
    lines.join("\n")
}

/// The read tool by which an agent retrieves its own held command's outcome.
fn approval_show_tool() -> Value {
    json!({
        "name": APPROVAL_SHOW_TOOL_NAME,
        "title": "Show a Held Command",
        "description": "Show one held command owned by the caller, including its persisted transcript and exit code once it has run. With `wait`, block until an operator arms it or it reaches a terminal state, up to that many seconds. Read-only: it never approves and never executes. `status` is `pending` while it awaits a decision, `armed` once an operator approved it and it is waiting to be resumed, and a terminal value once it is finished.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "reference": { "type": "string" },
                "wait": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Optional: seconds to block for the hold to be armed or decided. Omit to read the current state and return immediately."
                }
            },
            "required": ["reference"]
        },
        "outputSchema": admin_output_schema("approval_show", "item", json!({ "type": "object" })),
        "annotations": {
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false
        }
    })
}

/// The execute verb for an armed hold. Listed only over stdio.
fn approval_resume_tool() -> Value {
    json!({
        "name": APPROVAL_RESUME_TOOL_NAME,
        "title": "Resume an Armed Held Command",
        "description": "Run one held command that an operator armed, as its original requester. The daemon accepts a single durable execution claim, so a hold runs at most once. Use guard_approval_show first to confirm the hold is armed.",
        "inputSchema": {
            "type": "object",
            "properties": { "reference": { "type": "string" } },
            "required": ["reference"]
        },
        "outputSchema": admin_output_schema("approval_resume", "result", json!({ "type": "object" })),
        "annotations": {
            "readOnlyHint": false,
            "destructiveHint": true,
            "idempotentHint": false,
            "openWorldHint": true
        }
    })
}

/// One held command as text an agent can act on. `status` is the field to
/// branch on; the transcript is present once the hold has run.
fn render_approval_text(item: &server::ApprovalSummary) -> String {
    let mut line = format!(
        "{} status={} command={} deadline={}",
        item.handle, item.status, item.command, item.deadline_unix
    );
    if let Some(reason) = item.decided_reason.as_deref() {
        line.push_str(&format!("\nreason: {reason}"));
    }
    match item.status.as_str() {
        "pending" => line.push_str("\nno operator decision yet; nothing has executed"),
        "armed" => line.push_str(&format!(
            "\napproved and armed; run it with guard_approval_resume {}",
            item.handle
        )),
        _ => {}
    }
    if let Some(exit_code) = item.exit_code {
        line.push_str(&format!("\nexit_code: {exit_code}"));
    }
    if let Some(stdout) = item.stdout.as_deref() {
        line.push_str(&format!("\nstdout:\n{stdout}"));
        if item.stdout_truncated {
            line.push_str("\n[guard stdout transcript truncated]");
        }
    }
    if let Some(stderr) = item.stderr.as_deref() {
        line.push_str(&format!("\nstderr:\n{stderr}"));
        if item.stderr_truncated {
            line.push_str("\n[guard stderr transcript truncated]");
        }
    }
    line
}

fn render_access_text(items: &[server::AccessItem]) -> String {
    if items.is_empty() {
        return "(no access requests or sessions)".to_string();
    }
    items
        .iter()
        .map(|item| {
            let uses = match item.use_policy.as_str() {
                "bounded" => format!(
                    " uses={}",
                    item.remaining_uses
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "0".to_string())
                ),
                other => format!(" uses={other}"),
            };
            let consequence = if item.consequence.is_empty() {
                if item.reference.starts_with("gr-") { "grant" } else { "arm" }
            } else {
                item.consequence.as_str()
            };
            let mut line = format!(
                "{} kind={} consequence={} requester={} target={} scope={} expiry={}{} state={} next={}",
                item.reference,
                item.kind,
                consequence,
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
                uses,
                item.state,
                item.next_action
            );
            for (label, command) in ["approve", "once", "bounded"]
                .into_iter()
                .zip(item.approval_options.iter())
            {
                line.push_str(&format!("\n{label}: {command}"));
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Wrap a read-only admin proxy result in the MCP tool-result envelope. These
/// are never daemon errors (those go through `tool_error_result`), so
/// `isError` is false.
fn admin_output_schema(result_type: &str, payload_name: &str, payload_schema: Value) -> Value {
    let mut schema = json!({
        "type": "object",
        "properties": {
            "schema_version": { "type": "integer", "const": TOOL_SCHEMA_VERSION },
            "type": { "type": "string", "enum": [result_type, "error"] },
            "reason": { "type": "string" }
        },
        "required": ["schema_version", "type"],
        "allOf": [
            {
                "if": { "properties": { "type": { "const": result_type } } },
                "then": { "required": [payload_name] }
            },
            {
                "if": { "properties": { "type": { "const": "error" } } },
                "then": { "required": ["reason"] }
            }
        ]
    });
    schema["properties"][payload_name] = payload_schema;
    schema
}

fn admin_tool_result(result_type: &str, text: String, mut structured: Value) -> Value {
    let fields = structured
        .as_object_mut()
        .expect("admin structured content is an object");
    fields.insert("schema_version".to_string(), json!(TOOL_SCHEMA_VERSION));
    fields.insert("type".to_string(), json!(result_type));
    json!({
        "content": [
            {
                "type": "text",
                "text": text
            }
        ],
        "structuredContent": structured,
        "isError": false
    })
}

fn parse_tool_call(params: Value) -> Result<ToolCallParams> {
    serde_json::from_value(params).context("invalid tools/call params")
}

fn negotiate_protocol_version(requested: &str) -> &'static str {
    SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .copied()
        .find(|candidate| *candidate == requested)
        .unwrap_or(SUPPORTED_PROTOCOL_VERSIONS[0])
}

fn ensure_initialized(initialize_seen: bool, method: &str) -> Result<()> {
    if initialize_seen {
        Ok(())
    } else {
        bail!("received {method} before initialize")
    }
}

fn validate_initialize_params(params: &Value) -> Result<()> {
    let Some(params) = params.as_object() else {
        bail!("initialize params must be an object");
    };
    if params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        bail!("initialize requires a nonempty protocolVersion");
    }
    if !params.get("capabilities").is_some_and(Value::is_object) {
        bail!("initialize requires a capabilities object");
    }
    let Some(client) = params.get("clientInfo").and_then(Value::as_object) else {
        bail!("initialize requires a clientInfo object");
    };
    for field in ["name", "version"] {
        if client
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            bail!("initialize clientInfo requires a nonempty {field}");
        }
    }
    Ok(())
}

fn jsonrpc_result_response(id: Value, result: Value) -> Value {
    serde_json::to_value(JsonRpcResponse {
        jsonrpc: JSONRPC_VERSION,
        id,
        result: Some(result),
        error: None,
    })
    .expect("response should serialize")
}

fn jsonrpc_error_response(id: Value, code: i64, message: String, data: Option<Value>) -> Value {
    serde_json::to_value(JsonRpcResponse {
        jsonrpc: JSONRPC_VERSION,
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message,
            data,
        }),
    })
    .expect("error response should serialize")
}

fn tool_result(result: GuardToolResponse) -> Value {
    let is_error = result.containment_failure.is_some()
        || (result.auto_revert_durable == Some(false) && result.containment_failure.is_none());
    let structured = json!({
        "schema_version": TOOL_SCHEMA_VERSION,
        "type": "execution_result",
        "allowed": result.allowed,
        "reason": result.reason,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "status": result.status,
        "handle": result.handle,
        "confirm_deadline_unix": result.confirm_deadline_unix,
        "confirm_window_secs": result.confirm_window_secs,
        "auto_revert_durable": result.auto_revert_durable,
        "containment_failure": result.containment_failure,
        "approval_options": result.approval_options,
        "access_requests": result.access_requests,
        "coverage": result.coverage,
        "verb_matches": result.verb_matches,
        "guidance": result.guidance,
        "decision_source": result.decision_source
    });

    json!({
        "content": [
            {
                "type": "text",
                "text": render_tool_text(&structured)
            }
        ],
        "structuredContent": structured,
        "isError": is_error
    })
}

fn tool_error_result(message: String) -> Value {
    let structured = json!({
        "schema_version": TOOL_SCHEMA_VERSION,
        "type": "error",
        "allowed": false,
        "reason": message,
        "exit_code": Value::Null,
        "stdout": Value::Null,
        "stderr": Value::Null,
        "status": Value::Null,
        "handle": Value::Null,
        "confirm_deadline_unix": Value::Null,
        "confirm_window_secs": Value::Null,
        "auto_revert_durable": Value::Null,
        "containment_failure": Value::Null,
        "approval_options": [],
        "access_requests": [],
        "coverage": Value::Null,
        "verb_matches": [],
        "guidance": Value::Null,
        "decision_source": "validation"
    });

    json!({
        "content": [
            {
                "type": "text",
                "text": format!("ERROR: {}", structured["reason"].as_str().unwrap_or("unknown error"))
            }
        ],
        "structuredContent": structured,
        "isError": true
    })
}

/// Render the gate coverage (what was checked / not checked) as appended text so
/// the agent reads the honesty surface inline, not just in structuredContent.
fn coverage_text(result: &Value) -> String {
    let Some(cov) = result.get("coverage") else {
        return String::new();
    };
    if cov.is_null() {
        return String::new();
    }
    let mut out = String::new();
    if let Some(checked) = cov.get("checked").and_then(Value::as_array) {
        for c in checked {
            if let Some(s) = c.as_str() {
                out.push_str(&format!("\n  checked: {s}"));
            }
        }
    }
    if let Some(not_checked) = cov.get("not_checked").and_then(Value::as_array) {
        for c in not_checked {
            if let Some(s) = c.as_str() {
                out.push_str(&format!("\n  NOT checked: {s}"));
            }
        }
    }
    out
}

fn render_tool_text(result: &Value) -> String {
    let allowed = result
        .get("allowed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let reason = result
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let exit_code = result.get("exit_code").and_then(Value::as_i64);
    let stdout = result.get("stdout").and_then(Value::as_str).unwrap_or("");
    let stderr = result.get("stderr").and_then(Value::as_str).unwrap_or("");
    let status = result.get("status").and_then(Value::as_str);
    let handle = result.get("handle").and_then(Value::as_str).unwrap_or("");
    let approval_options = result
        .get("approval_options")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    let access_next_steps = render_access_next_steps(result, handle, &approval_options);
    let guidance = result
        .get("guidance")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("\nGuidance: {value}"))
        .unwrap_or_default();
    let decision = decision_text(result);

    let typed_containment_failure = result
        .get("containment_failure")
        .is_some_and(|failure| !failure.is_null());
    let legacy_containment_failure = !typed_containment_failure
        && result.get("auto_revert_durable").and_then(Value::as_bool) == Some(false);
    if typed_containment_failure || legacy_containment_failure {
        let action = if handle.is_empty() {
            "Operator action required: inspect `guard provisionals`; no recovery handle is available."
                .to_string()
        } else {
            format!(
                "Operator action required for handle {handle}: inspect `guard provisionals`, then run `guard confirm {handle}` or `guard revert {handle}`."
            )
        };
        let mut out = String::new();
        if !stdout.is_empty() {
            out.push_str(stdout);
            if !stdout.ends_with('\n') {
                out.push('\n');
            }
        }
        if !stderr.is_empty() {
            out.push_str("stderr:\n");
            out.push_str(stderr);
            if !stderr.ends_with('\n') {
                out.push('\n');
            }
        }
        out.push_str(&format!(
            "CONTAINMENT FAILED: {reason}\nNo auto-revert timer is armed.\n{action}{}",
            coverage_text(result)
        ));
        return out;
    }

    // Consequence-gate outcomes are not denials: surface the handle, the next
    // step, and the honest coverage so the model knows what was NOT verified.
    match status {
        Some("held") => {
            return format!(
                "HELD for operator approval (request {handle}): {reason}{access_next_steps}\nDo not retry; wait or proceed with other work.{}",
                coverage_text(result),
            ) + &decision + &guidance;
        }
        Some("provisional") => {
            let mut out = String::new();
            if !stdout.is_empty() {
                out.push_str(stdout);
                out.push('\n');
            }
            out.push_str(&format!(
                "PROVISIONAL (handle {handle}): applied behind an auto-revert envelope; it reverts unless the operator runs `guard confirm {handle}`.{}",
                coverage_text(result)
            ));
            if let (Some(deadline), Some(window)) = (
                result.get("confirm_deadline_unix").and_then(Value::as_u64),
                result.get("confirm_window_secs").and_then(Value::as_u64),
            ) {
                out.push_str(&format!(
                    "\nConfirmation window: {window}s; deadline unix {deadline}."
                ));
            }
            return out;
        }
        Some("dry_run") => {
            return format!("[DRY-RUN] {reason}{}", coverage_text(result));
        }
        _ => {}
    }

    if !allowed {
        let request = if handle.is_empty() {
            String::new()
        } else {
            format!(" (request {handle})")
        };
        return format!("DENIED{request}: {reason}{access_next_steps}{decision}{guidance}");
    }

    // Approved path: the policy reason is operational noise for the
    // model (it just adds tokens without informing the next action).
    // Show only exec output; surface the exit code when non-zero so
    // the model notices failures and stderr when present.
    if stderr.is_empty() && exit_code.unwrap_or(0) == 0 {
        return stdout.to_string();
    }

    let mut sections = Vec::new();
    if let Some(code) = exit_code {
        if code != 0 {
            sections.push(format!("exit_code: {code}"));
        }
    }
    if !stdout.is_empty() {
        sections.push(stdout.to_string());
    }
    if !stderr.is_empty() {
        sections.push(format!("stderr:\n{stderr}"));
    }
    if sections.is_empty() {
        // Approved, exit 0, no stdout, no stderr - produce something
        // non-empty so the MCP transport doesn't return a blank value.
        return "(no output)".to_string();
    }
    sections.join("\n")
}

fn render_access_next_steps(result: &Value, handle: &str, approval_options: &[&str]) -> String {
    let access_requests = result
        .get("access_requests")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let reference = item.get("reference")?.as_str()?;
            let commands = item
                .get("approval_options")?
                .as_array()?
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            Some((reference, commands))
        })
        .collect::<Vec<_>>();

    if access_requests.len() == 1 {
        let (reference, commands) = &access_requests[0];
        return render_single_access_next_steps(reference, commands);
    }
    if !access_requests.is_empty() {
        let mut output = String::from("\nAccess requests:");
        for (reference, commands) in access_requests {
            output.push_str(&format!("\n- `{reference}`"));
            for command in commands {
                output.push_str(&format!("\n  `{command}`"));
            }
            output.push_str(&format!(
                "\n  Inspect with `guard access show {reference}`."
            ));
        }
        return output;
    }

    render_single_access_next_steps(handle, approval_options)
}

fn render_single_access_next_steps(handle: &str, approval_options: &[&str]) -> String {
    let mut output = String::new();
    if !approval_options.is_empty() {
        output.push_str(if approval_options.len() == 1 {
            "\nOperator command:"
        } else {
            "\nOperator commands:"
        });
        for command in approval_options {
            output.push_str(&format!("\n`{command}`"));
        }
    }
    if !handle.is_empty() {
        output.push_str(&format!("\nInspect with `guard access show {handle}`."));
    }
    output
}

fn decision_text(result: &Value) -> String {
    let source = result
        .get("decision_source")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let matches = result
        .get("verb_matches")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    Some(format!(
                        "{}/{}",
                        item.get("verb")?.as_str()?,
                        item.get("cell")?.as_str()?
                    ))
                })
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    if matches.is_empty() {
        format!("\nDecision source: {source}")
    } else {
        format!("\nDecision source: {source}; matched cells: {matches}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use guard::wire::mcp::McpSshHostKeyMode;
    use std::collections::VecDeque;
    use tokio::io::{AsyncRead, AsyncReadExt};
    use tokio::net::TcpStream;

    #[derive(Clone)]
    struct FakeExecutor {
        response: Result<GuardToolResponse, String>,
    }

    #[async_trait]
    impl GuardExecutor for FakeExecutor {
        async fn execute(&self, _args: GuardToolArgs) -> Result<GuardToolResponse> {
            match &self.response {
                Ok(result) => Ok(result.clone()),
                Err(error) => Err(anyhow!(error.clone())),
            }
        }
    }

    /// Admin proxy stub returning a fixed AdminResponse for every RPC.
    #[derive(Clone)]
    struct FakeAdmin {
        response: server::AdminResponse,
    }

    #[async_trait]
    impl GuardAdmin for FakeAdmin {
        async fn send_admin(
            &self,
            _request: server::AdminRequest,
        ) -> Result<server::AdminResponse> {
            Ok(self.response.clone())
        }
    }

    fn empty_admin() -> Arc<FakeAdmin> {
        Arc::new(FakeAdmin {
            response: server::AdminResponse::Ok,
        })
    }

    enum ScriptedReply {
        Response(server::AdminResponse),
        Failure,
    }

    #[derive(Clone)]
    struct ScriptedAdmin {
        replies: Arc<std::sync::Mutex<VecDeque<ScriptedReply>>>,
        requests: Arc<std::sync::Mutex<Vec<server::AdminRequest>>>,
    }

    impl ScriptedAdmin {
        fn new(replies: Vec<ScriptedReply>) -> Self {
            Self {
                replies: Arc::new(std::sync::Mutex::new(replies.into())),
                requests: Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl GuardAdmin for ScriptedAdmin {
        async fn send_admin(&self, request: server::AdminRequest) -> Result<server::AdminResponse> {
            self.requests.lock().unwrap().push(request);
            match self.replies.lock().unwrap().pop_front() {
                Some(ScriptedReply::Response(response)) => Ok(response),
                Some(ScriptedReply::Failure) => Err(anyhow!("probe failed")),
                None => panic!("unexpected probe request"),
            }
        }
    }

    fn ping(capable: bool) -> server::AdminResponse {
        server::AdminResponse::Ping {
            version: "0.7.1".to_string(),
            uptime_secs: 1,
            mode: "enforce".to_string(),
            dry_run: false,
            capabilities: capable
                .then(|| APPROVAL_CONSEQUENCES_CAPABILITY.to_string())
                .into_iter()
                .collect(),
        }
    }

    fn probe_config(tcp: bool, http: bool) -> McpConfig {
        McpConfig {
            socket_path: (!tcp).then(|| PathBuf::from("/run/guard/guard.sock")),
            tcp_port: tcp.then_some(9555),
            http_addr: http.then(|| "127.0.0.1:9556".parse().unwrap()),
            http_token: http.then(|| "fixture-token".to_string()),
            ..McpConfig::default()
        }
    }

    fn listed_names(surface: McpSurface, http: bool, tcp: bool) -> Vec<String> {
        let executor = Arc::new(FakeExecutor {
            response: Err("unused".to_string()),
        });
        let server = McpServer::new(executor, empty_admin(), DEFAULT_TOOL_NAME.to_string())
            .with_endpoint_available(surface.endpoint_available)
            .with_admin_tools(surface.admin_tools)
            .with_execute_admin_tools(surface.execute_admin_tools)
            .with_approval_consequence_tools(surface.approval_consequence_tools)
            .with_http_transport(http)
            .with_tcp_backend(tcp)
            .with_diagnostics(surface.diagnostics);
        server.list_tools_result()["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn probe_matrix_caches_ping_and_applies_transport_boundaries() {
        for capable in [false, true] {
            for http in [false, true] {
                let admin = ScriptedAdmin::new(vec![
                    ScriptedReply::Response(ping(capable)),
                    ScriptedReply::Response(server::AdminResponse::AccessItems {
                        items: Vec::new(),
                    }),
                ]);
                let surface = probe_mcp_surface(&admin, &probe_config(false, http)).await;
                assert_eq!(
                    surface.diagnostics.detected_version.as_deref(),
                    Some("0.7.1")
                );
                assert_eq!(
                    surface.diagnostics.detected_capabilities.len(),
                    usize::from(capable)
                );
                let names = listed_names(surface, http, false);
                assert!(names.iter().any(|name| name == DEFAULT_TOOL_NAME));
                assert_eq!(
                    names.iter().any(|name| name == APPROVAL_RESUME_TOOL_NAME),
                    capable && !http
                );
                assert_eq!(
                    names.iter().any(|name| name == APPROVAL_SHOW_TOOL_NAME),
                    capable && !http
                );
                assert_eq!(
                    names.iter().any(|name| name == ACCESS_STATUS_TOOL_NAME),
                    !http
                );
                let requests = admin.requests.lock().unwrap();
                assert!(matches!(
                    requests.as_slice(),
                    [server::AdminRequest::Ping, server::AdminRequest::AccessList]
                ));
            }

            for http in [false, true] {
                let admin = ScriptedAdmin::new(vec![ScriptedReply::Response(ping(capable))]);
                let surface = probe_mcp_surface(&admin, &probe_config(true, http)).await;
                assert_eq!(listed_names(surface, http, true), [DEFAULT_TOOL_NAME]);
                assert!(matches!(
                    admin.requests.lock().unwrap().as_slice(),
                    [server::AdminRequest::Ping]
                ));
            }
        }
    }

    #[tokio::test]
    async fn failed_or_malformed_ping_never_runs_admin_probe_or_lists_tools() {
        for first in [
            ScriptedReply::Failure,
            ScriptedReply::Response(server::AdminResponse::Ok),
        ] {
            let admin = ScriptedAdmin::new(vec![first]);
            let surface = probe_mcp_surface(&admin, &probe_config(false, false)).await;
            assert!(!surface.endpoint_available);
            assert!(listed_names(surface, false, false).is_empty());
            assert!(matches!(
                admin.requests.lock().unwrap().as_slice(),
                [server::AdminRequest::Ping]
            ));
        }
    }

    #[tokio::test]
    async fn failed_unix_admin_probe_has_endpoint_unavailable_diagnostic() {
        let admin = ScriptedAdmin::new(vec![
            ScriptedReply::Response(ping(true)),
            ScriptedReply::Failure,
        ]);
        let surface = probe_mcp_surface(&admin, &probe_config(false, false)).await;
        assert_eq!(surface.diagnostics.endpoint_state, "reachable");
        assert_eq!(surface.diagnostics.admin_reason, "unix_admin_probe_failed");

        let executor = Arc::new(FakeExecutor {
            response: Err("unused".to_string()),
        });
        let server = McpServer::new(executor, empty_admin(), DEFAULT_TOOL_NAME.to_string())
            .with_endpoint_available(surface.endpoint_available)
            .with_admin_tools(surface.admin_tools)
            .with_diagnostics(surface.diagnostics);
        let response = server.unavailable_tool_response(json!(1), DEFAULT_TOOL_NAME);
        assert_eq!(response["error"]["data"]["code"], "endpoint_unavailable");
        assert_eq!(
            response["error"]["data"]["diagnostic"],
            "unix_admin_probe_failed"
        );
    }

    #[test]
    fn held_tool_text_returns_exact_access_commands() {
        let text = render_tool_text(&serde_json::json!({
            "allowed": true,
            "reason": "needs review",
            "status": "held",
            "handle": "hold-example",
            "approval_options": ["guard access approve hold-example --once"],
            "exit_code": null,
            "stdout": null,
            "stderr": null
        }));
        for command in [
            "`guard access approve hold-example --once`",
            "`guard access show hold-example`",
        ] {
            assert!(text.contains(command), "missing {command}: {text}");
        }
        assert!(!text.contains("--uses"));
    }

    #[test]
    fn denied_tool_text_returns_exact_access_commands() {
        let text = render_tool_text(&serde_json::json!({
            "allowed": false,
            "reason": "outside current access",
            "status": null,
            "handle": "request-example",
            "approval_options": [
                "guard access approve request-example",
                "guard access approve request-example --once",
                "guard access approve request-example --uses 3"
            ],
            "exit_code": null,
            "stdout": null,
            "stderr": null
        }));
        for command in [
            "`guard access approve request-example`",
            "`guard access approve request-example --once`",
            "`guard access approve request-example --uses 3`",
            "`guard access show request-example`",
        ] {
            assert!(text.contains(command), "missing {command}: {text}");
        }
    }

    #[test]
    fn multi_request_denial_returns_each_exact_operator_handoff() {
        let text = render_tool_text(&serde_json::json!({
            "allowed": false,
            "reason": "two independent systems need access",
            "status": null,
            "handle": null,
            "approval_options": [],
            "access_requests": [
                {
                    "reference": "access-cloud",
                    "approval_options": [
                        "guard access approve access-cloud",
                        "guard access approve access-cloud --once",
                        "guard access approve access-cloud --uses 3"
                    ]
                },
                {
                    "reference": "access-host",
                    "approval_options": [
                        "guard access approve access-host",
                        "guard access approve access-host --once",
                        "guard access approve access-host --uses 3"
                    ]
                }
            ],
            "exit_code": null,
            "stdout": null,
            "stderr": null,
            "decision_source": "typed_verb"
        }));

        for reference in ["access-cloud", "access-host"] {
            for suffix in ["", " --once", " --uses 3"] {
                let command = format!("`guard access approve {reference}{suffix}`");
                assert!(text.contains(&command), "missing {command}: {text}");
            }
            let show = format!("`guard access show {reference}`");
            assert!(text.contains(&show), "missing {show}: {text}");
        }
    }

    #[derive(Clone)]
    struct RecordingAdmin {
        request: Arc<std::sync::Mutex<Option<server::AdminRequest>>>,
    }

    #[async_trait]
    impl GuardAdmin for RecordingAdmin {
        async fn send_admin(&self, request: server::AdminRequest) -> Result<server::AdminResponse> {
            *self.request.lock().unwrap() = Some(request);
            Ok(server::AdminResponse::EvaluationBatch { items: Vec::new() })
        }
    }

    #[tokio::test]
    async fn initialize_advertises_tools_capability() {
        let executor = Arc::new(FakeExecutor {
            response: Ok(GuardToolResponse {
                allowed: true,
                reason: "ok".to_string(),
                exit_code: Some(0),
                stdout: Some("ok\n".to_string()),
                stderr: None,
                status: None,
                handle: None,
                confirm_deadline_unix: None,
                confirm_window_secs: None,
                auto_revert_durable: None,
                containment_failure: None,
                approval_options: Vec::new(),
                access_requests: Vec::new(),
                coverage: None,
                verb_matches: Vec::new(),
                guidance: None,
                decision_source: "static_policy".to_string(),
            }),
        });
        let mut server = McpServer::new(executor, empty_admin(), DEFAULT_TOOL_NAME.to_string());

        let response = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": { "name": "test", "version": "1.0.0" }
                }
            }))
            .await
            .expect("initialize should respond");

        assert_eq!(response["result"]["protocolVersion"], "2025-03-26");
        assert!(response["result"]["capabilities"]["tools"].is_object());
    }

    #[tokio::test]
    async fn request_ids_cannot_be_reused_within_one_mcp_session() {
        let mut server = http_test_server();
        let initialize = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": "duplicate",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": { "name": "fixture", "version": "1" }
                }
            }))
            .await
            .expect("initialize response");
        assert!(initialize["result"].is_object());

        let duplicate = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": "duplicate",
                "method": "ping"
            }))
            .await
            .expect("duplicate response");
        assert_eq!(duplicate["error"]["code"], -32600);
        assert!(duplicate["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("already used")));
    }

    #[tokio::test]
    async fn initialize_rejects_incomplete_client_parameters() {
        let mut server = http_test_server();
        let response = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            }))
            .await
            .expect("initialization error response");
        assert_eq!(response["error"]["code"], -32602);
        assert!(!server.initialize_seen);
    }

    #[tokio::test]
    async fn evaluate_batch_sends_mcp_owned_session_separately_from_target() {
        let executor = Arc::new(FakeExecutor {
            response: Err("unused".to_string()),
        });
        let recorded = Arc::new(std::sync::Mutex::new(None));
        let admin = Arc::new(RecordingAdmin {
            request: recorded.clone(),
        });
        let mut server = McpServer::new(executor, admin, DEFAULT_TOOL_NAME.to_string())
            .with_caller_token(Some("mcp-owner".to_string()));
        server.initialize_seen = true;
        let response = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tools/call",
                "params": {
                    "name": EVALUATE_BATCH_TOOL_NAME,
                    "arguments": {
                        "session": "requested-target",
                        "commands": [{"binary": "true", "args": []}]
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(response["result"]["isError"], false);
        assert!(matches!(
            recorded.lock().unwrap().as_ref(),
            Some(server::AdminRequest::EvaluateBatch {
                session_token: Some(target),
                caller_token: Some(owner),
                ..
            }) if target == "requested-target" && owner == "mcp-owner"
        ));
    }

    #[tokio::test]
    async fn access_status_sends_the_requested_session_reference() {
        let executor = Arc::new(FakeExecutor {
            response: Err("unused".to_string()),
        });
        let recorded = Arc::new(std::sync::Mutex::new(None));
        let admin = Arc::new(RecordingAdmin {
            request: recorded.clone(),
        });
        let mut server = McpServer::new(executor, admin, DEFAULT_TOOL_NAME.to_string())
            .with_caller_token(Some("mcp-owner".to_string()));
        server.initialize_seen = true;
        let _ = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 43,
                "method": "tools/call",
                "params": {
                    "name": ACCESS_STATUS_TOOL_NAME,
                    "arguments": { "reference": "requested-target" }
                }
            }))
            .await
            .unwrap();
        assert!(matches!(
            recorded.lock().unwrap().as_ref(),
            Some(server::AdminRequest::AccessStatus { reference })
                if reference == "requested-target"
        ));
    }

    #[tokio::test]
    async fn access_show_sends_the_requested_durable_reference() {
        let executor = Arc::new(FakeExecutor {
            response: Err("unused".to_string()),
        });
        let recorded = Arc::new(std::sync::Mutex::new(None));
        let admin = Arc::new(RecordingAdmin {
            request: recorded.clone(),
        });
        let mut server = McpServer::new(executor, admin, DEFAULT_TOOL_NAME.to_string());
        server.initialize_seen = true;
        let _ = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 44,
                "method": "tools/call",
                "params": {
                    "name": ACCESS_SHOW_TOOL_NAME,
                    "arguments": { "reference": "requested-target" }
                }
            }))
            .await
            .unwrap();
        assert!(matches!(
            recorded.lock().unwrap().as_ref(),
            Some(server::AdminRequest::AccessShow { reference })
                if reference == "requested-target"
        ));
    }

    #[tokio::test]
    async fn access_request_sends_exact_intent() {
        let executor = Arc::new(FakeExecutor {
            response: Err("unused".to_string()),
        });
        let recorded = Arc::new(std::sync::Mutex::new(None));
        let admin = Arc::new(RecordingAdmin {
            request: recorded.clone(),
        });
        let mut server = McpServer::new(executor, admin, DEFAULT_TOOL_NAME.to_string());
        server.initialize_seen = true;
        let _ = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 44,
                "method": "tools/call",
                "params": {
                    "name": ACCESS_REQUEST_TOOL_NAME,
                    "arguments": { "intent": "Inspect the deployment target" }
                }
            }))
            .await
            .unwrap();
        assert!(matches!(
            recorded.lock().unwrap().as_ref(),
            Some(server::AdminRequest::AccessRequest { intent })
                if intent == "Inspect the deployment target"
        ));
    }

    #[tokio::test]
    async fn tools_list_returns_guard_tool() {
        let executor = Arc::new(FakeExecutor {
            response: Ok(GuardToolResponse {
                allowed: true,
                reason: "ok".to_string(),
                exit_code: Some(0),
                stdout: Some("ok\n".to_string()),
                stderr: None,
                status: None,
                handle: None,
                confirm_deadline_unix: None,
                confirm_window_secs: None,
                auto_revert_durable: None,
                containment_failure: None,
                approval_options: Vec::new(),
                access_requests: Vec::new(),
                coverage: None,
                verb_matches: Vec::new(),
                guidance: None,
                decision_source: "static_policy".to_string(),
            }),
        });
        let mut server = McpServer::new(executor, empty_admin(), DEFAULT_TOOL_NAME.to_string());
        server.initialize_seen = true;

        let response = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list"
            }))
            .await
            .expect("tools/list should respond");

        assert_eq!(response["result"]["tools"][0]["name"], DEFAULT_TOOL_NAME);
        assert!(
            response["result"]["tools"][0]["inputSchema"]
                .get("required")
                .is_none(),
            "binary/args must not be schema-required: a verb-only invocation is valid"
        );
        assert_eq!(
            response["result"]["tools"][0]["inputSchema"]["properties"]["waitApproval"]["type"],
            json!(["integer", "boolean"])
        );
        assert_eq!(
            response["result"]["tools"][0]["inputSchema"]["properties"]["hostkey"]["enum"],
            json!(["only-existing", "accept-new", "accept-all"])
        );
        assert_eq!(
            response["result"]["tools"][0]["inputSchema"]["properties"]["secretFiles"]["type"],
            "object"
        );
        assert_eq!(
            response["result"]["tools"][0]["inputSchema"]["properties"]["confirmCheck"]["type"],
            "string"
        );
        assert_eq!(
            response["result"]["tools"][0]["inputSchema"]["properties"]["revertControlPath"]
                ["type"],
            "string"
        );
    }

    #[tokio::test]
    async fn tcp_scoped_mcp_advertises_and_accepts_only_guard_run() {
        let executor = Arc::new(FakeExecutor {
            response: Err("unused".to_string()),
        });
        let mut server = McpServer::new(executor, empty_admin(), DEFAULT_TOOL_NAME.to_string())
            .with_admin_tools(false);
        server.initialize_seen = true;

        let listed = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list"
            }))
            .await
            .expect("tools/list response");
        let names: Vec<&str> = listed["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        assert_eq!(names, [DEFAULT_TOOL_NAME]);

        let hidden_call = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": VERB_LIST_TOOL_NAME, "arguments": {} }
            }))
            .await
            .expect("tools/call response");
        assert_eq!(hidden_call["error"]["code"], -32601);
    }

    #[test]
    fn guard_tool_args_accepts_hostkey_mode() {
        let parsed: GuardToolArgs = serde_json::from_value(json!({
            "binary": "ssh",
            "args": ["host01", "id"],
            "hostkey": "accept-new"
        }))
        .unwrap();
        assert_eq!(parsed.hostkey, Some(McpSshHostKeyMode::AcceptNew));

        // Omitting it defaults to None (only-existing behavior server-side).
        let without: GuardToolArgs = serde_json::from_value(json!({
            "binary": "ssh",
            "args": ["host01", "id"]
        }))
        .unwrap();
        assert_eq!(without.hostkey, None);
    }

    #[test]
    fn guard_tool_args_accepts_verb_without_binary() {
        let parsed: GuardToolArgs = serde_json::from_value(json!({
            "verb": { "name": "drain-node", "params": { "node": "worker-1" } }
        }))
        .unwrap();
        assert_eq!(parsed.binary, "");
        assert!(parsed.args.is_empty());
        let verb = parsed.verb.expect("verb parsed");
        assert_eq!(verb.name, "drain-node");
        assert_eq!(
            verb.params.get("node").map(String::as_str),
            Some("worker-1")
        );
    }

    #[test]
    fn wait_approval_accepts_boolean_and_integer_forms() {
        let seconds: GuardToolArgs =
            serde_json::from_value(json!({ "binary": "true", "waitApproval": 30 })).unwrap();
        assert_eq!(
            seconds.wait_approval.and_then(WaitApproval::into_secs),
            Some(30)
        );

        let unbounded: GuardToolArgs =
            serde_json::from_value(json!({ "binary": "true", "waitApproval": true })).unwrap();
        assert_eq!(
            unbounded.wait_approval.and_then(WaitApproval::into_secs),
            Some(u64::MAX)
        );

        let disabled: GuardToolArgs =
            serde_json::from_value(json!({ "binary": "true", "waitApproval": false })).unwrap();
        assert_eq!(
            disabled.wait_approval.and_then(WaitApproval::into_secs),
            None
        );

        let omitted: GuardToolArgs = serde_json::from_value(json!({ "binary": "true" })).unwrap();
        assert_eq!(
            omitted.wait_approval.and_then(WaitApproval::into_secs),
            None
        );
    }

    #[tokio::test]
    async fn executor_rejects_calls_without_binary_or_verb() {
        let executor = ClientExecutor {
            socket_path: Some(PathBuf::from("/nonexistent/guard.sock")),
            tcp_port: None,
            auth_token: None,
            session_token: None,
        };
        let args: GuardToolArgs = serde_json::from_value(json!({})).unwrap();
        let error = executor.execute(args).await.unwrap_err();
        assert!(
            error.to_string().contains("`binary` or `verb`"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn executor_threads_session_and_exec_auth_tokens() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = tokio::io::split(stream);
            let mut lines = BufReader::new(reader).lines();
            let request: Value =
                serde_json::from_str(&lines.next_line().await.unwrap().expect("execute request"))
                    .unwrap();
            writer
                .write_all(
                    br#"{"allowed":true,"reason":"fixture","exit_code":0,"stdout":null,"stderr":null}"#,
                )
                .await
                .unwrap();
            writer.write_all(b"\n").await.unwrap();
            request
        });

        let executor = ClientExecutor {
            socket_path: None,
            tcp_port: Some(port),
            auth_token: Some("exec-auth-fixture".to_string()),
            session_token: Some("session-fixture".to_string()),
        };
        let args: GuardToolArgs = serde_json::from_value(json!({ "binary": "true" })).unwrap();
        executor.execute(args).await.unwrap();

        let request = captured.await.unwrap();
        assert_eq!(request["execute"]["auth_token"], "exec-auth-fixture");
        assert_eq!(request["execute"]["session_token"], "session-fixture");
    }

    #[tokio::test]
    async fn admin_client_never_forwards_operator_authority() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = tokio::io::split(stream);
            let mut lines = BufReader::new(reader).lines();
            let request: Value =
                serde_json::from_str(&lines.next_line().await.unwrap().expect("admin request"))
                    .unwrap();
            writer
                .write_all(br#"{"result":"verbs","items":[]}"#)
                .await
                .unwrap();
            writer.write_all(b"\n").await.unwrap();
            request
        });

        let executor = ClientExecutor {
            socket_path: None,
            tcp_port: Some(port),
            auth_token: Some("exec-auth-fixture".to_string()),
            session_token: None,
        };
        let response = executor
            .send_admin(server::AdminRequest::VerbList)
            .await
            .unwrap();
        assert!(matches!(response, server::AdminResponse::Verbs { .. }));

        let request = captured.await.unwrap();
        assert!(request.get("admin_token").is_none());
        assert!(request.get("auth_token").is_none());
    }

    #[test]
    fn guard_tool_args_accepts_secret_file_bindings() {
        let parsed: GuardToolArgs = serde_json::from_value(json!({
            "binary": "credential-tool",
            "args": ["inspect"],
            "secretFiles": {
                "CREDENTIAL_FILE": "service/credential"
            }
        }))
        .unwrap();
        assert_eq!(
            parsed
                .secret_files
                .get("CREDENTIAL_FILE")
                .map(String::as_str),
            Some("service/credential")
        );
    }

    #[test]
    fn guard_tool_args_accepts_complete_containment_envelope() {
        let parsed: GuardToolArgs = serde_json::from_value(json!({
            "binary": "ssh",
            "args": ["firewall-a", "apply"],
            "revert": "ssh firewall-a rollback",
            "confirmCheck": "ssh firewall-a verify",
            "revertControlPath": "brokered SSH to firewall-a",
            "confirmWithin": 45
        }))
        .unwrap();
        assert_eq!(parsed.revert.as_deref(), Some("ssh firewall-a rollback"));
        assert_eq!(
            parsed.confirm_check.as_deref(),
            Some("ssh firewall-a verify")
        );
        assert_eq!(
            parsed.revert_control_path.as_deref(),
            Some("brokered SSH to firewall-a")
        );
        assert_eq!(parsed.confirm_within, Some(45));
    }

    #[tokio::test]
    async fn tool_call_returns_structured_output() {
        let executor = Arc::new(FakeExecutor {
            response: Ok(GuardToolResponse {
                allowed: true,
                reason: "allowed by policy".to_string(),
                exit_code: Some(0),
                stdout: Some("uptime output\n".to_string()),
                stderr: None,
                status: None,
                handle: None,
                confirm_deadline_unix: None,
                confirm_window_secs: None,
                auto_revert_durable: None,
                containment_failure: None,
                approval_options: Vec::new(),
                access_requests: Vec::new(),
                coverage: None,
                verb_matches: Vec::new(),
                guidance: None,
                decision_source: "static_policy".to_string(),
            }),
        });
        let mut server = McpServer::new(executor, empty_admin(), DEFAULT_TOOL_NAME.to_string());
        server.initialize_seen = true;

        let response = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": DEFAULT_TOOL_NAME,
                    "arguments": {
                        "binary": "ssh",
                        "args": ["prod", "uptime"]
                    }
                }
            }))
            .await
            .expect("tools/call should respond");

        assert_eq!(
            response["result"]["structuredContent"]["stdout"],
            "uptime output\n"
        );
        assert_eq!(response["result"]["isError"], false);
    }

    #[tokio::test]
    async fn tool_call_reports_backend_errors_as_tool_errors() {
        let executor = Arc::new(FakeExecutor {
            response: Err("backend unavailable".to_string()),
        });
        let mut server = McpServer::new(executor, empty_admin(), DEFAULT_TOOL_NAME.to_string());
        server.initialize_seen = true;

        let response = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": DEFAULT_TOOL_NAME,
                    "arguments": {
                        "binary": "ssh",
                        "args": ["prod", "uptime"]
                    }
                }
            }))
            .await
            .expect("tools/call should respond");

        assert_eq!(response["result"]["isError"], true);
        assert_eq!(
            response["result"]["structuredContent"]["reason"],
            "backend unavailable"
        );
    }

    #[test]
    fn guard_tool_secret_map_derives_and_dedupes_secret_env_names() {
        let secrets = guard_tool_secret_map(
            &[
                "opnsense-apikey-secret".to_string(),
                "opnsense-apikey-secret".to_string(),
            ],
            HashMap::from([(
                "AWS_SESSION_TOKEN".to_string(),
                "aws/session-token".to_string(),
            )]),
        )
        .unwrap();

        assert_eq!(
            secrets.get("OPNSENSE_APIKEY_SECRET").map(String::as_str),
            Some("opnsense-apikey-secret")
        );
        assert_eq!(
            secrets.get("AWS_SESSION_TOKEN").map(String::as_str),
            Some("aws/session-token")
        );
    }

    #[test]
    fn guard_tool_secret_map_rejects_conflicting_secret_mappings() {
        let err = guard_tool_secret_map(
            &["opnsense-apikey-secret".to_string()],
            HashMap::from([(
                "OPNSENSE_APIKEY_SECRET".to_string(),
                "other-secret".to_string(),
            )]),
        )
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("conflicting duplicate secret injection"));
    }

    #[test]
    fn denied_tool_results_are_not_transport_errors() {
        let value = tool_result(GuardToolResponse {
            allowed: false,
            reason: "policy denied".to_string(),
            exit_code: None,
            stdout: None,
            stderr: None,
            status: None,
            handle: None,
            confirm_deadline_unix: None,
            confirm_window_secs: None,
            auto_revert_durable: None,
            containment_failure: None,
            approval_options: Vec::new(),
            access_requests: Vec::new(),
            coverage: None,
            verb_matches: Vec::new(),
            guidance: None,
            decision_source: "static_policy".to_string(),
        });

        assert_eq!(value["isError"], false);
        assert_eq!(value["structuredContent"]["allowed"], false);
        assert_eq!(
            value["content"][0]["text"],
            "DENIED: policy denied\nDecision source: static_policy"
        );
    }

    #[test]
    fn structured_results_preserve_decision_fields_for_gate_statuses() {
        for (allowed, status, handle) in [
            (false, None, None),
            (true, Some("held"), Some("request-1")),
            (true, Some("provisional"), Some("provisional-1")),
            (true, Some("executed"), None),
        ] {
            let value = tool_result(GuardToolResponse {
                allowed,
                reason: "fixture result".to_string(),
                exit_code: Some(0),
                stdout: Some("fixture\n".to_string()),
                stderr: None,
                status: status.map(str::to_string),
                handle: handle.map(str::to_string),
                confirm_deadline_unix: None,
                confirm_window_secs: None,
                auto_revert_durable: None,
                containment_failure: None,
                approval_options: if status == Some("held") {
                    vec!["guard access approve request-1 --once".to_string()]
                } else {
                    Vec::new()
                },
                access_requests: Vec::new(),
                coverage: None,
                verb_matches: Vec::new(),
                guidance: Some("inspect access state".to_string()),
                decision_source: "fixture".to_string(),
            });
            let structured = &value["structuredContent"];
            assert_eq!(structured["schema_version"], TOOL_SCHEMA_VERSION);
            assert_eq!(structured["type"], "execution_result");
            assert_eq!(structured["allowed"], allowed);
            assert_eq!(structured["status"], json!(status));
            assert_eq!(structured["handle"], json!(handle));
            assert!(structured["approval_options"].is_array());
            assert!(structured["verb_matches"].is_array());
            assert_eq!(structured["guidance"], "inspect access state");
            assert_eq!(structured["decision_source"], "fixture");
            assert_eq!(value["isError"], false);
        }
    }

    fn execute_response_fixture() -> server::ExecuteResponse {
        server::ExecuteResponse {
            allowed: true,
            reason: "recoverable change".to_string(),
            exit_code: Some(0),
            stdout: None,
            stderr: None,
            status: Some(server::GateStatus::Provisional),
            handle: Some("pv-visible".to_string()),
            approval_options: Vec::new(),
            access_requests: Vec::new(),
            coverage: Some(guard::gating::Coverage::contain()),
            verb_matches: Vec::new(),
            verb_guidance: None,
            confirm_deadline_unix: Some(1_700_000_300),
            confirm_window_secs: Some(300),
            auto_revert_durable: Some(true),
            containment_failure: None,
            decision_source: "static_policy".to_string(),
            decision_trace: None,
        }
    }

    #[test]
    fn mcp_provisional_result_preserves_and_renders_confirmation_window() {
        let value = tool_result(execute_response_fixture().into());
        let structured = &value["structuredContent"];
        assert_eq!(structured["confirm_deadline_unix"], 1_700_000_300_u64);
        assert_eq!(structured["confirm_window_secs"], 300);
        assert_eq!(structured["auto_revert_durable"], true);
        assert!(structured["containment_failure"].is_null());
        let text = value["content"][0]["text"].as_str().expect("tool text");
        assert!(text.contains("pv-visible"));
        assert!(text.contains("300s"));
        assert!(text.contains("1700000300"));
        assert_eq!(value["isError"], false);
    }

    #[test]
    fn mcp_started_persistence_failure_is_typed_nonempty_and_actionable() {
        let mut response = execute_response_fixture();
        response.allowed = false;
        response.reason =
            "containment failed: command may have run; durable outcome unavailable".to_string();
        response.status = None;
        response.handle = Some("pv-recovery".to_string());
        response.confirm_deadline_unix = None;
        response.confirm_window_secs = None;
        response.auto_revert_durable = Some(false);
        response.containment_failure = Some(server::ContainmentFailure {
            kind: server::ContainmentFailureKind::PersistenceFailure,
            command_may_have_run: true,
            forward_exit_code: Some(0),
        });

        let value = tool_result(response.into());
        let structured = &value["structuredContent"];
        assert_eq!(structured["status"], Value::Null);
        assert_eq!(
            structured["containment_failure"]["kind"],
            "persistence_failure"
        );
        assert_eq!(
            structured["containment_failure"]["command_may_have_run"],
            true
        );
        assert_eq!(structured["containment_failure"]["forward_exit_code"], 0);
        assert!(structured["confirm_deadline_unix"].is_null());
        assert!(structured["confirm_window_secs"].is_null());
        assert_eq!(structured["auto_revert_durable"], false);
        assert_eq!(value["isError"], true);
        let text = value["content"][0]["text"].as_str().expect("tool text");
        assert!(!text.is_empty());
        assert!(text.contains("CONTAINMENT FAILED"));
        assert!(text.contains("pv-recovery"));
        assert!(text.contains("guard confirm pv-recovery"));
        assert!(text.contains("guard revert pv-recovery"));
        assert!(text.contains("durable outcome unavailable"));
    }

    fn prior_v1_durability_failure_fixture() -> server::ExecuteResponse {
        let mut response = execute_response_fixture();
        response.allowed = true;
        response.reason =
            "durable auto-revert state could not be recorded; operator decision required"
                .to_string();
        response.status = Some(server::GateStatus::Provisional);
        response.handle = Some("legacy-recovery".to_string());
        response.confirm_deadline_unix = None;
        response.confirm_window_secs = None;
        response.auto_revert_durable = Some(false);
        response.containment_failure = None;
        response
    }

    fn assert_prior_v1_durability_failure(value: &Value, stdout: &str, stderr: &str) {
        let structured = &value["structuredContent"];
        assert_eq!(structured["allowed"], true);
        assert_eq!(structured["status"], "provisional");
        assert_eq!(structured["auto_revert_durable"], false);
        assert!(structured["containment_failure"].is_null());
        assert_eq!(value["isError"], true);
        let text = value["content"][0]["text"].as_str().expect("tool text");
        assert!(text.contains(stdout));
        assert!(text.contains(stderr));
        assert!(text.contains("CONTAINMENT FAILED"));
        assert!(text.contains("No auto-revert timer is armed"));
        assert!(text.contains("Operator action required"));
        assert!(text.contains("legacy-recovery"));
        assert!(text.contains("guard confirm legacy-recovery"));
        assert!(text.contains("guard revert legacy-recovery"));
        assert!(!text.contains("applied behind an auto-revert envelope"));
    }

    #[test]
    fn mcp_prior_v1_nonstreaming_durability_failure_is_actionable_error() {
        let mut response = prior_v1_durability_failure_fixture();
        response.stdout = Some("forward output".to_string());
        response.stderr = Some("forward warning".to_string());
        let wire = serde_json::to_string(&response).expect("serialize prior v1 response");
        let parsed: server::ExecuteResponse =
            serde_json::from_str(&wire).expect("parse prior v1 response");

        let value = tool_result(parsed.into());
        assert_prior_v1_durability_failure(&value, "forward output", "forward warning");
    }

    #[tokio::test]
    async fn mcp_prior_v1_streaming_durability_failure_is_actionable_error() {
        let mut response = prior_v1_durability_failure_fixture();
        response.stdout = None;
        response.stderr = None;
        let messages = [
            serde_json::to_string(&server::ExecuteStreamMessage::Stdout {
                data: "streamed output".to_string(),
            })
            .expect("serialize stdout"),
            serde_json::to_string(&server::ExecuteStreamMessage::Stderr {
                data: "streamed warning".to_string(),
            })
            .expect("serialize stderr"),
            serde_json::to_string(&server::ExecuteStreamMessage::Result { response })
                .expect("serialize result"),
        ]
        .join("\n")
            + "\n";
        let parsed = crate::daemon_client::read_streaming_response_for_test(&messages)
            .await
            .expect("parse streaming prior v1 response");

        let value = tool_result(parsed.into());
        assert_prior_v1_durability_failure(&value, "streamed output", "streamed warning");
    }

    #[tokio::test]
    async fn request_missing_method_gets_invalid_request_error() {
        let executor = Arc::new(FakeExecutor {
            response: Ok(GuardToolResponse {
                allowed: true,
                reason: "ok".to_string(),
                exit_code: Some(0),
                stdout: Some("ok\n".to_string()),
                stderr: None,
                status: None,
                handle: None,
                confirm_deadline_unix: None,
                confirm_window_secs: None,
                auto_revert_durable: None,
                containment_failure: None,
                approval_options: Vec::new(),
                access_requests: Vec::new(),
                coverage: None,
                verb_matches: Vec::new(),
                guidance: None,
                decision_source: "static_policy".to_string(),
            }),
        });
        let mut server = McpServer::new(executor, empty_admin(), DEFAULT_TOOL_NAME.to_string());

        let response = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 5,
                "params": {}
            }))
            .await
            .expect("invalid request should respond");

        assert_eq!(response["error"]["code"], -32600);
        assert_eq!(response["id"], 5);
    }

    #[tokio::test]
    async fn tools_list_has_stable_order_and_access_request_schema() {
        let executor = Arc::new(FakeExecutor {
            response: Ok(GuardToolResponse {
                allowed: true,
                reason: "ok".to_string(),
                exit_code: Some(0),
                stdout: None,
                stderr: None,
                status: None,
                handle: None,
                confirm_deadline_unix: None,
                confirm_window_secs: None,
                auto_revert_durable: None,
                containment_failure: None,
                approval_options: Vec::new(),
                access_requests: Vec::new(),
                coverage: None,
                verb_matches: Vec::new(),
                guidance: None,
                decision_source: "static_policy".to_string(),
            }),
        });
        let mut server = McpServer::new(executor, empty_admin(), DEFAULT_TOOL_NAME.to_string());
        server.initialize_seen = true;

        let response = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/list"
            }))
            .await
            .expect("tools/list should respond");

        let names: Vec<&str> = response["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();

        assert_eq!(
            names,
            vec![
                DEFAULT_TOOL_NAME,
                VERB_LIST_TOOL_NAME,
                ACCESS_REQUEST_TOOL_NAME,
                APPROVAL_LIST_TOOL_NAME,
                EVALUATE_BATCH_TOOL_NAME,
                ACCESS_SHOW_TOOL_NAME,
                ACCESS_STATUS_TOOL_NAME,
                APPROVAL_SHOW_TOOL_NAME,
                APPROVAL_RESUME_TOOL_NAME,
            ]
        );
        let access_request = &response["result"]["tools"][2];
        assert_eq!(
            access_request["inputSchema"]["properties"]["intent"]["type"],
            "string"
        );
        assert_eq!(access_request["inputSchema"]["required"], json!(["intent"]));
        assert_eq!(access_request["inputSchema"]["additionalProperties"], false);

        for tool in response["result"]["tools"].as_array().expect("tools array") {
            let output = &tool["outputSchema"];
            assert!(output.is_object(), "{} needs outputSchema", tool["name"]);
            assert_eq!(
                output["properties"]["schema_version"]["const"],
                TOOL_SCHEMA_VERSION
            );
            assert!(output["properties"]["type"].is_object());
        }

        let output = &response["result"]["tools"][0]["outputSchema"];
        for field in [
            "approval_options",
            "access_requests",
            "verb_matches",
            "guidance",
            "decision_source",
        ] {
            assert!(output["properties"].get(field).is_some(), "missing {field}");
            assert!(
                output["required"]
                    .as_array()
                    .expect("output required array")
                    .iter()
                    .any(|required| required == field),
                "{field} must be required"
            );
        }
        let handle_description = output["properties"]["handle"]["description"]
            .as_str()
            .expect("handle description");
        assert!(handle_description.contains("held"));
        assert!(handle_description.contains("provisional"));
    }

    #[tokio::test]
    async fn verb_list_tool_proxies_daemon_catalog() {
        let executor = Arc::new(FakeExecutor {
            response: Ok(GuardToolResponse {
                allowed: true,
                reason: "ok".to_string(),
                exit_code: Some(0),
                stdout: None,
                stderr: None,
                status: None,
                handle: None,
                confirm_deadline_unix: None,
                confirm_window_secs: None,
                auto_revert_durable: None,
                containment_failure: None,
                approval_options: Vec::new(),
                access_requests: Vec::new(),
                coverage: None,
                verb_matches: Vec::new(),
                guidance: None,
                decision_source: "static_policy".to_string(),
            }),
        });
        let admin = Arc::new(FakeAdmin {
            response: server::AdminResponse::Verbs {
                items: vec![server::VerbSummary {
                    name: "drain-node".to_string(),
                    description: "cordon and drain a node".to_string(),
                    binary: "kubectl".to_string(),
                    baseline: true,
                    coverage: Vec::new(),
                    credential_plan: None,
                    consequence: "recoverable".to_string(),
                    trusted: true,
                    has_revert: true,
                    params: std::collections::BTreeMap::new(),
                    auto_promoted: false,
                    evidence: None,
                }],
            },
        });
        let mut server = McpServer::new(executor, admin, DEFAULT_TOOL_NAME.to_string());
        server.initialize_seen = true;

        let response = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {
                    "name": VERB_LIST_TOOL_NAME,
                    "arguments": {}
                }
            }))
            .await
            .expect("tools/call should respond");

        assert_eq!(response["result"]["isError"], false);
        assert_eq!(
            response["result"]["structuredContent"]["schema_version"],
            TOOL_SCHEMA_VERSION
        );
        assert_eq!(response["result"]["structuredContent"]["type"], "verb_list");
        assert_eq!(
            response["result"]["structuredContent"]["verbs"][0]["name"],
            "drain-node"
        );
    }

    #[tokio::test]
    async fn access_list_tool_proxies_non_mutating_access_state() {
        let executor = Arc::new(FakeExecutor {
            response: Ok(GuardToolResponse {
                allowed: true,
                reason: "ok".to_string(),
                exit_code: Some(0),
                stdout: None,
                stderr: None,
                status: None,
                handle: None,
                confirm_deadline_unix: None,
                confirm_window_secs: None,
                auto_revert_durable: None,
                containment_failure: None,
                approval_options: Vec::new(),
                access_requests: Vec::new(),
                coverage: None,
                verb_matches: Vec::new(),
                guidance: None,
                decision_source: "static_policy".to_string(),
            }),
        });
        let admin = Arc::new(FakeAdmin {
            response: server::AdminResponse::AccessItems { items: vec![] },
        });
        let mut server = McpServer::new(executor, admin, DEFAULT_TOOL_NAME.to_string());
        server.initialize_seen = true;

        let response = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": APPROVAL_LIST_TOOL_NAME,
                    "arguments": {}
                }
            }))
            .await
            .expect("tools/call should respond");

        assert_eq!(response["result"]["isError"], false);
        assert_eq!(
            response["result"]["structuredContent"]["schema_version"],
            TOOL_SCHEMA_VERSION
        );
        assert_eq!(
            response["result"]["structuredContent"]["type"],
            "access_list"
        );
        assert!(response["result"]["structuredContent"]["items"]
            .as_array()
            .expect("approvals array")
            .is_empty());
    }

    #[test]
    fn http_config_requires_token() {
        let mut config = McpConfig {
            socket_path: Some(PathBuf::from("/run/guard/guard.sock")),
            tcp_port: None,
            auth_token: None,
            session_token: None,
            tool_name: DEFAULT_TOOL_NAME.to_string(),
            http_addr: Some("127.0.0.1:0".parse().unwrap()),
            http_token: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("bearer token"));

        config.http_token = Some("   ".to_string());
        assert!(config.validate().is_err(), "blank token must be rejected");

        config.http_token = Some("secret-token".to_string());
        config
            .validate()
            .expect("token present makes http config valid");

        config.http_addr = Some("0.0.0.0:7333".parse().unwrap());
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("loopback"));
    }

    #[test]
    fn custom_execution_tool_cannot_shadow_a_built_in_tool() {
        for reserved in BUILT_IN_TOOL_NAMES
            .iter()
            .copied()
            .filter(|name| *name != DEFAULT_TOOL_NAME)
        {
            let config = McpConfig {
                socket_path: Some(PathBuf::from("/run/guard/guard.sock")),
                tool_name: reserved.to_string(),
                ..McpConfig::default()
            };
            let error = config.validate().expect_err("reserved name must fail");
            assert!(error.to_string().contains("reserved"));
            assert!(error.to_string().contains(reserved));
        }

        let default = McpConfig {
            socket_path: Some(PathBuf::from("/run/guard/guard.sock")),
            ..McpConfig::default()
        };
        default
            .validate()
            .expect("the default execution name is valid");

        let custom = McpConfig {
            socket_path: Some(PathBuf::from("/run/guard/guard.sock")),
            tool_name: "fixture_run".to_string(),
            ..McpConfig::default()
        };
        custom
            .validate()
            .expect("an independent custom name is valid");
    }

    #[test]
    fn constant_time_eq_matches_only_on_equal_bytes() {
        use crate::server::constant_time_eq;
        assert!(constant_time_eq(b"token", b"token"));
        assert!(!constant_time_eq(b"token", b"tokem"));
        assert!(!constant_time_eq(b"token", b"token-longer"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    fn http_test_server() -> McpServer<FakeExecutor, FakeAdmin> {
        let executor = Arc::new(FakeExecutor {
            response: Ok(GuardToolResponse {
                allowed: true,
                reason: "ok".to_string(),
                exit_code: Some(0),
                stdout: None,
                stderr: None,
                status: None,
                handle: None,
                confirm_deadline_unix: None,
                confirm_window_secs: None,
                auto_revert_durable: None,
                containment_failure: None,
                approval_options: Vec::new(),
                access_requests: Vec::new(),
                coverage: None,
                verb_matches: Vec::new(),
                guidance: None,
                decision_source: "static_policy".to_string(),
            }),
        });
        McpServer::new(executor, empty_admin(), DEFAULT_TOOL_NAME.to_string())
    }

    #[test]
    fn expired_http_sessions_are_pruned_deterministically() {
        let now = Instant::now();
        let mut sessions = HttpSessionTable::new();
        sessions.insert(
            "expired".to_string(),
            HttpSession {
                connection: Arc::new(Mutex::new(http_test_server())),
                expires_at: now,
            },
        );
        sessions.insert(
            "active".to_string(),
            HttpSession {
                connection: Arc::new(Mutex::new(http_test_server())),
                expires_at: now + HTTP_SESSION_IDLE_TIMEOUT,
            },
        );

        prune_expired_http_sessions(&mut sessions, now);

        assert!(!sessions.contains_key("expired"));
        assert!(sessions.contains_key("active"));
    }

    /// Bind an ephemeral port and serve the real hyper-backed HTTP transport
    /// (`serve_http_on`) on it, so tests exercise the production accept loop,
    /// connection builder, and request handler.
    async fn spawn_http_server(token: &str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let token = token.to_string();
        let handle = tokio::spawn(async move {
            let _ = serve_http_on(listener, http_test_server(), token).await;
        });
        (addr, handle)
    }

    /// Read exactly one HTTP response (status line, headers, Content-Length
    /// body) off a connection without consuming bytes of a following response,
    /// so keep-alive tests can issue sequential requests on one stream.
    async fn read_one_response_parts<R: AsyncRead + Unpin>(
        stream: &mut R,
    ) -> (u16, HashMap<String, String>, String) {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            let read = stream.read(&mut byte).await.expect("read header byte");
            assert!(read > 0, "connection closed before end of headers");
            head.push(byte[0]);
        }
        let head_text = String::from_utf8_lossy(&head).into_owned();
        let status: u16 = head_text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .expect("status code");
        let headers = head_text
            .lines()
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
            .collect::<HashMap<_, _>>();
        let content_length: usize = head_text
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.trim().eq_ignore_ascii_case("content-length") {
                    value.trim().parse().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);
        let mut body = vec![0u8; content_length];
        stream.read_exact(&mut body).await.expect("read body");
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    }

    async fn read_one_response<R: AsyncRead + Unpin>(stream: &mut R) -> (u16, String) {
        let (status, _, body) = read_one_response_parts(stream).await;
        (status, body)
    }

    /// Drive one raw HTTP request against an ephemeral-port HTTP MCP server and
    /// return the parsed status line + body string.
    async fn http_roundtrip(
        addr: SocketAddr,
        authorization: Option<&str>,
        additional_headers: &[(&str, &str)],
        json_body: &str,
    ) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let mut request = format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            json_body.len()
        );
        if let Some(auth) = authorization {
            request.push_str(&format!("Authorization: {auth}\r\n"));
        }
        for (name, value) in additional_headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("Connection: close\r\n\r\n");
        request.push_str(json_body);
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");

        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read response");
        let text = String::from_utf8_lossy(&raw).into_owned();
        let status: u16 = text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .expect("status code");
        let body = text
            .split_once("\r\n\r\n")
            .map(|(_, body)| body.to_string())
            .unwrap_or_default();
        (status, body)
    }

    fn authenticated_http_post(token: &str, body: &str) -> String {
        format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    fn authenticated_http_post_with_session(token: &str, session_id: &str, body: &str) -> String {
        format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nMcp-Session-Id: {session_id}\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_transport_enforces_bearer() {
        let token = "test-bearer-token".to_string();
        let (addr, handle) = spawn_http_server(&token).await;

        let ping_body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}"#;

        // No Authorization header -> 401, no JSON-RPC result.
        let (status, body) = http_roundtrip(addr, None, &[], ping_body).await;
        assert_eq!(status, 401, "missing token must be rejected");
        assert!(
            !body.contains("\"result\""),
            "401 body must not leak a result"
        );

        // Wrong token -> 401.
        let (status, _) = http_roundtrip(addr, Some("Bearer wrong-token"), &[], ping_body).await;
        assert_eq!(status, 401, "wrong token must be rejected");

        // Correct token -> 200 + a valid JSON-RPC result listing tools.
        let auth = format!("Bearer {token}");
        let (status, body) = http_roundtrip(addr, Some(&auth), &[], ping_body).await;
        assert_eq!(status, 200, "valid token must be accepted");
        let parsed: Value = serde_json::from_str(&body).expect("body is JSON");
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["id"], 1);
        assert!(parsed["result"].is_object());

        // A non-POST method is rejected with 405.
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(
                format!("GET /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await
            .expect("write GET");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read");
        let text = String::from_utf8_lossy(&raw);
        let status: u16 = text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .expect("status");
        assert_eq!(status, 405, "GET must be rejected");

        handle.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_transport_rejects_non_loopback_origins_and_invalid_versions() {
        let token = "origin-token";
        let auth = format!("Bearer {token}");
        let (addr, handle) = spawn_http_server(token).await;
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}"#;

        let (status, _) = http_roundtrip(
            addr,
            Some(&auth),
            &[("Origin", "https://attacker.example")],
            body,
        )
        .await;
        assert_eq!(status, 403);

        let (status, _) = http_roundtrip(
            addr,
            Some(&auth),
            &[("Origin", "http://localhost:4180")],
            body,
        )
        .await;
        assert_eq!(status, 200);

        let (status, _) = http_roundtrip(
            addr,
            Some(&auth),
            &[("MCP-Protocol-Version", "2099-01-01")],
            body,
        )
        .await;
        assert_eq!(status, 400);

        let (status, _) = http_roundtrip(
            addr,
            Some(&auth),
            &[("MCP-Protocol-Version", "2025-11-25")],
            body,
        )
        .await;
        assert_eq!(status, 200);

        handle.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_transport_requires_streamable_http_accept_types() {
        let token = "accept-token";
        let (addr, handle) = spawn_http_server(token).await;
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream.write_all(request.as_bytes()).await.expect("write");
        let (status, _) = read_one_response(&mut stream).await;
        assert_eq!(status, 406);
        handle.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn invalid_and_notification_initializes_cannot_exhaust_session_capacity() {
        let token = "initialize-capacity-token";
        let (addr, handle) = spawn_http_server(token).await;
        let mut stream = TcpStream::connect(addr).await.expect("connect");

        for id in 0..MAX_HTTP_SESSIONS {
            let notification = json!({
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": { "name": "fixture", "version": "1" }
                }
            })
            .to_string();
            stream
                .write_all(authenticated_http_post(token, &notification).as_bytes())
                .await
                .expect("write initialize notification");
            let (status, headers, _) = read_one_response_parts(&mut stream).await;
            assert_eq!(status, 400, "notification initialize {id}");
            assert!(!headers.contains_key("mcp-session-id"));

            let invalid = json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "initialize",
                "params": {}
            })
            .to_string();
            stream
                .write_all(authenticated_http_post(token, &invalid).as_bytes())
                .await
                .expect("write invalid initialize");
            let (status, headers, body) = read_one_response_parts(&mut stream).await;
            assert_eq!(status, 200, "invalid initialize {id}");
            assert!(!headers.contains_key("mcp-session-id"));
            let response: Value = serde_json::from_str(&body).expect("JSON-RPC error");
            assert_eq!(response["error"]["code"], -32602);
        }

        let valid = json!({
            "jsonrpc": "2.0",
            "id": "valid-after-invalid",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "fixture", "version": "1" }
            }
        })
        .to_string();
        stream
            .write_all(authenticated_http_post(token, &valid).as_bytes())
            .await
            .expect("write valid initialize");
        let (status, headers, body) = read_one_response_parts(&mut stream).await;
        assert_eq!(status, 200);
        assert!(headers.contains_key("mcp-session-id"));
        let response: Value = serde_json::from_str(&body).expect("InitializeResult");
        assert!(response["result"].is_object());

        handle.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_session_state_survives_reconnect_and_isolated_sessions_do_not_mix() {
        let token = "lifecycle-token";
        let (addr, handle) = spawn_http_server(token).await;
        let init = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "fixture", "version": "1" }
            }
        })
        .to_string();
        let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;

        let mut initialized = TcpStream::connect(addr).await.expect("connect");
        initialized
            .write_all(authenticated_http_post(token, &init).as_bytes())
            .await
            .expect("initialize");
        let (status, headers, _) = read_one_response_parts(&mut initialized).await;
        assert_eq!(status, 200);
        let session_id = headers
            .get("mcp-session-id")
            .expect("initialize response session id")
            .clone();
        drop(initialized);

        let mut reconnected = TcpStream::connect(addr).await.expect("reconnect");
        reconnected
            .write_all(authenticated_http_post_with_session(token, &session_id, list).as_bytes())
            .await
            .expect("list");
        let (_, body) = read_one_response(&mut reconnected).await;
        let response: Value = serde_json::from_str(&body).unwrap();
        assert!(response["result"]["tools"].is_array());

        let mut second = TcpStream::connect(addr).await.expect("second connect");
        second
            .write_all(authenticated_http_post(token, &init).as_bytes())
            .await
            .expect("second initialize");
        let (status, headers, _) = read_one_response_parts(&mut second).await;
        assert_eq!(status, 200);
        let second_session_id = headers
            .get("mcp-session-id")
            .expect("second initialize response session id")
            .clone();
        assert_ne!(session_id, second_session_id);

        let auth = format!("Bearer {token}");
        let first_headers = [("Mcp-Session-Id", session_id.as_str())];
        let second_headers = [("Mcp-Session-Id", second_session_id.as_str())];
        let (first_result, second_result) = tokio::join!(
            http_roundtrip(addr, Some(&auth), &first_headers, list),
            http_roundtrip(addr, Some(&auth), &second_headers, list)
        );
        assert_eq!(first_result.0, 200);
        assert_eq!(second_result.0, 200);

        let mut terminating = TcpStream::connect(addr).await.expect("terminate connect");
        terminating
            .write_all(
                format!(
                    "DELETE /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nMcp-Session-Id: {second_session_id}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("terminate session");
        assert_eq!(read_one_response(&mut terminating).await.0, 204);
        assert_eq!(
            http_roundtrip(addr, Some(&auth), &second_headers, list)
                .await
                .0,
            404
        );

        let mut missing = TcpStream::connect(addr).await.expect("connect");
        missing
            .write_all(authenticated_http_post(token, list).as_bytes())
            .await
            .expect("list without session");
        assert_eq!(read_one_response(&mut missing).await.0, 400);

        handle.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_transport_serves_sequential_requests_on_one_connection() {
        let token = "keepalive-token";
        let (addr, handle) = spawn_http_server(token).await;

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        for id in 1..=2 {
            let body = format!(
                r#"{{"jsonrpc":"2.0","id":{id},"method":"initialize","params":{{"protocolVersion":"2025-11-25","capabilities":{{}},"clientInfo":{{"name":"fixture","version":"1"}}}}}}"#
            );
            let request = format!(
                "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(request.as_bytes())
                .await
                .expect("write request");
            let (status, response_body) = read_one_response(&mut stream).await;
            assert_eq!(status, 200, "request {id} on the shared connection");
            let parsed: Value = serde_json::from_str(&response_body).expect("body is JSON");
            assert_eq!(parsed["id"], id);
            assert!(parsed["result"].is_object());
        }

        handle.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_transport_accepts_chunked_request_bodies() {
        let token = "chunked-token";
        let (addr, handle) = spawn_http_server(token).await;

        let body = r#"{"jsonrpc":"2.0","id":11,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}"#;
        let (first, second) = body.split_at(10);
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{first}\r\n{:x}\r\n{second}\r\n0\r\n\r\n",
            first.len(),
            second.len()
        );
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        let (status, response_body) = read_one_response(&mut stream).await;
        assert_eq!(status, 200, "chunked request must be accepted");
        let parsed: Value = serde_json::from_str(&response_body).expect("body is JSON");
        assert_eq!(parsed["id"], 11);

        handle.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_transport_rejects_oversized_bodies() {
        let token = "oversize-token";
        let (addr, handle) = spawn_http_server(token).await;

        // Declared oversized body: the 413 comes back from the Content-Length
        // check alone, before any body bytes are sent.
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            MAX_HTTP_BODY + 1
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        let (status, _) = read_one_response(&mut stream).await;
        assert_eq!(status, 413, "declared oversized body must be rejected");
        drop(stream);

        // Chunked oversized body (no Content-Length header to check up front):
        // the streaming cap on the body read must reject it. The body is one
        // byte over the cap and fully framed, so the server drains the input
        // and can deliver the 413 over a clean close.
        let stream = TcpStream::connect(addr).await.expect("connect");
        let (mut reader, mut writer) = stream.into_split();
        let token = token.to_string();
        let chunk = vec![b'x'; 64 * 1024];
        let writer_task = tokio::spawn(async move {
            writer
                .write_all(
                    format!(
                        "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .expect("write head");
            let mut remaining = MAX_HTTP_BODY + 1;
            while remaining > 0 {
                let take = remaining.min(chunk.len());
                let mut frame = format!("{take:x}\r\n").into_bytes();
                frame.extend_from_slice(&chunk[..take]);
                frame.extend_from_slice(b"\r\n");
                if let Err(error) = writer.write_all(&frame).await {
                    assert!(
                        matches!(
                            error.kind(),
                            std::io::ErrorKind::BrokenPipe
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                        ),
                        "unexpected chunk write failure: {error}"
                    );
                    return;
                }
                remaining -= take;
            }
            if let Err(error) = writer.write_all(b"0\r\n\r\n").await {
                assert!(
                    matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                    ),
                    "unexpected terminal chunk write failure: {error}"
                );
            }
        });
        let (status, _) = read_one_response(&mut reader).await;
        writer_task.await.expect("chunk writer task");
        assert_eq!(status, 413, "chunked oversized body must be rejected");

        handle.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_transport_rejects_malformed_requests() {
        let token = "malformed-token";
        let (addr, handle) = spawn_http_server(token).await;

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(b"this is not http\r\n\r\n")
            .await
            .expect("write garbage");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read response");
        let text = String::from_utf8_lossy(&raw);
        let status: u16 = text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .expect("status code");
        assert_eq!(status, 400, "malformed HTTP must be rejected");

        handle.abort();
    }
}
