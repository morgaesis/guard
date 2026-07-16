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
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

const JSONRPC_VERSION: &str = "2.0";
const DEFAULT_TOOL_NAME: &str = "guard_run";
const VERB_LIST_TOOL_NAME: &str = "guard_verbs";
const APPROVAL_LIST_TOOL_NAME: &str = "guard_approvals";
const EVALUATE_BATCH_TOOL_NAME: &str = "guard_evaluate_batch";
const SESSION_STATUS_TOOL_NAME: &str = "guard_session_status";
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-03-26", "2024-11-05"];

/// Cap the HTTP request body we will buffer. The MCP request payloads are
/// small JSON-RPC envelopes; this bounds the memory a single connection can
/// force us to allocate from an unauthenticated peer before the bearer check.
const MAX_HTTP_BODY: usize = 1024 * 1024;

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

        if self.tool_name.trim().is_empty() {
            bail!("MCP tool name cannot be empty");
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
                "--http requires a bearer token (set --http-token or GUARD_MCP_TOKEN); \
                 refusing to start an unauthenticated network MCP server"
            );
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
    parse_jsonrpc_envelope, EvaluateBatchArgs, GuardToolArgs, JsonRpcEnvelopeError,
    SessionStatusArgs, ToolCallParams, WaitApproval,
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
    /// Handle for a held/provisional command (use with guard approve/confirm).
    handle: Option<String>,
    /// Honest statement of what the gate checked and did not check.
    coverage: Option<guard::gating::Coverage>,
    verb_matches: Vec<server::VerbMatchInfo>,
    guidance: Option<String>,
    decision_source: String,
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
}

impl ClientExecutor {
    /// Build a bare daemon client carrying only the connection details and the
    /// optional TCP auth token. Used for read-only admin RPCs that the catalog
    /// and approval tools proxy.
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
    });
    let server = McpServer::new(executor.clone(), executor, config.tool_name)
        .with_caller_token(config.session_token);

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

/// Minimal MCP Streamable-HTTP transport: a single POST endpoint that pipes the
/// JSON-RPC body through the same request handler the stdio path uses. Every
/// request must carry `Authorization: Bearer <token>`; there is no server-side
/// SSE streaming. The handler is shared behind a Mutex because MCP keeps a
/// little session state (the initialize handshake) and clients are expected to
/// drive one logical session.
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
        tracing::warn!(
            address = %bound,
            "MCP HTTP transport bound to a non-loopback address; it is intended for \
             localhost or trusted networks only and authenticates with a single bearer token"
        );
    }
    tracing::info!(address = %bound, "MCP HTTP transport listening");

    serve_http_on(listener, server, token).await
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
    let server = Arc::new(Mutex::new(server));
    let token = Arc::new(token);

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
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let server = server.clone();
                let token = token.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(
                        handle_http_request(request, &server, &token).await,
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
    server: &Mutex<McpServer<E, A>>,
    token: &str,
) -> Response<Full<Bytes>> {
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

    if request.method() != Method::POST {
        return http_error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed; POST a JSON-RPC request",
        );
    }

    if !path_is_mcp_endpoint(request.uri().path()) {
        return http_error_response(StatusCode::NOT_FOUND, "not found");
    }

    if !bearer_matches(request.headers(), token) {
        return http_error_response(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
    }

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

    let response = {
        let mut guard = server.lock().await;
        guard.handle_message(message).await
    };

    // A JSON-RPC notification (no id) produces no response value. The MCP
    // Streamable-HTTP shape answers such a POST with 202 Accepted and no body.
    match response {
        Some(response) => json_response(StatusCode::OK, &response),
        None => empty_response(StatusCode::ACCEPTED),
    }
}

fn path_is_mcp_endpoint(path: &str) -> bool {
    path == "/" || path == "/mcp"
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
    let payload = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
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
    initialize_seen: bool,
    caller_token: Option<String>,
}

impl<E: GuardExecutor, A: GuardAdmin> McpServer<E, A> {
    fn new(executor: Arc<E>, admin: Arc<A>, tool_name: String) -> Self {
        Self {
            executor,
            admin,
            tool_name,
            initialize_seen: false,
            caller_token: None,
        }
    }

    fn with_caller_token(mut self, caller_token: Option<String>) -> Self {
        self.caller_token = caller_token.filter(|token| !token.is_empty());
        self
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
            Err(JsonRpcEnvelopeError::MissingMethod { id }) => {
                return Some(jsonrpc_error_response(
                    id.unwrap_or(Value::Null),
                    -32600,
                    "invalid request: missing method".to_string(),
                    None,
                ));
            }
        };

        if let Some(id) = envelope.id {
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
                if tool_call.name == self.tool_name {
                    let result = self.call_tool(tool_call.arguments).await;
                    jsonrpc_result_response(id, result)
                } else if tool_call.name == VERB_LIST_TOOL_NAME {
                    let result = self.call_verb_list().await;
                    jsonrpc_result_response(id, result)
                } else if tool_call.name == APPROVAL_LIST_TOOL_NAME {
                    let result = self.call_approval_list().await;
                    jsonrpc_result_response(id, result)
                } else if tool_call.name == EVALUATE_BATCH_TOOL_NAME {
                    let result = self.call_evaluate_batch(tool_call.arguments).await;
                    jsonrpc_result_response(id, result)
                } else if tool_call.name == SESSION_STATUS_TOOL_NAME {
                    let result = self.call_session_status(tool_call.arguments).await;
                    jsonrpc_result_response(id, result)
                } else {
                    jsonrpc_error_response(
                        id,
                        -32601,
                        format!("unknown tool '{}'", tool_call.name),
                        None,
                    )
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
        json!({
            "tools": [
                {
                    "name": self.tool_name,
                    "title": "Run Command Through Guard",
                    "description": "Execute a command through the guard daemon. Provide binary (with optional args) for a raw command, or verb for a catalog verb invocation; one of the two is required. The command is evaluated against security policy before execution. Plain environment overrides and named secret references are optional; secret values are resolved by the daemon and never exposed to the client.",
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
                            "allowed": { "type": "boolean" },
                            "reason": { "type": "string" },
                            "exit_code": { "type": ["integer", "null"] },
                            "stdout": { "type": ["string", "null"] },
                            "stderr": { "type": ["string", "null"] },
                            "status": { "type": ["string", "null"], "description": "Consequence-gate outcome: executed, provisional, held, reverted, dry_run." },
                            "handle": { "type": ["string", "null"], "description": "Handle for a held/provisional command (use with guard approve/confirm)." },
                            "coverage": { "type": ["object", "null"], "description": "What the gate checked and deliberately did NOT check (checked / not_checked arrays). Surfaced for held/provisional/dry-run outcomes." }
                        },
                        "required": ["allowed", "reason", "exit_code", "stdout", "stderr"]
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
                    "annotations": {
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false
                    }
                },
                {
                    "name": APPROVAL_LIST_TOOL_NAME,
                    "title": "List Held and Provisional Approvals",
                    "description": "List the caller's held approvals and provisional (auto-revert) executions, scoped to the caller by the daemon. Use to poll whether an operator has approved a held command or to see provisionals still inside their revert window. Read-only; it does not approve, confirm, or run anything.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": false
                    },
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
                    "annotations": {
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": true
                    }
                },
                {
                    "name": SESSION_STATUS_TOOL_NAME,
                    "title": "Show Session Status",
                    "description": "Show the caller's live grant, escalations, holds, and provisionals for one session token.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "session": { "type": "string" } },
                        "required": ["session"]
                    },
                    "annotations": {
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false
                    }
                }
            ]
        })
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
                admin_tool_result(render_verbs_text(&items), structured)
            }
            Ok(server::AdminResponse::Error { message }) => tool_error_result(message),
            Ok(_) => tool_error_result("unexpected response from guard daemon".to_string()),
            Err(error) => tool_error_result(format!("{error:#}")),
        }
    }

    /// Proxy AdminRequest::ApprovalList: surface the caller's held approvals.
    /// The daemon scopes the list to the caller; this path never approves,
    /// confirms, or executes anything.
    async fn call_approval_list(&self) -> Value {
        match self
            .admin
            .send_admin(server::AdminRequest::ApprovalList)
            .await
        {
            Ok(server::AdminResponse::Approvals { items }) => {
                let structured = json!({ "approvals": items });
                admin_tool_result(render_approvals_text(&items), structured)
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
                admin_tool_result(text, json!({ "items": items }))
            }
            Ok(server::AdminResponse::Error { message }) => tool_error_result(message),
            Ok(_) => tool_error_result("unexpected response from guard daemon".to_string()),
            Err(error) => tool_error_result(format!("{error:#}")),
        }
    }

    async fn call_session_status(&self, arguments: Value) -> Value {
        let args: SessionStatusArgs = match serde_json::from_value(arguments) {
            Ok(args) => args,
            Err(error) => return tool_error_result(format!("invalid tool arguments: {error}")),
        };
        match self
            .admin
            .send_admin(server::AdminRequest::SessionStatus {
                token: args.session,
                caller_token: self.caller_token.clone(),
            })
            .await
        {
            Ok(server::AdminResponse::SessionStatus {
                report,
                approvals,
                provisionals,
                requests,
            }) => admin_tool_result(
                format!(
                    "active={} approvals={} provisionals={} grant_requests={}",
                    report.active.is_some(),
                    approvals.len(),
                    provisionals.len(),
                    requests.len()
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

fn render_approvals_text(items: &[server::ApprovalSummary]) -> String {
    if items.is_empty() {
        return "(no held or provisional approvals)".to_string();
    }
    items
        .iter()
        .map(|a| {
            format!(
                "[{}] handle={} cmd={:?} risk={:?} class={:?} reason={:?}",
                a.status, a.handle, a.command, a.risk, a.reversibility, a.reason
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Wrap a read-only admin proxy result in the MCP tool-result envelope. These
/// are never daemon errors (those go through `tool_error_result`), so
/// `isError` is false.
fn admin_tool_result(text: String, structured: Value) -> Value {
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
    let structured = json!({
        "allowed": result.allowed,
        "reason": result.reason,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "status": result.status,
        "handle": result.handle,
        "coverage": result.coverage
        ,"verb_matches": result.verb_matches
        ,"guidance": result.guidance
        ,"decision_source": result.decision_source
    });

    json!({
        "content": [
            {
                "type": "text",
                "text": render_tool_text(&structured)
            }
        ],
        "structuredContent": structured,
        "isError": false
    })
}

fn tool_error_result(message: String) -> Value {
    let structured = json!({
        "allowed": false,
        "reason": message,
        "exit_code": Value::Null,
        "stdout": Value::Null,
        "stderr": Value::Null
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
    let guidance = result
        .get("guidance")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("\nGuidance: {value}"))
        .unwrap_or_default();
    let decision = decision_text(result);

    // Consequence-gate outcomes are not denials: surface the handle, the next
    // step, and the honest coverage so the model knows what was NOT verified.
    match status {
        Some("held") => {
            return format!(
                "HELD for operator approval (handle {handle}): {reason}\nThe operator must run `guard approve {handle}` for this to execute. Do not retry; wait or proceed with other work.{}",
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
            return out;
        }
        Some("dry_run") => {
            return format!("[DRY-RUN] {reason}{}", coverage_text(result));
        }
        _ => {}
    }

    if !allowed {
        return format!("DENIED: {reason}{decision}{guidance}");
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
    use tokio::io::AsyncReadExt;
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
    async fn session_status_sends_mcp_owned_session_separately_from_target() {
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
                    "name": SESSION_STATUS_TOOL_NAME,
                    "arguments": { "session": "requested-target" }
                }
            }))
            .await
            .unwrap();
        assert!(matches!(
            recorded.lock().unwrap().as_ref(),
            Some(server::AdminRequest::SessionStatus {
                token: target,
                caller_token: Some(owner),
            }) if target == "requested-target" && owner == "mcp-owner"
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
        };
        let args: GuardToolArgs = serde_json::from_value(json!({})).unwrap();
        let error = executor.execute(args).await.unwrap_err();
        assert!(
            error.to_string().contains("`binary` or `verb`"),
            "unexpected error: {error:#}"
        );
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
    async fn tools_list_includes_catalog_and_approval_tools() {
        let executor = Arc::new(FakeExecutor {
            response: Ok(GuardToolResponse {
                allowed: true,
                reason: "ok".to_string(),
                exit_code: Some(0),
                stdout: None,
                stderr: None,
                status: None,
                handle: None,
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

        assert!(names.contains(&DEFAULT_TOOL_NAME));
        assert!(names.contains(&VERB_LIST_TOOL_NAME));
        assert!(names.contains(&APPROVAL_LIST_TOOL_NAME));
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
            response["result"]["structuredContent"]["verbs"][0]["name"],
            "drain-node"
        );
    }

    #[tokio::test]
    async fn approval_list_tool_proxies_daemon_approvals() {
        let executor = Arc::new(FakeExecutor {
            response: Ok(GuardToolResponse {
                allowed: true,
                reason: "ok".to_string(),
                exit_code: Some(0),
                stdout: None,
                stderr: None,
                status: None,
                handle: None,
                coverage: None,
                verb_matches: Vec::new(),
                guidance: None,
                decision_source: "static_policy".to_string(),
            }),
        });
        let admin = Arc::new(FakeAdmin {
            response: server::AdminResponse::Approvals { items: vec![] },
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
        assert!(response["result"]["structuredContent"]["approvals"]
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
                coverage: None,
                verb_matches: Vec::new(),
                guidance: None,
                decision_source: "static_policy".to_string(),
            }),
        });
        let mut server = McpServer::new(executor, empty_admin(), DEFAULT_TOOL_NAME.to_string());
        // The HTTP server shares the same initialize gate; pre-seed it so a raw
        // POST of tools/list does not need the full handshake for this test.
        server.initialize_seen = true;
        server
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
    async fn read_one_response(stream: &mut TcpStream) -> (u16, String) {
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
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// Drive one raw HTTP request against an ephemeral-port HTTP MCP server and
    /// return the parsed status line + body string.
    async fn http_roundtrip(
        addr: SocketAddr,
        authorization: Option<&str>,
        json_body: &str,
    ) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let mut request = format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            json_body.len()
        );
        if let Some(auth) = authorization {
            request.push_str(&format!("Authorization: {auth}\r\n"));
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

    #[tokio::test(flavor = "multi_thread")]
    async fn http_transport_enforces_bearer_and_serves_tools_list() {
        let token = "test-bearer-token".to_string();
        let (addr, handle) = spawn_http_server(&token).await;

        let list_body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;

        // No Authorization header -> 401, no JSON-RPC result.
        let (status, body) = http_roundtrip(addr, None, list_body).await;
        assert_eq!(status, 401, "missing token must be rejected");
        assert!(
            !body.contains("\"result\""),
            "401 body must not leak a result"
        );

        // Wrong token -> 401.
        let (status, _) = http_roundtrip(addr, Some("Bearer wrong-token"), list_body).await;
        assert_eq!(status, 401, "wrong token must be rejected");

        // Correct token -> 200 + a valid JSON-RPC result listing tools.
        let auth = format!("Bearer {token}");
        let (status, body) = http_roundtrip(addr, Some(&auth), list_body).await;
        assert_eq!(status, 200, "valid token must be accepted");
        let parsed: Value = serde_json::from_str(&body).expect("body is JSON");
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["id"], 1);
        let names: Vec<&str> = parsed["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert!(names.contains(&DEFAULT_TOOL_NAME));
        assert!(names.contains(&VERB_LIST_TOOL_NAME));
        assert!(names.contains(&APPROVAL_LIST_TOOL_NAME));

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
    async fn http_transport_serves_sequential_requests_on_one_connection() {
        let token = "keepalive-token";
        let (addr, handle) = spawn_http_server(token).await;

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        for id in 1..=2 {
            let body = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#);
            let request = format!(
                "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
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

        let body = r#"{"jsonrpc":"2.0","id":11,"method":"ping"}"#;
        let (first, second) = body.split_at(10);
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{first}\r\n{:x}\r\n{second}\r\n0\r\n\r\n",
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
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(
                format!(
                    "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("write head");
        let chunk = vec![b'x'; 64 * 1024];
        let mut remaining = MAX_HTTP_BODY + 1;
        while remaining > 0 {
            let take = remaining.min(chunk.len());
            stream
                .write_all(format!("{take:x}\r\n").as_bytes())
                .await
                .expect("write chunk size");
            stream
                .write_all(&chunk[..take])
                .await
                .expect("write chunk data");
            stream.write_all(b"\r\n").await.expect("write chunk end");
            remaining -= take;
        }
        stream
            .write_all(b"0\r\n\r\n")
            .await
            .expect("write terminal chunk");
        let (status, _) = read_one_response(&mut stream).await;
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
