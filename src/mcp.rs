use crate::injection::{collect_unique_pairs, derive_env_name};
use crate::server;
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const JSONRPC_VERSION: &str = "2.0";
const DEFAULT_TOOL_NAME: &str = "guard_run";
const VERB_LIST_TOOL_NAME: &str = "guard_verbs";
const APPROVAL_LIST_TOOL_NAME: &str = "guard_approvals";
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
            tool_name: DEFAULT_TOOL_NAME.to_string(),
            http_addr: None,
            http_token: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
struct GuardVerbArgs {
    name: String,
    #[serde(default)]
    params: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct GuardToolArgs {
    #[serde(default)]
    binary: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default)]
    secrets: Vec<String>,
    #[serde(default, rename = "secretEnv")]
    secret_env: HashMap<String, String>,
    // --- Consequence gating (optional) ---
    /// Rollback command for a recoverable action, as a single string.
    #[serde(default)]
    revert: Option<String>,
    #[serde(default, rename = "confirmWithin")]
    confirm_within: Option<u64>,
    #[serde(default, rename = "requireApproval")]
    require_approval: bool,
    #[serde(default, rename = "waitApproval")]
    wait_approval: Option<u64>,
    /// Invoke a catalog verb instead of a raw binary.
    #[serde(default)]
    verb: Option<GuardVerbArgs>,
    /// Skip the daemon's auto-learned deny-shape fast path and force a fresh
    /// LLM look at this one command. Never skips an operator-authored policy
    /// deny rule. Use this if an auto-learned shape over-blocked something
    /// that should be allowed.
    #[serde(default)]
    reevaluate: bool,
}

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
    fn admin_client(&self) -> server::Client {
        let mut client = server::Client::new(self.socket_path.clone(), self.tcp_port);
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
        let env = collect_unique_pairs(args.env, "environment variable injection", "value")
            .map_err(anyhow::Error::msg)?;
        let secrets = guard_tool_secret_map(&args.secrets, args.secret_env)?;

        let revert = match args.revert.as_deref() {
            Some(spec) => {
                let parts = shell_words::split(spec)
                    .map_err(|e| anyhow::anyhow!("invalid revert command: {}", e))?;
                let mut it = parts.into_iter();
                let binary = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("revert command is empty"))?;
                Some(server::RevertSpec {
                    binary,
                    args: it.collect(),
                })
            }
            None => None,
        };

        let mut client = server::Client::new(self.socket_path.clone(), self.tcp_port)
            .with_gating(
                revert,
                args.confirm_within,
                args.require_approval,
                args.wait_approval,
            )
            .with_reevaluate(args.reevaluate);
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
            .execute_with_injections(&args.binary, &args.args, env, secrets)
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
    let server = McpServer::new(executor.clone(), executor, config.tool_name);

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
            if let Err(error) = handle_http_connection(stream, server, &token).await {
                tracing::debug!(error = %error, "MCP HTTP connection ended with error");
            }
        });
    }
}

/// Serve a single HTTP/1.1 request on `stream` (we always close after one,
/// `Connection: close`). Auth is enforced before the body is dispatched.
async fn handle_http_connection<E: GuardExecutor, A: GuardAdmin>(
    mut stream: TcpStream,
    server: Arc<Mutex<McpServer<E, A>>>,
    token: &str,
) -> Result<()> {
    // Bound the time spent reading one request so a stalled (slowloris-style)
    // connection cannot hold a task open indefinitely before the bearer check.
    let request = match tokio::time::timeout(
        std::time::Duration::from_secs(15),
        read_http_request(&mut stream),
    )
    .await
    {
        Ok(Ok(request)) => request,
        Ok(Err(HttpError::Status(code, message))) => {
            return write_http_response(&mut stream, code, &error_body(&message)).await;
        }
        Ok(Err(HttpError::Io(error))) => return Err(error.into()),
        Err(_) => {
            return write_http_response(&mut stream, 408, &error_body("request timeout")).await;
        }
    };

    if request.method != "POST" {
        return write_http_response(
            &mut stream,
            405,
            &error_body("method not allowed; POST a JSON-RPC request"),
        )
        .await;
    }

    if !request.path_is_mcp_endpoint() {
        return write_http_response(&mut stream, 404, &error_body("not found")).await;
    }

    if !request.bearer_matches(token) {
        return write_http_response(
            &mut stream,
            401,
            &error_body("missing or invalid bearer token"),
        )
        .await;
    }

    let message: Value = match serde_json::from_slice(&request.body) {
        Ok(message) => message,
        Err(error) => {
            let payload =
                jsonrpc_error_response(Value::Null, -32700, format!("parse error: {error}"), None);
            return write_http_response(&mut stream, 400, &payload).await;
        }
    };

    let response = {
        let mut guard = server.lock().await;
        guard.handle_message(message).await
    };

    // A JSON-RPC notification (no id) produces no response value. The MCP
    // Streamable-HTTP shape answers such a POST with 202 Accepted and no body.
    match response {
        Some(response) => write_http_response(&mut stream, 200, &response).await,
        None => write_http_empty(&mut stream, 202).await,
    }
}

enum HttpError {
    /// A protocol-level rejection we answer with this status and message.
    Status(u16, String),
    Io(std::io::Error),
}

impl From<std::io::Error> for HttpError {
    fn from(error: std::io::Error) -> Self {
        HttpError::Io(error)
    }
}

struct HttpRequest {
    method: String,
    path: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn path_is_mcp_endpoint(&self) -> bool {
        let path = self.path.split('?').next().unwrap_or(&self.path);
        path == "/" || path == "/mcp"
    }

    /// Constant-time-ish bearer comparison: reject on length mismatch, then
    /// compare every byte without early exit so the check does not leak the
    /// token length or a prefix match through timing.
    fn bearer_matches(&self, expected: &str) -> bool {
        let Some(value) = self.authorization.as_deref() else {
            return false;
        };
        let Some(presented) = value
            .strip_prefix("Bearer ")
            .or_else(|| value.strip_prefix("bearer "))
        else {
            return false;
        };
        constant_time_eq(presented.as_bytes(), expected.as_bytes())
    }
}

/// Length-checked, branch-stable byte comparison. Returns false immediately on
/// a length mismatch (the lengths are not secret), then ORs every byte diff so
/// the loop runs to completion regardless of where the first mismatch is.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Read one HTTP/1.1 request: the request line, headers, and exactly
/// `Content-Length` body bytes. Headers are parsed case-insensitively. We bound
/// both the header section and the body so an unauthenticated peer cannot force
/// unbounded buffering.
/// Cap on the request header section (request line + headers). Combined with the
/// body cap, this bounds the total bytes an unauthenticated peer can make the
/// server buffer for one request, even via a single header line with no newline.
const MAX_HTTP_HEADER_SECTION: usize = 64 * 1024;

async fn read_http_request(stream: &mut TcpStream) -> std::result::Result<HttpRequest, HttpError> {
    // Bound the total bytes read for one request (header section + body): reads
    // past the limit return EOF and degrade to a 400, so a single connection
    // cannot force unbounded buffering before the bearer check.
    let mut reader = BufReader::new(stream).take((MAX_HTTP_HEADER_SECTION + MAX_HTTP_BODY) as u64);
    let mut request_line = String::new();
    let read = reader.read_line(&mut request_line).await?;
    if read == 0 {
        return Err(HttpError::Status(400, "empty request".to_string()));
    }

    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| HttpError::Status(400, "malformed request line".to_string()))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| HttpError::Status(400, "malformed request line".to_string()))?
        .to_string();

    let mut content_length: Option<usize> = None;
    let mut authorization: Option<String> = None;
    loop {
        let mut header = String::new();
        let read = reader.read_line(&mut header).await?;
        if read == 0 {
            return Err(HttpError::Status(
                400,
                "unexpected end of headers".to_string(),
            ));
        }
        let trimmed = header.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            return Err(HttpError::Status(400, "malformed header".to_string()));
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-length" => {
                let parsed: usize = value
                    .parse()
                    .map_err(|_| HttpError::Status(400, "invalid Content-Length".to_string()))?;
                if parsed > MAX_HTTP_BODY {
                    return Err(HttpError::Status(413, "request body too large".to_string()));
                }
                content_length = Some(parsed);
            }
            "authorization" => authorization = Some(value.to_string()),
            _ => {}
        }
    }

    let body = match content_length {
        Some(0) | None => Vec::new(),
        Some(len) => {
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).await?;
            buf
        }
    };

    Ok(HttpRequest {
        method,
        path,
        authorization,
        body,
    })
}

fn error_body(message: &str) -> Value {
    json!({ "error": message })
}

/// Write an HTTP/1.1 response with a JSON body, correct Content-Length, and
/// `Connection: close`.
async fn write_http_response(stream: &mut TcpStream, status: u16, body: &Value) -> Result<()> {
    let payload = serde_json::to_vec(body)?;
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n",
        status = status,
        reason = http_reason(status),
        len = payload.len(),
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(())
}

/// Write an HTTP/1.1 response with no body (used for 202 Accepted on a
/// JSON-RPC notification).
async fn write_http_empty(stream: &mut TcpStream, status: u16) -> Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\
         \r\n",
        status = status,
        reason = http_reason(status),
    );
    stream.write_all(head.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

fn http_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        _ => "Error",
    }
}

struct McpServer<E: GuardExecutor, A: GuardAdmin> {
    executor: Arc<E>,
    admin: Arc<A>,
    tool_name: String,
    initialize_seen: bool,
}

impl<E: GuardExecutor, A: GuardAdmin> McpServer<E, A> {
    fn new(executor: Arc<E>, admin: Arc<A>, tool_name: String) -> Self {
        Self {
            executor,
            admin,
            tool_name,
            initialize_seen: false,
        }
    }

    async fn handle_message(&mut self, message: Value) -> Option<Value> {
        let Some(object) = message.as_object() else {
            return Some(jsonrpc_error_response(
                Value::Null,
                -32600,
                "invalid request: JSON-RPC message must be an object".to_string(),
                None,
            ));
        };

        let id = object.get("id").cloned();
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            return Some(jsonrpc_error_response(
                id.unwrap_or(Value::Null),
                -32600,
                "invalid request: missing method".to_string(),
                None,
            ));
        };
        let params = object.get("params").cloned().unwrap_or(Value::Null);

        if let Some(id) = id {
            return self.handle_request(id, method, params).await;
        }

        self.handle_notification(method, params);
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
                    "description": "Execute a command through the guard daemon. The command is evaluated against security policy before execution. Plain environment overrides and named secret references are optional; secret values are resolved by the daemon and never exposed to the client.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "binary": {
                                "type": "string",
                                "description": "Binary to execute (e.g. ssh, kubectl, helm, aws)."
                            },
                            "args": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Arguments to pass to the binary."
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
                            "verb": {
                                "type": "object",
                                "description": "Optional: invoke an operator-defined verb instead of a raw binary. Provide name and params; the daemon renders the typed template.",
                                "properties": {
                                    "name": { "type": "string" },
                                    "params": { "type": "object", "additionalProperties": { "type": "string" } }
                                },
                                "required": ["name"]
                            },
                            "revert": {
                                "type": "string",
                                "description": "Optional rollback command (single string) for a recoverable action under consequence gating. It is policy-evaluated before the action is armed."
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
                                "type": "integer",
                                "description": "Optional: block up to N seconds for an operator decision on a held command and return the real result inline."
                            },
                            "reevaluate": {
                                "type": "boolean",
                                "description": "Optional: skip the daemon's auto-learned deny-shape fast path and force a fresh policy look at this one command. Never skips an operator-authored deny rule. Use this if you believe an auto-learned shape over-blocked something that should be allowed."
                            }
                        },
                        "required": ["binary", "args"]
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
}

fn render_verbs_text(items: &[server::VerbSummary]) -> String {
    if items.is_empty() {
        return "(no verbs configured)".to_string();
    }
    let mut lines = Vec::with_capacity(items.len());
    for v in items {
        let mut line = format!(
            "{} [{}]{}{} — {}",
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

#[derive(Debug, Deserialize)]
struct ToolCallParams {
    name: String,
    #[serde(default)]
    arguments: Value,
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

    // Consequence-gate outcomes are not denials: surface the handle, the next
    // step, and the honest coverage so the model knows what was NOT verified.
    match status {
        Some("held") => {
            return format!(
                "HELD for operator approval (handle {handle}): {reason}\nThe operator must run `guard approve {handle}` for this to execute. Do not retry; wait or proceed with other work.{}",
                coverage_text(result)
            );
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
        return format!("DENIED: {reason}");
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
        // Approved, exit 0, no stdout, no stderr — produce something
        // non-empty so the MCP transport doesn't return a blank value.
        return "(no output)".to_string();
    }
    sections.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

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
        assert_eq!(
            response["result"]["tools"][0]["inputSchema"]["required"],
            json!(["binary", "args"])
        );
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
        });

        assert_eq!(value["isError"], false);
        assert_eq!(value["structuredContent"]["allowed"], false);
        assert_eq!(value["content"][0]["text"], "DENIED: policy denied");
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
            }),
        });
        let admin = Arc::new(FakeAdmin {
            response: server::AdminResponse::Verbs {
                items: vec![server::VerbSummary {
                    name: "drain-node".to_string(),
                    description: "cordon and drain a node".to_string(),
                    binary: "kubectl".to_string(),
                    consequence: "recoverable".to_string(),
                    trusted: true,
                    has_revert: true,
                    params: std::collections::BTreeMap::new(),
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
            }),
        });
        let mut server = McpServer::new(executor, empty_admin(), DEFAULT_TOOL_NAME.to_string());
        // The HTTP server shares the same initialize gate; pre-seed it so a raw
        // POST of tools/list does not need the full handshake for this test.
        server.initialize_seen = true;
        server
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
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let token_for_task = token.clone();
        let handle = tokio::spawn(async move {
            // Inline a one-connection-at-a-time accept loop mirroring serve_http,
            // so the test exercises the real connection handler and auth path.
            let server = Arc::new(Mutex::new(http_test_server()));
            let token = Arc::new(token_for_task);
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(_) => break,
                };
                let server = server.clone();
                let token = token.clone();
                tokio::spawn(async move {
                    let _ = handle_http_connection(stream, server, &token).await;
                });
            }
        });

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
}
