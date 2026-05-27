use crate::injection::{collect_unique_pairs, derive_env_name};
use crate::server;
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};

const JSONRPC_VERSION: &str = "2.0";
const DEFAULT_TOOL_NAME: &str = "guard_run";
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-03-26", "2024-11-05"];

#[derive(Clone, Debug)]
pub struct McpConfig {
    pub socket_path: Option<PathBuf>,
    pub tcp_port: Option<u16>,
    pub auth_token: Option<String>,
    pub tool_name: String,
}

impl McpConfig {
    pub fn validate(&self) -> Result<()> {
        if self.socket_path.is_none() && self.tcp_port.is_none() {
            bail!("no guard server configured for MCP (set a socket or TCP port)");
        }

        if self.tool_name.trim().is_empty() {
            bail!("MCP tool name cannot be empty");
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
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct GuardToolArgs {
    binary: String,
    args: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default)]
    secrets: Vec<String>,
    #[serde(default, rename = "secretEnv")]
    secret_env: HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct GuardToolResponse {
    allowed: bool,
    reason: String,
    exit_code: Option<i32>,
    stdout: Option<String>,
    stderr: Option<String>,
}

impl From<server::ExecuteResponse> for GuardToolResponse {
    fn from(response: server::ExecuteResponse) -> Self {
        Self {
            allowed: response.allowed,
            reason: response.reason,
            exit_code: response.exit_code,
            stdout: response.stdout,
            stderr: response.stderr,
        }
    }
}

#[async_trait]
trait GuardExecutor: Send + Sync {
    async fn execute(&self, args: GuardToolArgs) -> Result<GuardToolResponse>;
}

#[derive(Clone)]
struct ClientExecutor {
    socket_path: Option<PathBuf>,
    tcp_port: Option<u16>,
    auth_token: Option<String>,
}

#[async_trait]
impl GuardExecutor for ClientExecutor {
    async fn execute(&self, args: GuardToolArgs) -> Result<GuardToolResponse> {
        let env = collect_unique_pairs(args.env, "environment variable injection", "value")
            .map_err(anyhow::Error::msg)?;
        let secrets = guard_tool_secret_map(&args.secrets, args.secret_env)?;
        let client = if let Some(token) = &self.auth_token {
            server::Client::new(self.socket_path.clone(), self.tcp_port).with_auth(token.clone())
        } else {
            server::Client::new(self.socket_path.clone(), self.tcp_port)
        };

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
    let mut server = McpServer::new(executor, config.tool_name);

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

struct McpServer<E: GuardExecutor> {
    executor: Arc<E>,
    tool_name: String,
    initialize_seen: bool,
}

impl<E: GuardExecutor> McpServer<E> {
    fn new(executor: Arc<E>, tool_name: String) -> Self {
        Self {
            executor,
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
                if tool_call.name != self.tool_name {
                    jsonrpc_error_response(
                        id,
                        -32601,
                        format!("unknown tool '{}'", tool_call.name),
                        None,
                    )
                } else {
                    let result = self.call_tool(tool_call.arguments).await;
                    jsonrpc_result_response(id, result)
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
                            "stderr": { "type": ["string", "null"] }
                        },
                        "required": ["allowed", "reason", "exit_code", "stdout", "stderr"]
                    },
                    "annotations": {
                        "readOnlyHint": false,
                        "destructiveHint": true,
                        "idempotentHint": false,
                        "openWorldHint": true
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
        "stderr": result.stderr
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

    #[tokio::test]
    async fn initialize_advertises_tools_capability() {
        let executor = Arc::new(FakeExecutor {
            response: Ok(GuardToolResponse {
                allowed: true,
                reason: "ok".to_string(),
                exit_code: Some(0),
                stdout: Some("ok\n".to_string()),
                stderr: None,
            }),
        });
        let mut server = McpServer::new(executor, DEFAULT_TOOL_NAME.to_string());

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
            }),
        });
        let mut server = McpServer::new(executor, DEFAULT_TOOL_NAME.to_string());
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
            }),
        });
        let mut server = McpServer::new(executor, DEFAULT_TOOL_NAME.to_string());
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
        let mut server = McpServer::new(executor, DEFAULT_TOOL_NAME.to_string());
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
            }),
        });
        let mut server = McpServer::new(executor, DEFAULT_TOOL_NAME.to_string());

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
}
