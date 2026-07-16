//! Untrusted MCP request parsing: the JSON-RPC envelope and the typed tool
//! argument shapes an MCP client can send. Lives in the library crate so the
//! parsing surface can be fuzzed; the MCP server (`src/mcp.rs`) consumes these
//! types directly.

use super::{BatchCommand, SshHostKeyMode};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

/// A parsed JSON-RPC message: request when `id` is present, notification
/// otherwise.
#[derive(Debug, Clone)]
pub struct JsonRpcEnvelope {
    pub id: Option<Value>,
    pub method: String,
    pub params: Value,
}

/// Envelope-level rejection, carrying the id (when one was readable) so the
/// error response can echo it per JSON-RPC.
#[derive(Debug, Clone)]
pub enum JsonRpcEnvelopeError {
    NotAnObject,
    MissingMethod { id: Option<Value> },
}

/// Extract id/method/params from a JSON-RPC message. Matches the daemon's
/// tolerance exactly: any JSON object with a string `method` is accepted;
/// `params` defaults to null.
pub fn parse_jsonrpc_envelope(message: &Value) -> Result<JsonRpcEnvelope, JsonRpcEnvelopeError> {
    let Some(object) = message.as_object() else {
        return Err(JsonRpcEnvelopeError::NotAnObject);
    };
    let id = object.get("id").cloned();
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return Err(JsonRpcEnvelopeError::MissingMethod { id });
    };
    Ok(JsonRpcEnvelope {
        id,
        method: method.to_string(),
        params: object.get("params").cloned().unwrap_or(Value::Null),
    })
}

/// `tools/call` params: tool name plus its free-form arguments.
#[derive(Debug, Deserialize)]
pub struct ToolCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct GuardVerbArgs {
    pub name: String,
    #[serde(default)]
    pub params: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum McpSshHostKeyMode {
    OnlyExisting,
    AcceptNew,
    AcceptAll,
}

impl From<McpSshHostKeyMode> for SshHostKeyMode {
    fn from(value: McpSshHostKeyMode) -> Self {
        match value {
            McpSshHostKeyMode::OnlyExisting => Self::OnlyExisting,
            McpSshHostKeyMode::AcceptNew => Self::AcceptNew,
            McpSshHostKeyMode::AcceptAll => Self::AcceptAll,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct GuardToolArgs {
    #[serde(default)]
    pub binary: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub secrets: Vec<String>,
    #[serde(default, rename = "secretEnv")]
    pub secret_env: HashMap<String, String>,
    #[serde(default, rename = "secretFiles")]
    pub secret_files: HashMap<String, String>,
    // --- Consequence gating (optional) ---
    /// Rollback command for a recoverable action, as a single string.
    #[serde(default)]
    pub revert: Option<String>,
    #[serde(default, rename = "confirmCheck")]
    pub confirm_check: Option<String>,
    #[serde(default, rename = "revertControlPath")]
    pub revert_control_path: Option<String>,
    #[serde(default, rename = "confirmWithin")]
    pub confirm_within: Option<u64>,
    #[serde(default, rename = "requireApproval")]
    pub require_approval: bool,
    #[serde(default, rename = "waitApproval")]
    pub wait_approval: Option<WaitApproval>,
    /// Invoke a catalog verb instead of a raw binary.
    #[serde(default)]
    pub verb: Option<GuardVerbArgs>,
    /// Skip the daemon's auto-learned deny-shape fast path and force a fresh
    /// LLM look at this one command. Never skips an operator-authored policy
    /// deny rule. Use this if an auto-learned shape over-blocked something
    /// that should be allowed.
    #[serde(default)]
    pub reevaluate: bool,
    /// SSH host-key policy for a guarded `ssh` command. Defaults to
    /// only-existing (ssh's strict checking) when omitted.
    #[serde(default)]
    pub hostkey: Option<McpSshHostKeyMode>,
}

/// `waitApproval` accepts a boolean or an integer so the MCP argument mirrors
/// the CLI's `--wait-approval [SECONDS|unbounded]`: `true` is the bare flag
/// (unbounded wait), an integer bounds the wait in seconds, and `false` is the
/// same as omitting the argument.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum WaitApproval {
    Flag(bool),
    Seconds(u64),
}

impl WaitApproval {
    /// Convert to the wire representation the daemon expects: seconds to
    /// wait, with `u64::MAX` meaning unbounded (identical to the CLI flag).
    pub fn into_secs(self) -> Option<u64> {
        match self {
            WaitApproval::Flag(true) => Some(u64::MAX),
            WaitApproval::Flag(false) => None,
            WaitApproval::Seconds(secs) => Some(secs),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct EvaluateBatchArgs {
    #[serde(default)]
    pub session: Option<String>,
    pub commands: Vec<BatchCommand>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionStatusArgs {
    pub session: String,
}
