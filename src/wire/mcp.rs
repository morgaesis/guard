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
    Invalid {
        id: Option<Value>,
        message: &'static str,
    },
}

/// Validate and extract one MCP JSON-RPC 2.0 request or notification.
pub fn parse_jsonrpc_envelope(message: &Value) -> Result<JsonRpcEnvelope, JsonRpcEnvelopeError> {
    let Some(object) = message.as_object() else {
        return Err(JsonRpcEnvelopeError::NotAnObject);
    };
    let id = object.get("id").cloned();
    if object.get("jsonrpc") != Some(&Value::String("2.0".to_string())) {
        return Err(JsonRpcEnvelopeError::Invalid {
            id,
            message: "jsonrpc must equal \"2.0\"",
        });
    }
    if let Some(value) = id.as_ref() {
        let valid = match value {
            Value::String(_) => true,
            Value::Number(number) => number.is_i64() || number.is_u64(),
            _ => false,
        };
        if !valid {
            return Err(JsonRpcEnvelopeError::Invalid {
                id: None,
                message: "id must be a string or integer",
            });
        }
    }
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return Err(JsonRpcEnvelopeError::Invalid {
            id,
            message: "missing method",
        });
    };
    let params = object.get("params").cloned().unwrap_or(Value::Null);
    if !params.is_null() && !params.is_object() {
        return Err(JsonRpcEnvelopeError::Invalid {
            id,
            message: "params must be an object when present",
        });
    }
    Ok(JsonRpcEnvelope {
        id,
        method: method.to_string(),
        params,
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
pub struct AccessShowArgs {
    pub reference: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn jsonrpc_envelope_requires_mcp_jsonrpc_shapes() {
        for invalid in [
            json!({"jsonrpc": "1.0", "id": 1, "method": "initialize"}),
            json!({"jsonrpc": "2.0", "id": null, "method": "initialize"}),
            json!({"jsonrpc": "2.0", "id": 1.5, "method": "initialize"}),
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": []}),
            json!({"jsonrpc": "2.0", "id": 1}),
        ] {
            assert!(parse_jsonrpc_envelope(&invalid).is_err(), "{invalid}");
        }

        let notification = parse_jsonrpc_envelope(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }))
        .expect("valid notification");
        assert!(notification.id.is_none());
    }
}
