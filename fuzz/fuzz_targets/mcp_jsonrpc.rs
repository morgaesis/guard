#![no_main]

//! Fuzz the MCP server's untrusted input: JSON-RPC envelope extraction and
//! the typed tool-argument shapes (`tools/call` params, guard_run arguments,
//! batch evaluation, and access inspection).

use guard::wire::mcp::{
    parse_jsonrpc_envelope, AccessShowArgs, EvaluateBatchArgs, GuardToolArgs, ToolCallParams,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(message) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };

    let Ok(envelope) = parse_jsonrpc_envelope(&message) else {
        return;
    };

    if let Ok(call) = serde_json::from_value::<ToolCallParams>(envelope.params.clone()) {
        let _ = serde_json::from_value::<GuardToolArgs>(call.arguments.clone());
        let _ = serde_json::from_value::<EvaluateBatchArgs>(call.arguments.clone());
        let _ = serde_json::from_value::<AccessShowArgs>(call.arguments);
    }

    // Clients also send malformed params directly; every typed shape must
    // reject them without panicking.
    let _ = serde_json::from_value::<GuardToolArgs>(envelope.params.clone());
    let _ = serde_json::from_value::<EvaluateBatchArgs>(envelope.params.clone());
    let _ = serde_json::from_value::<AccessShowArgs>(envelope.params);
});
