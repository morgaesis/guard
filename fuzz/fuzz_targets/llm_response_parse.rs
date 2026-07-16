#![no_main]

//! Fuzz the evaluator's provider-response parser: semi-trusted LLM output
//! that steers allow/deny decisions. Covers both OpenAI-compatible shapes
//! (tool call and JSON content) plus the structural error summaries.

use guard::evaluate::fuzzing::{
    parse_decision_response, provider_error_summary, response_shape_summary,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&flag, payload)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(payload) else {
        return;
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };

    let prefer_function_calling = flag & 1 == 1;
    let _ = parse_decision_response(&parsed, prefer_function_calling);
    let _ = response_shape_summary(&parsed);
    let _ = provider_error_summary(&parsed);
});
