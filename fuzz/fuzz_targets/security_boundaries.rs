#![no_main]

use guard::policy::PolicyEngine;
use guard::proxy::k8s::{parse_api_op, redact_secret_response};
use guard::proxy::validate_brokered_kubeconfig;
use guard::redact::{redact_output_text, redact_output_with_state, RedactionState};
use libfuzzer_sys::fuzz_target;

const FIELD_SEPARATOR: &str = "\n===\n";

fuzz_target!(|data: &[u8]| {
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(payload) else {
        return;
    };

    match selector {
        b'P' => fuzz_policy(text),
        b'R' => fuzz_redaction(text),
        b'K' => fuzz_kubernetes(text),
        b'C' => fuzz_kubeconfig(text),
        _ => match selector % 4 {
            0 => fuzz_policy(text),
            1 => fuzz_redaction(text),
            2 => fuzz_kubernetes(text),
            _ => fuzz_kubeconfig(text),
        },
    }
});

fn fuzz_policy(text: &str) {
    let (yaml, command) = text.split_once(FIELD_SEPARATOR).unwrap_or((text, ""));
    if let Ok(engine) = PolicyEngine::load_yaml(yaml) {
        let _ = engine.check(command);
        let _ = engine.check_deny_fast_path(command);
    }
}

fn fuzz_redaction(text: &str) {
    let _ = redact_output_text(text);

    let mut state = RedactionState::default();
    for line in text.lines() {
        let _ = redact_output_with_state(line, &mut state);
    }

    if let Ok(mut value) = serde_json::from_str(text) {
        let _ = redact_secret_response(&mut value);
    }
}

fn fuzz_kubernetes(text: &str) {
    let mut fields = text.splitn(3, FIELD_SEPARATOR);
    let method = fields.next().unwrap_or_default();
    let path = fields.next().unwrap_or_default();
    let query = fields.next().unwrap_or_default();
    let _ = parse_api_op(method, path, query);
}

fn fuzz_kubeconfig(text: &str) {
    let _ = validate_brokered_kubeconfig(text);
}
