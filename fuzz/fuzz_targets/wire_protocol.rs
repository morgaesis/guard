#![no_main]

//! Fuzz the daemon's primary untrusted input: the JSON wire protocol any
//! socket client can send. Exercises `ExecuteRequest`/`BatchCommand`
//! deserialization, the binary-name validator, and the ssh host-key option
//! injection, and checks that an accepted request round-trips through serde.

use guard::wire::{validate_args, validate_binary_name, BatchCommand, ExecuteRequest};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(mut request) = serde_json::from_str::<ExecuteRequest>(text) {
        let _ = validate_binary_name(&request.binary);
        let _ = validate_args(&request.args);
        request.apply_ssh_hostkey_options();

        // An accepted request must survive a serialize/deserialize round trip:
        // the daemon logs, audits, and forwards these values.
        let serialized =
            serde_json::to_string(&request).expect("accepted ExecuteRequest must serialize");
        let _reparsed: ExecuteRequest = serde_json::from_str(&serialized)
            .expect("serialized ExecuteRequest must reparse");
    }

    if let Ok(batch) = serde_json::from_str::<BatchCommand>(text) {
        let _ = validate_binary_name(&batch.binary);
        let _ = validate_args(&batch.args);
    }
});
