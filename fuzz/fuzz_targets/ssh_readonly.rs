#![no_main]

//! Fuzz the ssh option fast-path parsers that grant a deterministic pre-LLM
//! allow. A parsing divergence here skips evaluation entirely, so beyond
//! panic-safety this target asserts two invariants: classification is
//! deterministic, and prepending an unvetted option always forfeits the fast
//! path.

use guard::gating::ssh_readonly::{
    is_fixed_readonly_diagnostic, ssh_o_directive_readonly_safe, ssh_options_all_readonly_safe,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Newline-separated argv, mirroring how the daemon receives discrete args.
    let args: Vec<String> = text.split('\n').map(str::to_string).collect();

    let safe = ssh_options_all_readonly_safe(&args);
    assert_eq!(
        safe,
        ssh_options_all_readonly_safe(&args),
        "classification must be deterministic"
    );

    // An unvetted option ahead of the command zone must always forfeit the
    // deterministic fast path (deny-by-default allow-listing).
    let mut with_forwarding = Vec::with_capacity(args.len() + 1);
    with_forwarding.push("-A".to_string());
    with_forwarding.extend(args.iter().cloned());
    assert!(
        !ssh_options_all_readonly_safe(&with_forwarding),
        "an unvetted leading option must never be classified safe"
    );

    for arg in &args {
        let _ = ssh_o_directive_readonly_safe(arg);
    }
    let _ = is_fixed_readonly_diagnostic(text);
});
