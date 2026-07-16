#![no_main]

//! Fuzz the operator verb catalog parser and the coverage matcher that feeds
//! scope resolution. Input format: YAML catalog, then `\n===\n`, then a
//! newline-separated command (binary on the first line, args after).

use guard::gating::verb::VerbCatalog;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

const FIELD_SEPARATOR: &str = "\n===\n";

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (yaml, command) = text.split_once(FIELD_SEPARATOR).unwrap_or((text, ""));

    let Ok(catalog) = VerbCatalog::from_yaml(yaml) else {
        return;
    };

    let mut lines = command.split('\n');
    let binary = lines.next().unwrap_or("");
    let args: Vec<String> = lines.map(str::to_string).collect();

    // Reverse matching must be deterministic: same catalog + argv, same cells.
    let first = catalog.match_command_all(binary, &args);
    let second = catalog.match_command_all(binary, &args);
    assert_eq!(first, second, "coverage matching must be deterministic");

    let empty = BTreeMap::new();
    let _ = catalog.match_command_all_with_environment(binary, &args, &empty, &empty, &empty);
    let _ = catalog.match_command(binary, &args);

    // Rendering with no params must never panic, whatever the catalog says.
    for name in catalog.names() {
        let _ = catalog.render(&name, &BTreeMap::new());
    }
});
