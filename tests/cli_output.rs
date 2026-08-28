//! CLI output lifecycle regression tests.

use std::process::{Command, Stdio};

const GUARD_BIN: &str = env!("CARGO_BIN_EXE_guard");

fn command_with_closed_stdout(arguments: &[&str]) -> std::process::Output {
    let (reader, writer) = std::io::pipe().expect("create stdout pipe");
    drop(reader);
    Command::new(GUARD_BIN)
        .args(arguments)
        .stdout(writer)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn guard")
        .wait_with_output()
        .expect("wait for guard")
}

fn assert_closed_stdout_is_success(arguments: &[&str]) {
    let output = command_with_closed_stdout(arguments);
    assert!(
        output.status.success(),
        "guard {arguments:?} failed after its stdout consumer closed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Broken pipe"),
        "unexpected stderr: {stderr}"
    );
    assert!(!stderr.contains("panicked"), "unexpected stderr: {stderr}");
}

#[test]
fn text_output_survives_a_closed_stdout_consumer() {
    assert_closed_stdout_is_success(&["help-tree"]);
}

#[test]
fn generated_output_survives_a_closed_stdout_consumer() {
    assert_closed_stdout_is_success(&["completions", "bash"]);
}

#[test]
fn clap_help_survives_a_closed_stdout_consumer() {
    assert_closed_stdout_is_success(&["--help"]);
}

#[test]
fn missing_subcommand_remains_invalid_usage() {
    let output = Command::new(GUARD_BIN)
        .arg("verb")
        .output()
        .expect("run guard with a missing verb subcommand");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let executable_name = std::path::Path::new(GUARD_BIN)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .expect("guard executable name");
    let expected_usage = format!("Usage: {executable_name} verb");
    assert!(String::from_utf8_lossy(&output.stderr).contains(&expected_usage));
}
