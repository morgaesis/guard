//! CLI output lifecycle regression tests.

use std::process::{Command, Stdio};

const GUARD_BIN: &str = env!("CARGO_BIN_EXE_guard");

fn guard_binary() -> std::path::PathBuf {
    let candidate = std::path::PathBuf::from(GUARD_BIN);
    let current = std::env::current_exe().expect("resolve the CLI output test executable");
    let candidate_name = candidate.file_name().and_then(std::ffi::OsStr::to_str);
    let expected_name = format!("guard{}", std::env::consts::EXE_SUFFIX);
    assert!(
        candidate_name == Some(expected_name.as_str()),
        "Cargo exposed a non-Guard executable to the CLI output test"
    );
    assert!(
        std::fs::canonicalize(&candidate).expect("resolve Cargo's guard executable")
            != std::fs::canonicalize(current).expect("resolve the CLI output test executable"),
        "Cargo exposed the CLI output test executable as Guard"
    );
    candidate
}

fn command_with_closed_stdout(arguments: &[&str]) -> std::process::Output {
    let mut child = Command::new(guard_binary())
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn guard");
    drop(child.stdout.take());
    child.wait_with_output().expect("wait for guard")
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
    let output = Command::new(guard_binary())
        .arg("verb")
        .output()
        .expect("run guard with a missing verb subcommand");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let binary = guard_binary();
    let executable_name = binary
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .expect("guard executable name");
    let expected_usage = format!("Usage: {executable_name} verb");
    assert!(String::from_utf8_lossy(&output.stderr).contains(&expected_usage));
}
