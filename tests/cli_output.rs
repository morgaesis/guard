//! CLI output lifecycle regression tests.

use std::process::{Command, Stdio};

const GUARD_BIN: &str = env!("CARGO_BIN_EXE_guard");

fn command_with_closed_stdout(arguments: &[&str]) -> std::process::Output {
    let mut child = Command::new(GUARD_BIN)
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
