//! End-to-end CLI output lifecycle tests using anonymous pipes.

use std::{
    path::Path,
    process::{Command, Stdio},
};

const GUARD_BIN: &str = env!("CARGO_BIN_EXE_guard");

fn command_with_closed_stdout(arguments: &[&str]) -> std::process::Output {
    let (reader, writer) = std::io::pipe().expect("create stdout pipe");
    drop(reader);
    let child = Command::new(GUARD_BIN)
        .args(arguments)
        .stdout(writer)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn guard");
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
    let output = Command::new(GUARD_BIN)
        .arg("verb")
        .output()
        .expect("run guard with a missing verb subcommand");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let executable = Path::new(GUARD_BIN)
        .file_name()
        .expect("guard binary has a file name")
        .to_string_lossy();
    let usage = format!("Usage: {executable} verb");
    assert!(String::from_utf8_lossy(&output.stderr).contains(&usage));
}

#[cfg(unix)]
#[tokio::test]
async fn execution_failure_cli_distinguishes_policy_in_text_and_json() {
    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    for json_output in [false, true] {
        for execution_failed in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let socket = directory.path().join("guard.sock");
            let listener = tokio::net::UnixListener::bind(&socket).unwrap();
            let mut response = json!({
                "allowed": false, "reason": "fixture failure", "decision_source": "static_policy",
                "policy": {"allowed": execution_failed, "reason": "fixture admission"}
            });
            if execution_failed {
                response["execution_failure"] = json!({"started": false, "stage": "cwd", "errno": 13, "message": "working directory permission denied"});
            }
            let server = async {
                let (stream, _) = listener.accept().await.unwrap();
                let (reader, mut writer) = stream.into_split();
                let mut line = String::new();
                BufReader::new(reader).read_line(&mut line).await.unwrap();
                let request: serde_json::Value = serde_json::from_str(&line).unwrap();
                let payload = if request["execute"]["stream"] == true {
                    json!({"type": "result", "response": response})
                } else {
                    response
                };
                writer
                    .write_all(format!("{payload}\n").as_bytes())
                    .await
                    .unwrap();
            };
            let client = async {
                let mut command = tokio::process::Command::new(GUARD_BIN);
                command
                    .env_clear()
                    .env("XDG_CONFIG_HOME", directory.path())
                    .current_dir(directory.path())
                    .kill_on_drop(true)
                    .args(["run", "--socket"])
                    .arg(&socket);
                if json_output {
                    command.arg("--json");
                }
                command.arg("true").output().await.unwrap()
            };
            let (_, output) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::join!(server, client)
            })
            .await
            .unwrap();
            assert_eq!(
                output.status.code(),
                Some(if execution_failed { 125 } else { 126 })
            );
            if json_output {
                let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(document["response"]["policy"]["allowed"], execution_failed);
                assert_eq!(document["response"]["allowed"], false);
                if execution_failed {
                    assert_eq!(document["response"]["execution_failure"]["stage"], "cwd");
                }
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if execution_failed {
                    assert!(stderr.contains("EXECUTION FAILED"));
                    assert!(!stderr.contains("DENIED"));
                    assert!(!stderr.contains("appeal:"));
                } else {
                    assert!(stderr.contains("DENIED"));
                    assert!(stderr.contains("appeal:"));
                }
            }
        }
    }
}
