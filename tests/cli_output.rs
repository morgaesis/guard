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
#[test]
fn explicit_no_auto_config_isolates_startup_without_changing_normal_loading() {
    let directory = tempfile::tempdir().unwrap();
    let config_root = directory.path().join("config");
    std::fs::create_dir_all(config_root.join("guard")).unwrap();
    std::fs::write(
        config_root.join("guard/client.yaml"),
        "server_socket: configured.sock\n",
    )
    .unwrap();
    std::fs::write(
        directory.path().join(".env"),
        "XDG_CONFIG_HOME=relative-invalid-config\n",
    )
    .unwrap();

    let run = |disable: Option<&str>, config: Option<&Path>| {
        let mut command = Command::new(GUARD_BIN);
        command
            .args(["config", "show", "--json"])
            .current_dir(directory.path())
            .env_remove("GUARD_NO_AUTO_CONFIG")
            .env_remove("XDG_CONFIG_HOME");
        if let Some(value) = disable {
            command.env("GUARD_NO_AUTO_CONFIG", value);
        }
        if let Some(path) = config {
            command.env("XDG_CONFIG_HOME", path);
        }
        command.output().unwrap()
    };

    // A normal client loads its stored configuration and discovers cwd .env.
    for disable in [None, Some("0")] {
        let configured = run(disable, Some(&config_root));
        assert!(configured.status.success());
        let config: serde_json::Value = serde_json::from_slice(&configured.stdout).unwrap();
        assert_eq!(config["server_socket"], "configured.sock");
        assert!(!run(disable, None).status.success());
    }

    for config in [Some(config_root.as_path()), None] {
        let isolated = run(Some("1"), config);
        assert!(isolated.status.success());
        let config: serde_json::Value = serde_json::from_slice(&isolated.stdout).unwrap();
        assert!(config["server_socket"].is_null());
        assert_eq!(config["admin_token_configured"], false);
    }
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

#[cfg(unix)]
#[tokio::test]
async fn execution_result_consumers_share_failure_denial_and_child_exits() {
    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    for command in [
        vec!["verb", "run", "fixture"],
        vec!["server", "connect", "true"],
        vec!["revert", "pv-fixture"],
        vec!["resume", "ap-fixture"],
    ] {
        for (started, denied, child_exit) in [
            (Some(false), false, None),
            (Some(true), false, None),
            (None, false, None),
            (None, true, None),
            (None, false, Some(7)),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let socket = directory.path().join("guard.sock");
            let listener = tokio::net::UnixListener::bind(&socket).unwrap();
            let failed = !denied && child_exit.is_none();
            let mut response = json!({"allowed": child_exit.is_some(), "reason": "fixture outcome",
                "policy": {"allowed": !denied, "reason": "fixture policy"}, "decision_source": "validation",
                "exit_code": child_exit});
            if failed {
                response["execution_failure"] = json!({"started": started, "stage": "cwd",
                "errno": 13, "message": "working directory permission denied"});
            }
            let admin = matches!(command[0], "revert" | "resume");
            if admin {
                response["result"] = json!("gate_action");
                response["message"] = json!("fixture outcome");
                // A null legacy exit must not hide a typed failure or denial.
                response["exit_code"] = json!(child_exit);
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
                tokio::process::Command::new(GUARD_BIN)
                    .env_clear()
                    .env("XDG_CONFIG_HOME", directory.path())
                    .current_dir(directory.path())
                    .kill_on_drop(true)
                    .args(&command)
                    .arg("--socket")
                    .arg(&socket)
                    .output()
                    .await
                    .unwrap()
            };
            let (_, output) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::join!(server, client)
            })
            .await
            .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(
                output.status.code(),
                Some(if failed {
                    125
                } else if denied {
                    126
                } else {
                    7
                }),
                "{command:?}: {stderr}"
            );
            if failed {
                assert!(stderr.contains("EXECUTION FAILED"), "{command:?}: {stderr}");
                assert!(!stderr.contains("DENIED") && !stderr.contains("appeal:"));
            } else if denied {
                assert!(stderr.contains("DENIED"), "{command:?}: {stderr}");
            }
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn verb_file_diagnostics_preserve_mapping_parser_and_connection_order() {
    let mapping = "name: fixture\nbinary: echo\nconsequence: reversible\n";
    let sequence = "- name: fixture\n  binary: echo\n  consequence: reversible\n";
    let malformed = "name: fixture\nbinary: echo\nargs: [\n";
    for verb in ["add", "amend"] {
        for json in [false, true] {
            for (yaml, diagnostic) in [
                (mapping, None),
                (
                    sequence,
                    Some("invalid type: sequence, expected struct Verb"),
                ),
                (
                    malformed,
                    Some("did not find expected node content at line 4 column 1"),
                ),
            ] {
                let directory = tempfile::tempdir().unwrap();
                let file = directory.path().join("verb.yaml");
                std::fs::write(&file, yaml).unwrap();
                let listening_socket = directory.path().join("parse-probe.sock");
                let listener = std::os::unix::net::UnixListener::bind(&listening_socket).unwrap();
                listener.set_nonblocking(true).unwrap();
                let socket = if diagnostic.is_some() {
                    listening_socket
                } else {
                    directory.path().join("missing.sock")
                };
                let mut command = tokio::process::Command::new(GUARD_BIN);
                command
                    .env_clear()
                    .env("XDG_CONFIG_HOME", directory.path())
                    .current_dir(directory.path())
                    .kill_on_drop(true)
                    .args(["verb", verb]);
                if verb == "amend" {
                    command.arg("fixture");
                }
                command
                    .arg("--file")
                    .arg(&file)
                    .arg("--socket")
                    .arg(&socket);
                if json {
                    command.arg("--json");
                }
                let output =
                    tokio::time::timeout(std::time::Duration::from_secs(5), command.output())
                        .await
                        .expect("verb file handling must not wait for a daemon")
                        .unwrap();
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert_eq!(output.status.code(), Some(125), "{verb}: {stderr}");
                assert!(
                    output.stdout.is_empty(),
                    "parse and connection errors stay on stderr, including --json"
                );
                if let Some(diagnostic) = diagnostic {
                    assert!(stderr.contains("top-level YAML mapping"), "{stderr}");
                    assert!(stderr.contains("starting with 'name:'"), "{stderr}");
                    assert!(
                        stderr.contains("without a leading '-' list marker"),
                        "{stderr}"
                    );
                    assert!(stderr.contains("'verbs:' wrapper"), "{stderr}");
                    assert!(
                        stderr.contains(diagnostic),
                        "underlying YAML error must survive: {stderr}"
                    );
                    assert!(!stderr.contains("cannot reach guard server"));
                } else {
                    assert!(stderr.contains("cannot reach guard server"), "{stderr}");
                    assert!(stderr.contains(socket.to_str().unwrap()), "{stderr}");
                    assert!(!stderr.contains("failed to parse"), "{stderr}");
                }
                assert_eq!(
                    listener.accept().unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock,
                    "invalid YAML must not contact the daemon"
                );
            }
        }
    }
}

#[test]
fn verb_file_help_names_the_single_mapping_format() {
    for verb in ["add", "amend"] {
        let output = Command::new(GUARD_BIN)
            .args(["verb", verb, "--help"])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let help = String::from_utf8(output.stdout)
            .unwrap()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(help.contains("--file <PATH>"), "{help}");
        assert!(help.contains("one top-level verb mapping"), "{help}");
        assert!(
            help.contains("no leading '-' list marker or 'verbs:' wrapper"),
            "{help}"
        );
    }
}
