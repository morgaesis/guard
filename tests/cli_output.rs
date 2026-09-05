//! End-to-end CLI output lifecycle tests using anonymous pipes.

use std::{
    path::Path,
    process::{Command, Stdio},
};

#[cfg(unix)]
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixListener,
    thread,
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
fn root_socket_status_reports_unreachable_json_explicitly() {
    let directory = tempfile::tempdir().expect("create endpoint directory");
    let socket = directory.path().join("missing.sock");
    let output = Command::new(GUARD_BIN)
        .arg("--socket")
        .arg(&socket)
        .args(["status", "--json"])
        .output()
        .expect("run guard status against a missing endpoint");

    assert_eq!(output.status.code(), Some(1));
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("status stdout must remain valid JSON");
    assert_eq!(document["type"], "status");
    assert_eq!(document["server"]["reachable"], false);
    assert_eq!(document["server"]["version"], serde_json::Value::Null);
}

#[cfg(unix)]
enum StatusReply {
    Restricted,
    OperationalError,
    Close,
    Malformed,
}

#[cfg(unix)]
fn run_status_with_ping_then(reply: StatusReply) -> std::process::Output {
    let directory = tempfile::tempdir().expect("create status mock directory");
    let socket = directory.path().join("guard.sock");
    let listener = UnixListener::bind(&socket).expect("bind status mock");
    let endpoint = socket.to_string_lossy().into_owned();
    let server = thread::spawn(move || {
        let (ping_stream, _) = listener.accept().expect("accept ping connection");
        let mut ping_reader = BufReader::new(ping_stream.try_clone().expect("clone ping stream"));
        let mut ping_request = String::new();
        ping_reader
            .read_line(&mut ping_request)
            .expect("read ping request");
        assert!(ping_request.contains("\"op\":\"ping\""), "{ping_request}");
        let mut ping_writer = ping_stream;
        writeln!(
            ping_writer,
            "{{\"result\":\"ping\",\"version\":\"test-server\",\"uptime_secs\":7,\"mode\":\"readonly\",\"dry_run\":false}}"
        )
        .expect("write ping response");

        let (status_stream, _) = listener.accept().expect("accept status connection");
        let mut status_reader =
            BufReader::new(status_stream.try_clone().expect("clone status stream"));
        let mut status_request = String::new();
        status_reader
            .read_line(&mut status_request)
            .expect("read status request");
        assert!(
            status_request.contains("\"op\":\"status\""),
            "{status_request}"
        );

        let response = match reply {
            StatusReply::Restricted => Some(
                "{\"result\":\"error\",\"message\":\"full server status requires operator authority\"}",
            ),
            StatusReply::OperationalError => {
                Some("{\"result\":\"error\",\"message\":\"verb catalog authority is unavailable\"}")
            }
            StatusReply::Close => None,
            StatusReply::Malformed => Some("not-json"),
        };
        if let Some(response) = response {
            let mut status_writer = status_stream;
            writeln!(status_writer, "{response}").expect("write status response");
        }
    });

    let output = Command::new(GUARD_BIN)
        .args(["--socket", &endpoint, "status", "--json"])
        .output()
        .expect("run guard status against status mock");
    server.join().expect("status mock completes");
    output
}

#[cfg(unix)]
fn status_json(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("status stdout must remain valid JSON")
}

#[test]
#[cfg(unix)]
fn status_json_restricted_response_is_a_successful_liveness_result() {
    let output = run_status_with_ping_then(StatusReply::Restricted);
    assert!(
        output.status.success(),
        "restricted status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document = status_json(&output);
    assert_eq!(document["type"], "status");
    assert_eq!(document["server"]["reachable"], true);
    assert_eq!(document["server"]["full_restricted"], true);
    assert_eq!(document["server"]["full"], serde_json::Value::Null);
    assert!(document["server"].get("error").is_none());
}

#[test]
#[cfg(unix)]
fn status_json_operational_error_is_a_reachable_failure() {
    let output = run_status_with_ping_then(StatusReply::OperationalError);
    assert_eq!(output.status.code(), Some(1));
    let document = status_json(&output);
    assert_eq!(document["server"]["reachable"], true);
    assert_eq!(
        document["server"]["full_restricted"],
        serde_json::Value::Null
    );
    assert_eq!(document["server"]["error"]["code"], "status_error");
    assert_eq!(
        document["server"]["error"]["message"],
        "verb catalog authority is unavailable"
    );
}

#[test]
#[cfg(unix)]
fn status_json_ping_then_status_transport_failures_are_reachable_errors() {
    for reply in [StatusReply::Close, StatusReply::Malformed] {
        let output = run_status_with_ping_then(reply);
        assert_eq!(output.status.code(), Some(1));
        let document = status_json(&output);
        assert_eq!(document["server"]["reachable"], true);
        assert_eq!(
            document["server"]["full_restricted"],
            serde_json::Value::Null
        );
        assert_eq!(document["server"]["full"], serde_json::Value::Null);
        assert_eq!(document["server"]["error"]["code"], "status_rpc_failed");
        assert!(document["server"]["error"]["message"].is_string());
    }
}

#[test]
fn verb_run_positional_parameter_points_to_param_flag() {
    let output = Command::new(GUARD_BIN)
        .args(["verb", "run", "inspect", "name=value"])
        .output()
        .expect("run guard with a misplaced verb parameter");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--param key=value"));
}

#[test]
fn state_database_check_is_machine_readable_and_does_not_modify_source() {
    let directory = tempfile::tempdir().expect("create state directory");
    let database = directory.path().join("state.db");
    let connection = rusqlite::Connection::open(&database).expect("create state database");
    connection
        .execute_batch("CREATE TABLE fixture (value TEXT); INSERT INTO fixture VALUES ('kept');")
        .expect("write source fixture");
    drop(connection);
    let before = std::fs::read(&database).expect("read source before check");

    let output = Command::new(GUARD_BIN)
        .args(["state-db", "check", "--file"])
        .arg(&database)
        .arg("--json")
        .output()
        .expect("run state database compatibility check");

    assert!(
        output.status.success(),
        "compatibility check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("compatibility stdout must be JSON");
    assert_eq!(document["type"], "state_db_compatibility");
    assert_eq!(document["compatible"], true);
    assert_eq!(document["simulated_startup"]["succeeded"], true);
    assert!(document["simulated_startup"]["error_category"].is_null());
    assert_eq!(document["rejected_rows"], serde_json::json!([]));
    assert_eq!(
        std::fs::read(&database).expect("read source after check"),
        before
    );
}
