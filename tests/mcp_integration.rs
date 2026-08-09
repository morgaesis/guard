//! End-to-end MCP integration test.
#![cfg(unix)]
//!
//! Spins up a real guard daemon with a static (no-LLM) policy on a temp socket,
//! spawns `guard mcp serve` as a child with piped stdio, and exercises the full
//! JSON-RPC handshake (initialize -> tools/list -> tools/call). Verifies that
//! the MCP transport layer correctly relays decisions from the daemon back to
//! the client without an LLM in the loop.
//!
//! Why static policy: this test covers the MCP plumbing, not LLM accuracy.
//! Using --no-llm with a deterministic deny/allow list keeps the test
//! reproducible, hermetic, and free from network dependencies.

use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};

const GUARD_BIN: &str = env!("CARGO_BIN_EXE_guard");

const POLICY_YAML: &str = r#"
policy:
  commands:
    allow:
      - "id"
      - "whoami"
      - "hostname"
      - "echo*"
      - "sh*"
    deny:
      - "rm*"
      - "cat /etc/shadow*"
"#;

const VERBS_YAML: &str = r#"
verbs:
  - name: inspect-identity
    description: Inspect the authenticated identity
    binary: fixture-inspect
    args: [status]
    baseline: false
    consequence: reversible
    trusted: true
"#;

struct DaemonGuard {
    child: Child,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

async fn wait_for_socket(path: &std::path::Path, child: &mut Child) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if path.exists() {
            return;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!(
                "daemon exited with {status} before creating socket {} (its stderr is passed \
                 through above)",
                path.display()
            );
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("daemon socket {} did not appear within 5s", path.display());
}

async fn start_daemon(tmp: &TempDir) -> (DaemonGuard, std::path::PathBuf) {
    start_daemon_with_gate(tmp, false).await
}

async fn start_daemon_with_gate(
    tmp: &TempDir,
    consequence_gate: bool,
) -> (DaemonGuard, std::path::PathBuf) {
    // The daemon refuses to open its state database when any ancestor
    // directory is group- or other-writable (see validate_state_ancestor in
    // src/session_store.rs). tempfile::tempdir() inherits the process umask,
    // so on hosts with a group-writable umask (e.g. 007 -> mode 0770) the
    // daemon exits at startup and the socket never appears. Pin the tempdir,
    // which doubles as HOME, to 0700 so the test is umask-independent.
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700))
        .expect("restrict tempdir permissions");

    let socket_path = tmp.path().join("guard.sock");
    let policy_path = tmp.path().join("policy.yaml");
    let verbs_path = tmp.path().join("verbs.yaml");
    std::fs::write(&policy_path, POLICY_YAML).expect("write policy yaml");
    std::fs::write(&verbs_path, VERBS_YAML).expect("write verbs yaml");
    let test_secret_env = format!("GUARD_SECRET_U{}_mcp-test-placeholder", current_uid());

    let mut command = Command::new(GUARD_BIN);
    command
        .args(["server", "start", "--no-llm", "--policy"])
        .arg(&policy_path)
        .arg("--socket")
        .arg(&socket_path)
        .arg("--state-db")
        .arg(tmp.path().join("state.db"))
        .arg("--verbs")
        .arg(&verbs_path);
    if consequence_gate {
        command.args(["--gate", "consequence"]);
    }
    let mut child = command
        .env("HOME", tmp.path())
        .env("XDG_CONFIG_HOME", tmp.path())
        .env("GUARD_BACKEND", "env")
        .env(&test_secret_env, "synthetic-sensitive-marker")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // Pass the daemon's stderr through: when startup fails, the daemon's
        // own error is the diagnosis, and discarding it turns any failure
        // into an opaque socket-wait timeout.
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn guard daemon");

    wait_for_socket(&socket_path, &mut child).await;
    (DaemonGuard { child }, socket_path)
}

fn current_uid() -> u32 {
    let status = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
    let uid_line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .expect("Uid line present");
    uid_line
        .split_whitespace()
        .nth(1)
        .expect("real uid field present")
        .parse()
        .expect("uid parses")
}

struct McpClient {
    child: Child,
    stdin: tokio::process::ChildStdin,
    stdout: BufReader<tokio::process::ChildStdout>,
}

impl Drop for McpClient {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

impl McpClient {
    async fn spawn(socket_path: &std::path::Path, tmp: &TempDir) -> Self {
        let mut child = Command::new(GUARD_BIN)
            .args(["mcp", "serve", "--socket"])
            .arg(socket_path)
            .env("HOME", tmp.path())
            .env("XDG_CONFIG_HOME", tmp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn guard mcp serve");

        let stdin = child.stdin.take().expect("take stdin");
        let stdout = BufReader::new(child.stdout.take().expect("take stdout"));

        Self {
            child,
            stdin,
            stdout,
        }
    }

    async fn spawn_from_config(tmp: &TempDir, session_token: &str) -> Self {
        let mut child = Command::new(GUARD_BIN)
            .args(["mcp", "serve"])
            .env("HOME", tmp.path())
            .env("XDG_CONFIG_HOME", tmp.path())
            .env("GUARD_SESSION", session_token)
            .env_remove("GUARD_SOCKET")
            .env_remove("GUARD_TCP_PORT")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn configured guard mcp serve");

        let stdin = child.stdin.take().expect("take stdin");
        let stdout = BufReader::new(child.stdout.take().expect("take stdout"));
        Self {
            child,
            stdin,
            stdout,
        }
    }

    async fn send(&mut self, message: Value) {
        let line = serde_json::to_string(&message).unwrap();
        self.stdin.write_all(line.as_bytes()).await.unwrap();
        self.stdin.write_all(b"\n").await.unwrap();
        self.stdin.flush().await.unwrap();
    }

    async fn recv(&mut self) -> Value {
        let mut line = String::new();
        let read = timeout(Duration::from_secs(10), self.stdout.read_line(&mut line))
            .await
            .expect("recv timed out")
            .expect("read line");
        assert!(read > 0, "MCP server closed stdout unexpectedly");
        serde_json::from_str(&line).expect("parse JSON-RPC response")
    }

    async fn rpc(&mut self, id: i64, method: &str, params: Value) -> Value {
        self.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .await;
        self.recv().await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_client_config_fails_closed_with_versioned_json() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_dir = tmp.path().join("guard");
    std::fs::create_dir_all(&config_dir).expect("create config directory");
    std::fs::write(config_dir.join("client.yaml"), "server_socket: [\n")
        .expect("write malformed config");

    let output = timeout(
        Duration::from_secs(10),
        Command::new(GUARD_BIN)
            .args(["access", "list", "--json"])
            .env("HOME", tmp.path())
            .env("XDG_CONFIG_HOME", tmp.path())
            .env_remove("GUARD_SOCKET")
            .env_remove("GUARD_TCP_PORT")
            .output(),
    )
    .await
    .expect("config validation timed out")
    .expect("run guard access list");

    assert_eq!(output.status.code(), Some(125));
    assert!(
        output.stderr.is_empty(),
        "JSON mode must not mix human errors"
    );
    let document: Value = serde_json::from_slice(&output.stdout).expect("versioned JSON error");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["type"], "client_config_error");
    assert_eq!(document["error"]["code"], "invalid_client_config");
    assert!(document["error"]["message"]
        .as_str()
        .is_some_and(|message| message.contains("failed to load client config")));
}

#[tokio::test(flavor = "multi_thread")]
async fn server_startup_rejects_malformed_client_config_before_listening() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let output = timeout(
        Duration::from_secs(10),
        Command::new(GUARD_BIN)
            .args(["server", "start", "--no-llm"])
            .env("HOME", tmp.path())
            .env("XDG_CONFIG_HOME", "relative-config")
            .env_remove("GUARD_SOCKET")
            .env_remove("GUARD_TCP_PORT")
            .output(),
    )
    .await
    .expect("server config validation timed out")
    .expect("run guard server start");

    assert_eq!(output.status.code(), Some(125));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed to load client config"), "{stderr}");
    assert!(stderr.contains("XDG_CONFIG_HOME"), "{stderr}");
    assert!(!tmp.path().join(".guard/guard.sock").exists());
}

async fn stop_test_daemon(mut daemon: DaemonGuard, socket_path: &std::path::Path) {
    daemon.child.kill().await.expect("stop fixture daemon");
    daemon.child.wait().await.expect("reap fixture daemon");
    if socket_path.exists() {
        std::fs::remove_file(socket_path).expect("remove stopped daemon socket");
    }
}

async fn restart_output(tmp: &TempDir, socket_path: &std::path::Path) -> std::process::Output {
    timeout(
        Duration::from_secs(10),
        Command::new(GUARD_BIN)
            .args(["server", "start", "--no-llm", "--policy"])
            .arg(tmp.path().join("policy.yaml"))
            .arg("--socket")
            .arg(socket_path)
            .arg("--state-db")
            .arg(tmp.path().join("state.db"))
            .arg("--verbs")
            .arg(tmp.path().join("verbs.yaml"))
            .env("HOME", tmp.path())
            .env("XDG_CONFIG_HOME", tmp.path())
            .output(),
    )
    .await
    .expect("daemon restart validation timed out")
    .expect("run daemon restart")
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_index_corruption_prevents_daemon_listener_startup() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (daemon, socket_path) = start_daemon(&tmp).await;
    let request = Command::new(GUARD_BIN)
        .args([
            "access",
            "request",
            "Inspect the authenticated identity",
            "--json",
            "--socket",
        ])
        .arg(&socket_path)
        .env("HOME", tmp.path())
        .env("XDG_CONFIG_HOME", tmp.path())
        .output()
        .await
        .expect("create durable access request");
    assert!(
        request.status.success(),
        "{}",
        String::from_utf8_lossy(&request.stderr)
    );
    stop_test_daemon(daemon, &socket_path).await;

    let database = tmp.path().join("state.db");
    let conn = rusqlite::Connection::open(&database).expect("open fixture database");
    let (handle, created_unix): (String, i64) = conn
        .query_row(
            "SELECT handle, created_unix FROM grant_requests LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("durable access request row");
    conn.execute(
        "UPDATE grant_requests SET status = 'approved', created_unix = ?1 WHERE handle = ?2",
        rusqlite::params![created_unix + 1, handle],
    )
    .expect("corrupt redundant indexes");
    conn.pragma_update(None, "user_version", 8)
        .expect("mark migration fixture");
    drop(conn);

    let output = restart_output(&tmp, &socket_path).await;
    assert_eq!(output.status.code(), Some(125));
    assert!(!socket_path.exists());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("grant-request index disagrees"), "{stderr}");

    let conn = rusqlite::Connection::open(database).expect("reopen fixture database");
    let (status, durable_created, version): (String, i64, i64) = (
        conn.query_row("SELECT status FROM grant_requests", [], |row| row.get(0))
            .unwrap(),
        conn.query_row("SELECT created_unix FROM grant_requests", [], |row| {
            row.get(0)
        })
        .unwrap(),
        conn.query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap(),
    );
    assert_eq!(status, "approved");
    assert_eq!(durable_created, created_unix + 1);
    assert_eq!(version, 8);
}

#[tokio::test(flavor = "multi_thread")]
async fn saved_grant_name_index_corruption_prevents_daemon_listener_startup() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (daemon, socket_path) = start_daemon(&tmp).await;
    stop_test_daemon(daemon, &socket_path).await;

    let conn =
        rusqlite::Connection::open(tmp.path().join("state.db")).expect("open fixture database");
    conn.execute(
        "INSERT INTO saved_grants (name, json, updated_unix) VALUES (?1, ?2, 0)",
        rusqlite::params!["indexed-name", r#"{"name":"serialized-name"}"#],
    )
    .expect("insert mismatched saved grant");
    drop(conn);

    let output = restart_output(&tmp, &socket_path).await;
    assert_eq!(output.status.code(), Some(125));
    assert!(!socket_path.exists());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("saved-grant index disagrees"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn removed_authority_commands_cannot_mint_or_modify_sessions() {
    for (args, replacement) in [
        (&["session", "new"][..], "guard access"),
        (&["grant", "issue", "fixture"][..], "guard access"),
        (
            &["appeal", "fixture", "status"][..],
            "guard access request <intent>",
        ),
    ] {
        let output = Command::new(GUARD_BIN)
            .args(args)
            .output()
            .await
            .expect("run removed authority command");
        assert_eq!(output.status.code(), Some(125));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("has been removed"), "{stderr}");
        assert!(stderr.contains(replacement), "{stderr}");
        assert!(!stderr.contains("GUARD_SESSION="), "{stderr}");
    }

    let output = Command::new(GUARD_BIN)
        .args(["api", "kubeconfig"])
        .output()
        .await
        .expect("run removed API credential export");
    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("has been removed"), "{stderr}");
    assert!(stderr.contains("kubectl or helm command verbs"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn removed_authority_wire_operations_cannot_mint_hidden_sessions() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_daemon, socket_path) = start_daemon_with_gate(&tmp, true).await;
    let mut stream = UnixStream::connect(&socket_path)
        .await
        .expect("connect daemon socket");
    stream
        .write_all(b"{\"admin\":{\"op\":\"session_grant\",\"token\":\"fixture-chosen-token\",\"activated_verbs\":[\"inspect-identity\"]}}\n")
        .await
        .expect("send removed wire operation");
    let mut response = String::new();
    BufReader::new(stream)
        .read_line(&mut response)
        .await
        .expect("read validation response");
    assert!(response.contains("invalid request"), "{response}");

    let output = Command::new(GUARD_BIN)
        .args(["access", "list", "--json", "--socket"])
        .arg(&socket_path)
        .output()
        .await
        .expect("inspect access state");
    assert!(output.status.success());
    let listing: Value = serde_json::from_slice(&output.stdout).expect("parse access list");
    assert_eq!(
        listing["response"]["items"].as_array().map(Vec::len),
        Some(0)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn secret_setter_reads_stdin_without_accepting_an_argv_value() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut child = Command::new(GUARD_BIN)
        .args(["config", "set-token"])
        .env("HOME", tmp.path())
        .env("XDG_CONFIG_HOME", tmp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn token setter");
    child
        .stdin
        .take()
        .expect("token setter stdin")
        .write_all(b"fixture-token\n")
        .await
        .expect("write token through stdin");
    let output = timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .expect("token setter timed out")
        .expect("wait for token setter");
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "Token set\n");
    assert!(output.stderr.is_empty());

    let config: serde_yaml_ng::Value = serde_yaml_ng::from_str(
        &std::fs::read_to_string(tmp.path().join("guard/client.yaml"))
            .expect("read client configuration"),
    )
    .expect("parse client configuration");
    assert!(config["auth_token"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));

    let rejected = Command::new(GUARD_BIN)
        .args(["config", "set-token", "fixture-token"])
        .env("HOME", tmp.path())
        .env("XDG_CONFIG_HOME", tmp.path())
        .output()
        .await
        .expect("run argv rejection");
    assert_eq!(rejected.status.code(), Some(2));
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_process_rejects_a_built_in_custom_tool_name() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join("missing.sock");
    let output = timeout(
        Duration::from_secs(10),
        Command::new(GUARD_BIN)
            .args(["mcp", "serve", "--socket"])
            .arg(socket)
            .args(["--tool-name", "guard_access_request"])
            .env("HOME", tmp.path())
            .env("XDG_CONFIG_HOME", tmp.path())
            .output(),
    )
    .await
    .expect("MCP validation timed out")
    .expect("run MCP validation");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("guard_access_request"));
    assert!(stderr.contains("reserved"));
}

#[tokio::test(flavor = "multi_thread")]
async fn typed_verb_denial_prints_every_exact_access_command() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_daemon, socket_path) = start_daemon_with_gate(&tmp, true).await;
    let output = timeout(
        Duration::from_secs(10),
        Command::new(GUARD_BIN)
            .args(["verb", "run", "inspect-identity", "--socket"])
            .arg(&socket_path)
            .env("HOME", tmp.path())
            .env("XDG_CONFIG_HOME", tmp.path())
            .env_remove("GUARD_SESSION")
            .output(),
    )
    .await
    .expect("typed denial timed out")
    .expect("run typed verb");
    assert_eq!(output.status.code(), Some(126));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let reference = stderr
        .lines()
        .find_map(|line| line.trim().strip_prefix("request: "))
        .unwrap_or_else(|| panic!("durable request reference missing from stderr: {stderr}"));
    assert!(reference.starts_with("gr-"));
    assert!(stderr.contains(&format!("guard access approve {reference}\n")));
    assert!(stderr.contains(&format!("guard access approve {reference} --once")));
    assert!(stderr.contains(&format!("guard access approve {reference} --uses 3")));
    assert!(stderr.contains(&format!("guard access show {reference}")));
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_threads_execution_and_session_tokens_without_operator_authority() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let config_dir = tmp.path().join("guard");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("client.yaml"),
        format!(
            "server_socket: null\nserver_tcp_port: {port}\nauth_token: configured-exec\nadmin_token: configured-admin\ndefault_user: null\n"
        ),
    )
    .unwrap();

    let daemon = tokio::spawn(async move {
        let (execute_stream, _) = listener.accept().await.unwrap();
        let (execute_reader, mut execute_writer) = tokio::io::split(execute_stream);
        let mut execute_lines = BufReader::new(execute_reader).lines();
        let execute: Value = serde_json::from_str(
            &execute_lines
                .next_line()
                .await
                .unwrap()
                .expect("execute request"),
        )
        .unwrap();
        execute_writer
            .write_all(
                br#"{"allowed":true,"reason":"fixture","exit_code":0,"stdout":"ok\n","stderr":null}"#,
            )
            .await
            .unwrap();
        execute_writer.write_all(b"\n").await.unwrap();

        execute
    });

    let mut mcp = McpClient::spawn_from_config(&tmp, "configured-session").await;
    let initialize = mcp
        .rpc(
            1,
            "initialize",
            json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "integration-test", "version": "1" }
            }),
        )
        .await;
    assert!(initialize["result"].is_object());
    let listed = mcp.rpc(2, "tools/list", json!({})).await;
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert_eq!(names, ["guard_run"]);

    let hidden_admin = mcp
        .rpc(
            3,
            "tools/call",
            json!({ "name": "guard_verbs", "arguments": {} }),
        )
        .await;
    assert_eq!(hidden_admin["error"]["code"], -32601);

    let run = mcp
        .rpc(
            4,
            "tools/call",
            json!({ "name": "guard_run", "arguments": { "binary": "true" } }),
        )
        .await;
    assert_eq!(run["result"]["isError"], false);

    let execute = daemon.await.unwrap();
    assert_eq!(execute["execute"]["auth_token"], "configured-exec");
    assert_eq!(execute["execute"]["session_token"], "configured-session");
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_end_to_end_initialize_list_call() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_daemon, socket_path) = start_daemon(&tmp).await;
    let mut mcp = McpClient::spawn(&socket_path, &tmp).await;

    // 1. initialize
    let init = mcp
        .rpc(
            1,
            "initialize",
            json!({
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": { "name": "integration-test", "version": "1.0.0" }
            }),
        )
        .await;
    assert_eq!(init["jsonrpc"], "2.0");
    assert_eq!(init["id"], 1);
    assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
    assert!(init["result"]["capabilities"]["tools"].is_object());
    assert_eq!(init["result"]["serverInfo"]["name"], "guard");

    // 2. tools/list
    let list = mcp.rpc(2, "tools/list", json!({})).await;
    let tools = list["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert_eq!(
        names,
        vec![
            "guard_run",
            "guard_verbs",
            "guard_access_request",
            "guard_access_list",
            "guard_evaluate_batch",
            "guard_access_show",
            "guard_access_status",
        ],
        "MCP must advertise the complete intentional tool contract"
    );
    let guard_run = tools
        .iter()
        .find(|t| t["name"] == "guard_run")
        .expect("guard_run tool present");
    assert!(
        guard_run["inputSchema"].get("required").is_none(),
        "binary/args must not be schema-required: a verb-only invocation is valid"
    );
    assert_eq!(
        guard_run["inputSchema"]["properties"]["waitApproval"]["type"],
        json!(["integer", "boolean"])
    );

    for field in [
        "schema_version",
        "type",
        "approval_options",
        "access_requests",
        "verb_matches",
        "guidance",
        "decision_source",
    ] {
        assert!(
            guard_run["outputSchema"]["properties"].get(field).is_some(),
            "guard_run output schema missing {field}"
        );
    }
    let handle_description = guard_run["outputSchema"]["properties"]["handle"]["description"]
        .as_str()
        .expect("handle description");
    assert!(handle_description.contains("held"));
    assert!(handle_description.contains("provisional"));
    for tool in tools {
        assert!(
            tool["outputSchema"].is_object(),
            "{} must advertise outputSchema",
            tool["name"]
        );
        assert_eq!(
            tool["outputSchema"]["properties"]["schema_version"]["const"],
            1
        );
        assert!(tool["outputSchema"]["properties"]["type"].is_object());
    }

    // 3. tools/call for the authenticated caller's access request
    let access_request = mcp
        .rpc(
            3,
            "tools/call",
            json!({
                "name": "guard_access_request",
                "arguments": { "intent": "inspect-identity" }
            }),
        )
        .await;
    assert_eq!(access_request["result"]["isError"], false);
    let access_item = &access_request["result"]["structuredContent"]["item"];
    assert_eq!(
        access_request["result"]["structuredContent"]["schema_version"],
        1
    );
    assert_eq!(
        access_request["result"]["structuredContent"]["type"],
        "access_request"
    );
    let uid = current_uid().to_string();
    assert_eq!(access_item["kind"], "request");
    assert_eq!(access_item["requester"], uid.as_str());
    assert_eq!(access_item["target"], format!("agent:{uid}"));
    assert_eq!(access_item["state"], "pending");
    assert_eq!(access_item["intent"], "inspect-identity");
    assert_eq!(access_item["effective_scope"], json!(["inspect-identity"]));
    assert_eq!(access_item["approval_options"].as_array().unwrap().len(), 3);
    let reference = access_item["reference"].as_str().expect("access reference");

    // 4. tools/call for the same authenticated caller's scoped access list
    let access_list = mcp
        .rpc(
            4,
            "tools/call",
            json!({
                "name": "guard_access_list",
                "arguments": {}
            }),
        )
        .await;
    assert_eq!(access_list["result"]["isError"], false);
    let access_items = access_list["result"]["structuredContent"]["items"]
        .as_array()
        .expect("access items array");
    assert!(!access_items.is_empty());
    assert!(access_items.iter().all(|item| item["requester"] == uid));
    assert!(access_items
        .iter()
        .any(|item| item["reference"].as_str() == Some(reference)));

    // 5. tools/call for the same request reference. The daemon performs the
    // principal check from the Unix peer, not from a caller-supplied owner.
    let access_show = mcp
        .rpc(
            5,
            "tools/call",
            json!({
                "name": "guard_access_show",
                "arguments": { "reference": reference }
            }),
        )
        .await;
    assert_eq!(access_show["result"]["isError"], false);
    let shown_item = &access_show["result"]["structuredContent"]["item"];
    assert_eq!(shown_item["reference"], reference);
    assert_eq!(shown_item["requester"], uid.as_str());
    assert_eq!(shown_item["state"], "pending");

    // 6. tools/call with an allowed command
    let allowed = mcp
        .rpc(
            6,
            "tools/call",
            json!({
                "name": "guard_run",
                "arguments": { "binary": "id", "args": [] }
            }),
        )
        .await;
    assert_eq!(allowed["result"]["isError"], false);
    let structured = &allowed["result"]["structuredContent"];
    assert_eq!(structured["allowed"], true);
    assert!(structured["status"].is_null());
    assert!(structured["handle"].is_null());
    assert!(structured["approval_options"].is_array());
    assert!(structured["access_requests"].is_array());
    assert!(structured["verb_matches"].is_array());
    assert!(structured["decision_source"].is_string());
    let stdout = structured["stdout"].as_str().unwrap_or("");
    assert!(
        stdout.contains("uid="),
        "expected `id` output to contain uid=, got: {stdout}"
    );

    // 7. tools/call with a denied command
    let denied = mcp
        .rpc(
            7,
            "tools/call",
            json!({
                "name": "guard_run",
                "arguments": { "binary": "rm", "args": ["-rf", "/tmp/never"] }
            }),
        )
        .await;
    assert_eq!(denied["result"]["isError"], false);
    let denied_structured = &denied["result"]["structuredContent"];
    assert_eq!(denied_structured["allowed"], false);
    assert!(denied_structured["status"].is_null());
    assert!(denied_structured["approval_options"].is_array());
    assert!(denied_structured["access_requests"].is_array());
    assert!(denied_structured["verb_matches"].is_array());
    assert!(denied_structured["decision_source"].is_string());
    let reason = denied_structured["reason"].as_str().unwrap_or("");
    assert!(
        !reason.is_empty(),
        "denied response should include a non-empty reason"
    );

    // 8. tools/call with server-side secret injection
    let injected = mcp
        .rpc(
            8,
            "tools/call",
            json!({
                "name": "guard_run",
                "arguments": {
                    "binary": "sh",
                    "args": ["-lc", "[ -n \"$MCP_TEST_PLACEHOLDER\" ] && echo set"],
                    "secrets": ["mcp-test-placeholder"]
                }
            }),
        )
        .await;
    assert_eq!(injected["result"]["isError"], false);
    let injected_structured = &injected["result"]["structuredContent"];
    assert_eq!(injected_structured["allowed"], true);
    assert_eq!(injected_structured["stdout"], "set\n");

    // 9. tools/call against an unknown tool name
    let unknown = mcp
        .rpc(
            9,
            "tools/call",
            json!({
                "name": "not_a_tool",
                "arguments": {}
            }),
        )
        .await;
    assert_eq!(unknown["error"]["code"], -32601);
}

const HTTP_TOKEN: &str = "integration-test-bearer";

/// Spawn `guard mcp serve --http` against a (not necessarily live) daemon
/// socket path and wait until the HTTP listener accepts connections. The
/// initialize/tools/list handshake never touches the daemon, so this covers
/// the HTTP transport itself hermetically.
async fn start_http_mcp(tmp: &TempDir) -> (McpHttpGuard, std::net::SocketAddr) {
    let socket_path = tmp.path().join("guard.sock");
    // Reserve an ephemeral port, then hand it to the child. The tiny window
    // between drop and child bind is acceptable for a test environment.
    let addr = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe bind");
        probe.local_addr().expect("probe addr")
    };

    let child = Command::new(GUARD_BIN)
        .args(["mcp", "serve", "--socket"])
        .arg(&socket_path)
        .args(["--http", &addr.to_string()])
        .env("GUARD_MCP_TOKEN", HTTP_TOKEN)
        .env("HOME", tmp.path())
        .env("XDG_CONFIG_HOME", tmp.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn guard mcp serve --http");

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(stream) = TcpStream::connect(addr).await {
            drop(stream);
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "MCP HTTP listener on {addr} did not accept within 10s"
        );
        sleep(Duration::from_millis(50)).await;
    }

    (McpHttpGuard { child }, addr)
}

struct McpHttpGuard {
    child: Child,
}

impl Drop for McpHttpGuard {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// Read exactly one HTTP response (status line, headers, Content-Length body)
/// off a connection without consuming bytes of a following response, so
/// keep-alive assertions can reuse the stream.
async fn read_one_http_response_parts(
    stream: &mut TcpStream,
) -> (u16, std::collections::BTreeMap<String, String>, String) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let read = timeout(Duration::from_secs(10), stream.read(&mut byte))
            .await
            .expect("response header timed out")
            .expect("read header byte");
        assert!(read > 0, "connection closed before end of headers");
        head.push(byte[0]);
    }
    let head_text = String::from_utf8_lossy(&head).into_owned();
    let status: u16 = head_text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("status code");
    let headers = head_text
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let content_length: usize = head_text
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("content-length") {
                value.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let mut body = vec![0u8; content_length];
    timeout(Duration::from_secs(10), stream.read_exact(&mut body))
        .await
        .expect("response body timed out")
        .expect("read body");
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

async fn read_one_http_response(stream: &mut TcpStream) -> (u16, String) {
    let (status, _, body) = read_one_http_response_parts(stream).await;
    (status, body)
}

fn http_post(body: &str) -> String {
    http_post_with_headers(body, &[])
}

fn http_post_with_headers(body: &str, additional_headers: &[(&str, &str)]) -> String {
    let mut request = format!(
        "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {HTTP_TOKEN}\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in additional_headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    request
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_http_transport_keepalive_pair_on_one_connection() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_mcp, addr) = start_http_mcp(&tmp).await;

    let mut stream = TcpStream::connect(addr).await.expect("connect");

    // First request on the connection: initialize.
    let init_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": { "name": "integration-test", "version": "1.0.0" }
        }
    })
    .to_string();
    stream
        .write_all(http_post(&init_body).as_bytes())
        .await
        .expect("write initialize");
    let (status, headers, body) = read_one_http_response_parts(&mut stream).await;
    assert_eq!(status, 200);
    let session_id = headers
        .get("mcp-session-id")
        .expect("initialize session id");
    let init: Value = serde_json::from_str(&body).expect("initialize response is JSON");
    assert_eq!(init["id"], 1);
    assert_eq!(init["result"]["protocolVersion"], "2025-03-26");

    // Second request on the SAME connection: tools/list must be served without
    // a reconnect (keep-alive).
    let list_body = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
    stream
        .write_all(http_post_with_headers(list_body, &[("Mcp-Session-Id", session_id)]).as_bytes())
        .await
        .expect("write tools/list");
    let (status, body) = read_one_http_response(&mut stream).await;
    assert_eq!(status, 200);
    let list: Value = serde_json::from_str(&body).expect("tools/list response is JSON");
    assert_eq!(list["id"], 2);
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(names.contains(&"guard_run"));
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_http_transport_session_survives_reconnect() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_mcp, addr) = start_http_mcp(&tmp).await;
    let init_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "integration-test", "version": "1" }
        }
    })
    .to_string();
    let list_body = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;

    let mut initialized = TcpStream::connect(addr).await.expect("connect");
    initialized
        .write_all(http_post(&init_body).as_bytes())
        .await
        .expect("write initialize");
    let (status, headers, _) = read_one_http_response_parts(&mut initialized).await;
    assert_eq!(status, 200);
    let session_id = headers
        .get("mcp-session-id")
        .expect("initialize session id")
        .clone();
    drop(initialized);

    let mut reconnected = TcpStream::connect(addr).await.expect("reconnect");
    reconnected
        .write_all(http_post_with_headers(list_body, &[("Mcp-Session-Id", &session_id)]).as_bytes())
        .await
        .expect("write list");
    let (_, body) = read_one_http_response(&mut reconnected).await;
    let response: Value = serde_json::from_str(&body).unwrap();
    assert!(response["result"]["tools"].is_array());

    let mut missing = TcpStream::connect(addr).await.expect("connect");
    missing
        .write_all(http_post(list_body).as_bytes())
        .await
        .expect("write list without session");
    assert_eq!(read_one_http_response(&mut missing).await.0, 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_http_transport_validates_origin_accept_and_protocol_version() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_mcp, addr) = start_http_mcp(&tmp).await;
    let ping = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}"#;

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(
            http_post_with_headers(ping, &[("Origin", "https://attacker.example")]).as_bytes(),
        )
        .await
        .expect("write invalid origin");
    assert_eq!(read_one_http_response(&mut stream).await.0, 403);

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(http_post_with_headers(ping, &[("Origin", "http://127.0.0.1:4180")]).as_bytes())
        .await
        .expect("write loopback origin");
    assert_eq!(read_one_http_response(&mut stream).await.0, 200);

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(
            http_post_with_headers(ping, &[("MCP-Protocol-Version", "2099-01-01")]).as_bytes(),
        )
        .await
        .expect("write invalid version");
    assert_eq!(read_one_http_response(&mut stream).await.0, 400);

    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {HTTP_TOKEN}\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{ping}",
        ping.len()
    );
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write incomplete accept");
    assert_eq!(read_one_http_response(&mut stream).await.0, 406);
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_http_transport_rejects_non_loopback_bind() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket_path = tmp.path().join("guard.sock");
    let output = timeout(
        Duration::from_secs(10),
        Command::new(GUARD_BIN)
            .args(["mcp", "serve", "--socket"])
            .arg(&socket_path)
            .args(["--http", "0.0.0.0:7333"])
            .env("GUARD_MCP_TOKEN", HTTP_TOKEN)
            .env("HOME", tmp.path())
            .env("XDG_CONFIG_HOME", tmp.path())
            .output(),
    )
    .await
    .expect("non-loopback validation timed out")
    .expect("run guard mcp serve");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("loopback"));
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_http_transport_rejects_oversized_body() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_mcp, addr) = start_http_mcp(&tmp).await;

    // Declare a body over the transport's 1 MiB cap; the rejection must arrive
    // without the body ever being sent.
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {HTTP_TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        2 * 1024 * 1024
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request head");
    let (status, _) = read_one_http_response(&mut stream).await;
    assert_eq!(status, 413, "oversized body must be rejected");
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_http_transport_rejects_malformed_http() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_mcp, addr) = start_http_mcp(&tmp).await;

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(b"this is not http\r\n\r\n")
        .await
        .expect("write garbage");
    let mut raw = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .expect("response timed out")
        .expect("read response");
    let text = String::from_utf8_lossy(&raw);
    let status: u16 = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("status code");
    assert_eq!(status, 400, "malformed HTTP must be rejected");
}
