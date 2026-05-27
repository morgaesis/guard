//! End-to-end MCP integration test.
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

use std::process::Stdio;
use std::time::Duration;

use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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

struct DaemonGuard {
    child: Child,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

async fn wait_for_socket(path: &std::path::Path) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if path.exists() {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("daemon socket {} did not appear within 5s", path.display());
}

async fn start_daemon(tmp: &TempDir) -> (DaemonGuard, std::path::PathBuf) {
    let socket_path = tmp.path().join("guard.sock");
    let policy_path = tmp.path().join("policy.yaml");
    std::fs::write(&policy_path, POLICY_YAML).expect("write policy yaml");
    let test_secret_env = format!("GUARD_SECRET_U{}_mcp-test-secret", current_uid());

    let child = Command::new(GUARD_BIN)
        .args(["server", "start", "--no-llm", "--policy"])
        .arg(&policy_path)
        .arg("--socket")
        .arg(&socket_path)
        .env("HOME", tmp.path())
        .env("XDG_CONFIG_HOME", tmp.path())
        .env("SSH_GUARD_BACKEND", "env")
        .env(&test_secret_env, "test-value")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn guard daemon");

    wait_for_socket(&socket_path).await;
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
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "guard_run");
    assert_eq!(
        tools[0]["inputSchema"]["required"],
        json!(["binary", "args"])
    );

    // 3. tools/call with an allowed command
    let allowed = mcp
        .rpc(
            3,
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
    let stdout = structured["stdout"].as_str().unwrap_or("");
    assert!(
        stdout.contains("uid="),
        "expected `id` output to contain uid=, got: {stdout}"
    );

    // 4. tools/call with a denied command
    let denied = mcp
        .rpc(
            4,
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
    let reason = denied_structured["reason"].as_str().unwrap_or("");
    assert!(
        !reason.is_empty(),
        "denied response should include a non-empty reason"
    );

    // 5. tools/call with server-side secret injection
    let injected = mcp
        .rpc(
            5,
            "tools/call",
            json!({
                "name": "guard_run",
                "arguments": {
                    "binary": "sh",
                    "args": ["-lc", "[ -n \"$MCP_TEST_SECRET\" ] && echo set"],
                    "secrets": ["mcp-test-secret"]
                }
            }),
        )
        .await;
    assert_eq!(injected["result"]["isError"], false);
    let injected_structured = &injected["result"]["structuredContent"];
    assert_eq!(injected_structured["allowed"], true);
    assert_eq!(injected_structured["stdout"], "set\n");

    // 6. tools/call against an unknown tool name
    let unknown = mcp
        .rpc(
            6,
            "tools/call",
            json!({
                "name": "not_a_tool",
                "arguments": {}
            }),
        )
        .await;
    assert_eq!(unknown["error"]["code"], -32601);
}
