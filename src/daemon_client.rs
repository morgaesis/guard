//! Client for the guard daemon's local socket / TCP endpoint. Used by the
//! CLI (`guard run`, `guard secrets`, ...) and the MCP server to send
//! execute and admin requests over the wire protocol defined in `server::wire`.

use crate::server::{
    AdminRequest, AdminResponse, ExecuteRequest, ExecuteResponse, ExecuteStreamMessage,
    IncomingMessage, OutputStream, RevertSpec, SshHostKeyMode, VerbInvocation,
};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};

pub struct Client {
    socket_path: Option<PathBuf>,
    tcp_port: Option<u16>,
    auth_token: Option<String>,
    admin_token: Option<String>,
    session_token: Option<String>,
    /// Consequence-gating options carried onto each `guard run` request.
    revert: Option<RevertSpec>,
    confirm_within_secs: Option<u64>,
    require_approval: bool,
    wait_approval_secs: Option<u64>,
    verb: Option<VerbInvocation>,
    reevaluate: bool,
    ssh_hostkey: Option<SshHostKeyMode>,
}

impl Client {
    pub fn new(socket_path: Option<PathBuf>, tcp_port: Option<u16>) -> Self {
        Self {
            socket_path,
            tcp_port,
            auth_token: None,
            admin_token: None,
            session_token: None,
            revert: None,
            confirm_within_secs: None,
            require_approval: false,
            wait_approval_secs: None,
            verb: None,
            reevaluate: false,
            ssh_hostkey: None,
        }
    }

    /// Invoke a catalog verb instead of a raw binary.
    pub fn with_verb(mut self, verb: VerbInvocation) -> Self {
        self.verb = Some(verb);
        self
    }

    /// Skip the auto-learned deny-shape fast path for this client's requests
    /// and force a fresh LLM call. Never skips an operator-authored
    /// `PolicyEngine` deny rule.
    pub fn with_reevaluate(mut self, reevaluate: bool) -> Self {
        self.reevaluate = reevaluate;
        self
    }

    /// Set the ssh host-key mode carried onto each `guard run` request. Only
    /// affects ssh commands; the daemon injects the corresponding `-o` options
    /// server-side before evaluation and execution.
    pub fn with_hostkey(mut self, mode: SshHostKeyMode) -> Self {
        self.ssh_hostkey = Some(mode);
        self
    }

    pub fn with_auth(mut self, token: String) -> Self {
        self.auth_token = Some(token);
        self
    }

    pub fn with_admin_token(mut self, token: String) -> Self {
        self.admin_token = Some(token);
        self
    }

    pub fn with_session(mut self, session_token: String) -> Self {
        self.session_token = Some(session_token);
        self
    }

    /// Attach consequence-gating options for `guard run` (rollback command,
    /// auto-revert window, force-approval, and a blocking wait-for-approval).
    pub fn with_gating(
        mut self,
        revert: Option<RevertSpec>,
        confirm_within_secs: Option<u64>,
        require_approval: bool,
        wait_approval_secs: Option<u64>,
    ) -> Self {
        self.revert = revert;
        self.confirm_within_secs = confirm_within_secs;
        self.require_approval = require_approval;
        self.wait_approval_secs = wait_approval_secs;
        self
    }

    pub async fn send_admin(&self, request: AdminRequest) -> Result<AdminResponse> {
        let request_name = match &request {
            AdminRequest::SessionGrant { .. } => "session_grant",
            AdminRequest::SessionAppeal { .. } => "session_appeal",
            AdminRequest::SessionRevoke { .. } => "session_revoke",
            AdminRequest::SessionList { .. } => "session_list",
            AdminRequest::SessionShow { .. } => "session_show",
            AdminRequest::SecretSet { .. } => "secret_set",
            AdminRequest::SecretDelete { .. } => "secret_delete",
            AdminRequest::SecretExists { .. } => "secret_exists",
            AdminRequest::SecretList => "secret_list",
            AdminRequest::SecretListDetailed => "secret_list_detailed",
            AdminRequest::Status => "status",
            AdminRequest::Ping => "ping",
            AdminRequest::Confirm { .. } => "confirm",
            AdminRequest::Revert { .. } => "revert",
            AdminRequest::Provisionals => "provisionals",
            AdminRequest::Approve { .. } => "approve",
            AdminRequest::Deny { .. } => "deny",
            AdminRequest::ApprovalList => "approval_list",
            AdminRequest::ApprovalShow { .. } => "approval_show",
            AdminRequest::ApprovalNote { .. } => "approval_note",
            AdminRequest::VerbList => "verb_list",
            AdminRequest::VerbCreate { .. } => "verb_create",
        };
        let envelope = IncomingMessage::Admin {
            admin: Box::new(request),
            admin_token: self.admin_token.clone(),
        };
        let line = serde_json::to_string(&envelope)?;

        if let Some(ref socket_path) = self.socket_path {
            let stream = connect_local(socket_path).await?;
            let (reader, writer) = tokio::io::split(stream);
            let mut writer = tokio::io::BufWriter::new(writer);
            writer.write_all(line.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;

            let mut lines = BufReader::new(reader).lines();
            let response_line = lines
                .next_line()
                .await?
                .ok_or_else(|| anyhow::anyhow!("server closed connection without response"))?;
            let resp = parse_admin_response_line(&response_line, request_name)?;
            Ok(resp)
        } else if let Some(port) = self.tcp_port {
            let addr = format!("127.0.0.1:{}", port);
            let stream = tokio::net::TcpStream::connect(&addr)
                .await
                .context("failed to connect to guard server")?;
            let (reader, writer) = stream.into_split();
            let mut writer = tokio::io::BufWriter::new(writer);
            writer.write_all(line.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;

            let mut lines = BufReader::new(reader).lines();
            let response_line = lines
                .next_line()
                .await?
                .ok_or_else(|| anyhow::anyhow!("server closed connection without response"))?;
            let resp = parse_admin_response_line(&response_line, request_name)?;
            Ok(resp)
        } else {
            anyhow::bail!("no socket path or TCP port configured");
        }
    }

    pub fn endpoint_for_log(&self) -> String {
        if let Some(ref socket_path) = self.socket_path {
            format!("unix:{}", socket_path.display())
        } else if let Some(port) = self.tcp_port {
            format!("tcp:127.0.0.1:{}", port)
        } else {
            "unconfigured".to_string()
        }
    }

    pub async fn execute_with_injections(
        &self,
        binary: &str,
        args: &[String],
        env: HashMap<String, String>,
        secrets: HashMap<String, String>,
        secret_files: HashMap<String, String>,
    ) -> Result<ExecuteResponse> {
        let mut request =
            self.build_execute_request(binary, args, env, secrets, secret_files, false);

        tracing::debug!(
            binary = %binary,
            arg_count = args.len(),
            endpoint = %self.endpoint_for_log(),
            "client dispatching execute request"
        );

        if let Some(ref socket_path) = self.socket_path {
            request.cwd = std::env::current_dir().ok();
            self.send_local(socket_path, &request).await
        } else if let Some(port) = self.tcp_port {
            self.send_tcp(port, &request).await
        } else {
            anyhow::bail!("no socket path or TCP port configured");
        }
    }

    pub async fn execute_streaming_with_injections<F>(
        &self,
        binary: &str,
        args: &[String],
        env: HashMap<String, String>,
        secrets: HashMap<String, String>,
        secret_files: HashMap<String, String>,
        mut on_output: F,
    ) -> Result<ExecuteResponse>
    where
        F: FnMut(OutputStream, &str),
    {
        let mut request =
            self.build_execute_request(binary, args, env, secrets, secret_files, true);

        tracing::debug!(
            binary = %binary,
            arg_count = args.len(),
            endpoint = %self.endpoint_for_log(),
            "client dispatching streaming execute request"
        );

        if let Some(ref socket_path) = self.socket_path {
            request.cwd = std::env::current_dir().ok();
            self.send_local_streaming(socket_path, &request, &mut on_output)
                .await
        } else if let Some(port) = self.tcp_port {
            self.send_tcp_streaming(port, &request, &mut on_output)
                .await
        } else {
            anyhow::bail!("no socket path or TCP port configured");
        }
    }

    fn build_execute_request(
        &self,
        binary: &str,
        args: &[String],
        env: HashMap<String, String>,
        secrets: HashMap<String, String>,
        secret_files: HashMap<String, String>,
        stream: bool,
    ) -> ExecuteRequest {
        ExecuteRequest {
            binary: binary.to_string(),
            args: args.to_vec(),
            auth_token: self.auth_token.clone(),
            env,
            secrets,
            secret_files,
            stream,
            session_token: self.session_token.clone(),
            revert: self.revert.clone(),
            confirm_within_secs: self.confirm_within_secs,
            require_approval: if self.require_approval {
                Some(true)
            } else {
                None
            },
            wait_approval_secs: self.wait_approval_secs,
            verb: self.verb.clone(),
            reevaluate: self.reevaluate,
            ssh_hostkey: self.ssh_hostkey,
            cwd: None,
        }
    }

    async fn send_local(
        &self,
        socket_path: &Path,
        request: &ExecuteRequest,
    ) -> Result<ExecuteResponse> {
        tracing::debug!(
            socket = %socket_path.display(),
            "connecting to guard server"
        );
        let stream = connect_local(socket_path).await?;
        tracing::debug!(
            socket = %socket_path.display(),
            "connected to guard server"
        );

        let (reader, writer) = tokio::io::split(stream);

        let mut writer = tokio::io::BufWriter::new(writer);
        tracing::debug!(
            binary = %request.binary,
            arg_count = request.args.len(),
            "sending execute request"
        );
        writer
            .write_all(serde_json::to_string(request)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        tracing::debug!("execute request sent; waiting for server response");

        let mut reader = BufReader::new(reader).lines();
        let Some(line) = reader.next_line().await? else {
            bail!("server closed connection without response");
        };

        let response: ExecuteResponse =
            serde_json::from_str(&line).context("invalid server response")?;
        tracing::debug!(
            allowed = response.allowed,
            exit_code = ?response.exit_code,
            has_stdout = response.stdout.is_some(),
            has_stderr = response.stderr.is_some(),
            "received execute response"
        );

        Ok(response)
    }

    async fn send_local_streaming<F>(
        &self,
        socket_path: &Path,
        request: &ExecuteRequest,
        on_output: &mut F,
    ) -> Result<ExecuteResponse>
    where
        F: FnMut(OutputStream, &str),
    {
        tracing::debug!(
            socket = %socket_path.display(),
            "connecting to guard server"
        );
        let stream = connect_local(socket_path).await?;
        tracing::debug!(
            socket = %socket_path.display(),
            "connected to guard server"
        );

        let (reader, writer) = tokio::io::split(stream);
        let mut writer = tokio::io::BufWriter::new(writer);
        tracing::debug!(
            binary = %request.binary,
            arg_count = request.args.len(),
            "sending streaming execute request"
        );
        writer
            .write_all(serde_json::to_string(request)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        tracing::debug!("streaming execute request sent; waiting for server response");

        let mut reader = BufReader::new(reader).lines();
        read_streaming_response(&mut reader, on_output).await
    }

    async fn send_tcp(&self, port: u16, request: &ExecuteRequest) -> Result<ExecuteResponse> {
        let addr = format!("127.0.0.1:{}", port);
        tracing::debug!(addr = %addr, "connecting to guard server");
        let stream = tokio::net::TcpStream::connect(&addr)
            .await
            .context("failed to connect to guard server")?;
        tracing::debug!(addr = %addr, "connected to guard server");

        let (reader, writer) = stream.into_split();

        let mut writer = tokio::io::BufWriter::new(writer);
        tracing::debug!(
            binary = %request.binary,
            arg_count = request.args.len(),
            "sending execute request"
        );
        writer
            .write_all(serde_json::to_string(request)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        tracing::debug!("execute request sent; waiting for server response");

        let mut reader = BufReader::new(reader).lines();
        let Some(line) = reader.next_line().await? else {
            bail!("server closed connection without response");
        };

        let response: ExecuteResponse =
            serde_json::from_str(&line).context("invalid server response")?;
        tracing::debug!(
            allowed = response.allowed,
            exit_code = ?response.exit_code,
            has_stdout = response.stdout.is_some(),
            has_stderr = response.stderr.is_some(),
            "received execute response"
        );

        Ok(response)
    }

    async fn send_tcp_streaming<F>(
        &self,
        port: u16,
        request: &ExecuteRequest,
        on_output: &mut F,
    ) -> Result<ExecuteResponse>
    where
        F: FnMut(OutputStream, &str),
    {
        let addr = format!("127.0.0.1:{}", port);
        tracing::debug!(addr = %addr, "connecting to guard server");
        let stream = tokio::net::TcpStream::connect(&addr)
            .await
            .context("failed to connect to guard server")?;
        tracing::debug!(addr = %addr, "connected to guard server");

        let (reader, writer) = stream.into_split();
        let mut writer = tokio::io::BufWriter::new(writer);
        tracing::debug!(
            binary = %request.binary,
            arg_count = request.args.len(),
            "sending streaming execute request"
        );
        writer
            .write_all(serde_json::to_string(request)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        tracing::debug!("streaming execute request sent; waiting for server response");

        let mut reader = BufReader::new(reader).lines();
        read_streaming_response(&mut reader, on_output).await
    }
}

fn parse_admin_response_line(response_line: &str, request_name: &str) -> Result<AdminResponse> {
    match serde_json::from_str::<AdminResponse>(response_line) {
        Ok(resp) => Ok(resp),
        Err(admin_err) => {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(response_line) {
                if let Some(result_name) = value.get("result").and_then(|v| v.as_str()) {
                    return Ok(AdminResponse::Error {
                        message: format!(
                            "guard daemon returned malformed admin response for '{}': result '{}' did not match the current schema ({admin_err}). Restart the daemon onto the current binary.",
                            request_name, result_name
                        ),
                    });
                }
            }
            if let Ok(exec_resp) = serde_json::from_str::<ExecuteResponse>(response_line) {
                let message = if exec_resp.reason.contains("invalid request")
                    && exec_resp.reason.contains("IncomingMessage")
                {
                    format!(
                        "guard daemon rejected admin RPC '{}'. The running daemon likely predates this client or needs restart onto the current binary.",
                        request_name
                    )
                } else {
                    exec_resp.reason
                };
                return Ok(AdminResponse::Error { message });
            }
            Err(admin_err).context("invalid admin server response")
        }
    }
}

async fn read_streaming_response<R, F>(
    reader: &mut tokio::io::Lines<BufReader<R>>,
    on_output: &mut F,
) -> Result<ExecuteResponse>
where
    R: AsyncRead + Unpin,
    F: FnMut(OutputStream, &str),
{
    let mut stdout = String::new();
    let mut stderr = String::new();

    while let Some(line) = reader.next_line().await? {
        match serde_json::from_str::<ExecuteStreamMessage>(&line) {
            Ok(ExecuteStreamMessage::Stdout { data }) => {
                on_output(OutputStream::Stdout, &data);
                stdout.push_str(&data);
            }
            Ok(ExecuteStreamMessage::Stderr { data }) => {
                on_output(OutputStream::Stderr, &data);
                stderr.push_str(&data);
            }
            Ok(ExecuteStreamMessage::PolicyDecision { allowed, reason }) => {
                if allowed {
                    tracing::info!(reason = %reason, "POLICY_ALLOWED");
                } else {
                    tracing::trace!(reason = %reason, "POLICY_DENIED");
                }
            }
            Ok(ExecuteStreamMessage::Keepalive) => {}
            Ok(ExecuteStreamMessage::Result { mut response }) => {
                if response.stdout.is_none() && !stdout.is_empty() {
                    response.stdout = Some(stdout);
                }
                if response.stderr.is_none() && !stderr.is_empty() {
                    response.stderr = Some(stderr);
                }
                tracing::debug!(
                    allowed = response.allowed,
                    exit_code = ?response.exit_code,
                    has_stdout = response.stdout.is_some(),
                    has_stderr = response.stderr.is_some(),
                    "received streaming execute response"
                );
                return Ok(response);
            }
            Err(_) => {
                let response: ExecuteResponse =
                    serde_json::from_str(&line).context("invalid server response")?;
                tracing::debug!(
                    allowed = response.allowed,
                    exit_code = ?response.exit_code,
                    has_stdout = response.stdout.is_some(),
                    has_stderr = response.stderr.is_some(),
                    "received non-streaming execute response"
                );
                return Ok(response);
            }
        }
    }

    bail!("server closed connection without response")
}

/// Connect to the local guard daemon: UNIX domain socket on Unix, named pipe on
/// Windows. Returns a stream that implements `AsyncRead + AsyncWrite`.
#[cfg(unix)]
async fn connect_local(path: &Path) -> Result<tokio::net::UnixStream> {
    tokio::net::UnixStream::connect(path)
        .await
        .context("failed to connect to guard server")
}

#[cfg(windows)]
async fn connect_local(path: &Path) -> Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use tokio::net::windows::named_pipe::ClientOptions;
    let name = crate::server::winplat::pipe_name(path);
    ClientOptions::new()
        .open(&name)
        .context("failed to connect to guard server")
}

#[cfg(test)]
mod tests {
    use super::{parse_admin_response_line, AdminResponse, Client};
    use std::collections::HashMap;

    #[test]
    fn parse_admin_response_line_accepts_admin_response() {
        let line = r#"{"result":"error","message":"admin denied"}"#;
        match parse_admin_response_line(line, "secret_set").unwrap() {
            AdminResponse::Error { message } => assert_eq!(message, "admin denied"),
            other => panic!("expected admin error, got {:?}", other),
        }
    }

    #[test]
    fn parse_admin_response_line_maps_execute_invalid_request_to_actionable_error() {
        let line = r#"{"allowed":false,"reason":"invalid request: data did not match any variant of untagged enum IncomingMessage"}"#;
        match parse_admin_response_line(line, "secret_set").unwrap() {
            AdminResponse::Error { message } => {
                assert!(message.contains("secret_set"));
                assert!(message.contains("needs restart"));
            }
            other => panic!("expected admin error, got {:?}", other),
        }
    }

    #[test]
    fn parse_admin_response_line_surfaces_malformed_admin_payloads_as_restart_errors() {
        let line = r#"{"result":"secret_list","items":[{"key":"alpha"}]}"#;
        match parse_admin_response_line(line, "secret_list").unwrap() {
            AdminResponse::Error { message } => {
                assert!(message.contains("secret_list"));
                assert!(message.contains("malformed admin response"));
                assert!(message.contains("Restart the daemon"));
            }
            other => panic!("expected admin error, got {:?}", other),
        }
    }

    #[test]
    fn tcp_execute_request_does_not_carry_cwd() {
        let client = Client::new(None, Some(8123));
        let request = client.build_execute_request(
            "id",
            &[],
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            false,
        );
        assert!(request.cwd.is_none());
    }
}
