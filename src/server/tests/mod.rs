mod exec_policy;
mod gating;
mod grants;
mod sessions;
mod ssh;
mod verbs;
mod wire;

use crate::secrets::{EnvBackend, SecretManager};
use crate::session::SessionRegistry;
use crate::tool_config::ToolRegistry;
use guard::evaluate::{EvalConfig, Evaluator};
use guard::policy::PolicyMode;
use std::future::Future;
use std::io::Write;
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::{layer::SubscriberExt, Layer};

use super::{ServerConfig, ServerContext, ServerState};

#[test]
fn authority_fingerprint_key_is_stable_and_separate_from_sqlite() {
    let directory = tempfile::tempdir().unwrap();
    let first = super::load_or_create_authority_mac_key(Some(directory.path())).unwrap();
    let second = super::load_or_create_authority_mac_key(Some(directory.path())).unwrap();
    assert_eq!(first.as_ref(), second.as_ref());
    assert_eq!(
        std::fs::read(directory.path().join("authority.hmac"))
            .unwrap()
            .len(),
        32
    );
    assert!(!directory.path().join("state.db").exists());
}

#[cfg(unix)]
fn trusted_artifact_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let effective_user = unsafe { libc::geteuid() };
    let root = std::env::current_dir()
        .unwrap()
        .ancestors()
        .find(|candidate| {
            let writable = std::fs::metadata(candidate).is_ok_and(|metadata| {
                metadata.uid() == effective_user && metadata.mode() & 0o200 != 0
            });
            writable
                && candidate.ancestors().all(|ancestor| {
                    std::fs::metadata(ancestor).is_ok_and(|metadata| {
                        metadata.is_dir()
                            && (metadata.uid() == effective_user || metadata.uid() == 0)
                            && metadata.mode() & 0o022 == 0
                    })
                })
        })
        .map(std::path::Path::to_path_buf)
        .expect("a trusted writable test ancestor");
    let directory = tempfile::Builder::new()
        .prefix("guard-spawn-authority-")
        .tempdir_in(&root)
        .unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[cfg(unix)]
fn write_trusted_artifact(path: &std::path::Path, content: impl AsRef<[u8]>) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(unix)]
fn create_trusted_artifact_dir(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(unix)]
static TEST_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(unix)]
struct EnvRestore {
    key: &'static str,
    value: Option<std::ffi::OsString>,
}

#[cfg(unix)]
impl EnvRestore {
    fn capture(key: &'static str) -> Self {
        Self {
            key,
            value: std::env::var_os(key),
        }
    }
}

#[cfg(unix)]
impl Drop for EnvRestore {
    fn drop(&mut self) {
        match &self.value {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

/// Shared-buffer writer for the tracing fmt subscriber. Lets us capture
/// emitted log lines and assert on their contents.
#[derive(Clone)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedBuf {
    type Writer = SharedBuf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Minimal LLM stub for verb synthesis tests: serve each connection one
/// chat-completions response whose forced `create_verb` tool-call arguments
/// come from `respond`, applied to the raw request (headers plus JSON body) so
/// a test can branch on what the daemon actually sent.
async fn run_verb_synthesis_llm_with(
    listener: tokio::net::TcpListener,
    respond: fn(&str) -> serde_json::Value,
) {
    run_verb_synthesis_llm_with_preflight(listener, respond, "APPROVE", "fixture allowed").await;
}

async fn run_verb_synthesis_llm_with_preflight(
    listener: tokio::net::TcpListener,
    respond: fn(&str) -> serde_json::Value,
    preflight_decision: &'static str,
    preflight_reason: &'static str,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(stream) => stream,
            Err(_) => return,
        };
        tokio::spawn(async move {
            let mut request = Vec::new();
            let mut chunk = [0u8; 2048];
            while let Ok(read) = stream.read(&mut chunk).await {
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers
                        .split("\r\n")
                        .find_map(|line| {
                            line.strip_prefix("Content-Length: ")
                                .or_else(|| line.strip_prefix("content-length: "))
                                .and_then(|value| value.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if request.len() >= header_end + 4 + content_length {
                        break;
                    }
                }
            }
            let request = String::from_utf8_lossy(&request);
            let synthesis = request.contains("create_verb");
            let (function, arguments) = if synthesis {
                ("create_verb", respond(&request).to_string())
            } else {
                (
                    "decide",
                    serde_json::json!({
                        "decision": preflight_decision,
                        "reason": preflight_reason,
                        "risk": 1
                    })
                    .to_string(),
                )
            };
            let body = serde_json::json!({
                "choices": [{
                    "message": {
                        "tool_calls": [{
                            "id": "verb-1",
                            "type": "function",
                            "function": {
                                "name": function,
                                "arguments": arguments
                            }
                        }]
                    }
                }],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

fn synthesized_compiler_check_arguments(_request: &str) -> serde_json::Value {
    serde_json::json!({
        "name": "check-compiler",
        "description": "Inspect compiler version",
        "binary": "uptime",
        "args": ["--version"],
        "params": {},
        "consequence": "reversible",
        "trusted": false,
        "evidence": "The exact compiler version command is read only."
    })
}

/// The fixed-shape stub most synthesis tests use: every request yields the
/// same safe read-only candidate.
async fn run_verb_synthesis_llm(listener: tokio::net::TcpListener) {
    run_verb_synthesis_llm_with(listener, synthesized_compiler_check_arguments).await;
}

fn make_test_config() -> (ServerContext, SharedBuf) {
    // LLM disabled, no static policy → policy_allowed() never hits
    // this path; we manufacture results directly for audit tests.
    let eval_config = EvalConfig::default().llm_enabled(false);
    let evaluator = Evaluator::new(eval_config).expect("build evaluator");
    let secrets = SecretManager::with_backend(EnvBackend::default());
    let mut cfg = ServerContext {
        config: ServerConfig::default(),
        state: ServerState::new(
            evaluator,
            secrets,
            ToolRegistry::isolated_for_tests(),
            SessionRegistry::new(),
            None,
        ),
    };
    #[cfg(unix)]
    {
        // The test process owns its temporary fixtures, while the modeled
        // service child is a distinct untrusted identity. Dedicated lease
        // tests exercise rejection when both identities are the same.
        cfg.config.daemon_uid = 777;
        cfg.config.daemon_principal = guard::principal::PrincipalKey::from_uid(777);
    }
    let secret_root = tempfile::tempdir()
        .expect("secret-file test parent")
        .keep()
        .join("secret-files");
    super::secure_fs::prepare_private_root(&secret_root).expect("prepare secret-file test root");
    cfg.config.secret_file_root = Some(secret_root);
    let buf = SharedBuf(Arc::new(Mutex::new(Vec::new())));
    (cfg, buf)
}

pub(super) fn config_for_proposal_test() -> ServerContext {
    make_test_config().0
}

/// Attach a real durable audit sink (in a tempdir) to a test context. The
/// tempdir handle keeps the file alive for the test's lifetime.
fn attach_test_audit_log(
    cfg: &mut ServerContext,
) -> (tempfile::TempDir, Arc<guard::audit::AuditLog>) {
    let dir = tempfile::tempdir().expect("audit test dir");
    let log = Arc::new(
        guard::audit::AuditLog::open(dir.path().join("audit.jsonl")).expect("open audit log"),
    );
    cfg.state.audit = Some(log.clone());
    (dir, log)
}

fn paranoid_test_config() -> ServerContext {
    let eval_config = EvalConfig::default()
        .llm_enabled(false)
        .mode(PolicyMode::Paranoid);
    let evaluator = Evaluator::new(eval_config).expect("build evaluator");
    let secrets = SecretManager::with_backend(EnvBackend::default());
    let mut cfg = ServerContext {
        config: ServerConfig::default(),
        state: ServerState::new(
            evaluator,
            secrets,
            ToolRegistry::isolated_for_tests(),
            SessionRegistry::new(),
            None,
        ),
    };
    #[cfg(unix)]
    {
        cfg.config.daemon_uid = 777;
        cfg.config.daemon_principal = guard::principal::PrincipalKey::from_uid(777);
    }
    let secret_root = tempfile::tempdir()
        .expect("secret-file test parent")
        .keep()
        .join("secret-files");
    super::secure_fs::prepare_private_root(&secret_root).expect("prepare secret-file test root");
    cfg.config.secret_file_root = Some(secret_root);
    cfg
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

static TRACE_CAPTURE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn capture_async<F>(buf: &SharedBuf, future: F) -> (F::Output, String)
where
    F: Future,
{
    // Anchor the process-global dispatcher BEFORE creating any scoped
    // subscriber. Without a registered global dispatcher, tracing's callsite
    // interest cache can transiently read `never` while scoped dispatchers
    // churn, silently dropping an event emitted inside the capture scope
    // (observed as an empty capture buffer under parallel test runs).
    let _ = production_audit_buffer();
    let _capture_lock = TRACE_CAPTURE_LOCK.lock().await;
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .with_ansi(false)
        .without_time()
        .finish();
    let output = future.with_subscriber(subscriber).await;
    let bytes = buf.0.lock().unwrap().clone();
    (output, String::from_utf8_lossy(&bytes).to_string())
}

fn production_audit_buffer() -> SharedBuf {
    static BUFFER: OnceLock<SharedBuf> = OnceLock::new();
    BUFFER
        .get_or_init(|| {
            let audit = SharedBuf(Arc::new(Mutex::new(Vec::new())));
            let subscriber = tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(std::io::sink)
                        .with_ansi(false)
                        .with_filter(filter_fn(|metadata| metadata.target() != "guard::audit")),
                )
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(audit.clone())
                        .with_ansi(false)
                        .with_filter(filter_fn(|metadata| metadata.target() == "guard::audit")),
                );
            tracing::subscriber::set_global_default(subscriber)
                .expect("install production-shaped test audit subscriber");
            audit
        })
        .clone()
}
