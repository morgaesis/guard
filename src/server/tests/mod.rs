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
