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
#[cfg(unix)]
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use tracing::instrument::WithSubscriber;
#[cfg(unix)]
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt::MakeWriter;
#[cfg(unix)]
use tracing_subscriber::{layer::SubscriberExt, Layer};

use super::ServerConfig;

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

fn make_test_config() -> (ServerConfig, SharedBuf) {
    // LLM disabled, no static policy → policy_allowed() never hits
    // this path; we manufacture results directly for audit tests.
    let eval_config = EvalConfig::default().llm_enabled(false);
    let evaluator = Evaluator::new(eval_config).expect("build evaluator");
    let secrets = SecretManager::with_backend(EnvBackend::default());
    let mut cfg = ServerConfig::new(
        None,
        None,
        evaluator,
        secrets,
        false,
        None,
        None,
        None,
        None,
        None,
        false,
        ToolRegistry::isolated_for_tests(),
        Vec::new(),
        false,
        SessionRegistry::new(),
        None,
        false,
        None,
    );
    let secret_root = tempfile::tempdir()
        .expect("secret-file test parent")
        .keep()
        .join("secret-files");
    super::secure_fs::prepare_private_root(&secret_root).expect("prepare secret-file test root");
    cfg.secret_file_root = Some(secret_root);
    let buf = SharedBuf(Arc::new(Mutex::new(Vec::new())));
    (cfg, buf)
}

pub(super) fn config_for_proposal_test() -> ServerConfig {
    make_test_config().0
}

fn paranoid_test_config() -> ServerConfig {
    let eval_config = EvalConfig::default()
        .llm_enabled(false)
        .mode(PolicyMode::Paranoid);
    let evaluator = Evaluator::new(eval_config).expect("build evaluator");
    let secrets = SecretManager::with_backend(EnvBackend::default());
    let mut cfg = ServerConfig::new(
        None,
        None,
        evaluator,
        secrets,
        false,
        None,
        None,
        None,
        None,
        None,
        false,
        ToolRegistry::isolated_for_tests(),
        Vec::new(),
        false,
        SessionRegistry::new(),
        None,
        false,
        None,
    );
    let secret_root = tempfile::tempdir()
        .expect("secret-file test parent")
        .keep()
        .join("secret-files");
    super::secure_fs::prepare_private_root(&secret_root).expect("prepare secret-file test root");
    cfg.secret_file_root = Some(secret_root);
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

#[cfg(unix)]
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
