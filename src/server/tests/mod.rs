mod exec_policy;
mod gating;
mod grants;
mod sessions;
mod ssh;
mod verbs;
mod wire;

use crate::evaluate::{EvalConfig, Evaluator};
use crate::secrets::{EnvBackend, SecretManager};
use crate::session::SessionRegistry;
use crate::tool_config::ToolRegistry;
use guard::policy::PolicyMode;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing::subscriber::with_default;
use tracing_subscriber::fmt::MakeWriter;

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
    let cfg = ServerConfig::new(
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
    let buf = SharedBuf(Arc::new(Mutex::new(Vec::new())));
    (cfg, buf)
}

fn paranoid_test_config() -> ServerConfig {
    let eval_config = EvalConfig::default()
        .llm_enabled(false)
        .mode(PolicyMode::Paranoid);
    let evaluator = Evaluator::new(eval_config).expect("build evaluator");
    let secrets = SecretManager::with_backend(EnvBackend::default());
    ServerConfig::new(
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
    )
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn capture<F: FnOnce()>(buf: &SharedBuf, f: F) -> String {
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .with_ansi(false)
        .without_time()
        .finish();
    with_default(subscriber, f);
    let bytes = buf.0.lock().unwrap().clone();
    String::from_utf8_lossy(&bytes).to_string()
}
