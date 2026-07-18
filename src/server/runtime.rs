//! Daemon runtime side effects: operator notifications and child ownership.

use serde::Serialize;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::wire::CommandAdmissionStatus;

const MAX_COMMAND_ADMISSION_SCOPES: usize = 4096;

#[derive(Debug, Clone, Copy)]
pub(crate) struct CommandAdmissionConfig {
    pub handler_concurrency: usize,
    pub principal_handler_concurrency: usize,
    pub evaluator_concurrency: usize,
    pub principal_evaluator_concurrency: usize,
    pub evaluator_rate_per_minute: u32,
    pub evaluator_burst: u32,
    pub evaluator_error_threshold: u32,
    pub evaluator_circuit_cooldown: Duration,
}

impl Default for CommandAdmissionConfig {
    fn default() -> Self {
        Self {
            handler_concurrency: 32,
            principal_handler_concurrency: 8,
            evaluator_concurrency: 4,
            principal_evaluator_concurrency: 2,
            evaluator_rate_per_minute: 60,
            evaluator_burst: 10,
            evaluator_error_threshold: 3,
            evaluator_circuit_cooldown: Duration::from_secs(60),
        }
    }
}

struct CommandScopeState {
    handler: Arc<tokio::sync::Semaphore>,
    evaluator: Arc<tokio::sync::Semaphore>,
    tokens: f64,
    refilled_at: Instant,
    touched_at: Instant,
    consecutive_errors: u32,
    circuit_open_until: Option<Instant>,
}

#[derive(Default)]
struct CommandAdmissionCounters {
    handler_attempted: AtomicU64,
    handler_admitted: AtomicU64,
    handler_rejected: AtomicU64,
    evaluator_attempted: AtomicU64,
    evaluator_admitted: AtomicU64,
    evaluator_rate_limited: AtomicU64,
    evaluator_concurrency_limited: AtomicU64,
    evaluator_errors: AtomicU64,
    evaluator_circuit_rejections: AtomicU64,
}

/// Coarse, identifier-free concurrency gauges for the read-only metrics
/// surface. Read at scrape time; never on the request hot path.
#[derive(Debug, Clone, Copy)]
pub(super) struct ConcurrencyGauges {
    pub handler_capacity: u64,
    pub handler_available: u64,
    pub evaluator_capacity: u64,
    pub evaluator_available: u64,
    pub active_principal_scopes: u64,
}

#[derive(Clone)]
pub(super) struct CommandAdmission {
    config: CommandAdmissionConfig,
    handler: Arc<tokio::sync::Semaphore>,
    evaluator: Arc<tokio::sync::Semaphore>,
    scopes: Arc<Mutex<HashMap<String, CommandScopeState>>>,
    counters: Arc<CommandAdmissionCounters>,
}

pub(super) struct CommandHandlerPermit {
    _global: tokio::sync::OwnedSemaphorePermit,
    _principal: tokio::sync::OwnedSemaphorePermit,
}

pub(super) struct CommandEvaluatorPermit {
    _global: tokio::sync::OwnedSemaphorePermit,
    _principal: tokio::sync::OwnedSemaphorePermit,
}

impl CommandAdmission {
    pub(super) fn new(mut config: CommandAdmissionConfig) -> Self {
        config.handler_concurrency = config.handler_concurrency.max(1);
        config.principal_handler_concurrency = config.principal_handler_concurrency.max(1);
        config.evaluator_concurrency = config.evaluator_concurrency.max(1);
        config.principal_evaluator_concurrency = config.principal_evaluator_concurrency.max(1);
        config.evaluator_rate_per_minute = config.evaluator_rate_per_minute.max(1);
        config.evaluator_burst = config.evaluator_burst.max(1);
        config.evaluator_error_threshold = config.evaluator_error_threshold.max(1);
        config.evaluator_circuit_cooldown = config
            .evaluator_circuit_cooldown
            .max(Duration::from_millis(1));
        Self {
            handler: Arc::new(tokio::sync::Semaphore::new(config.handler_concurrency)),
            evaluator: Arc::new(tokio::sync::Semaphore::new(config.evaluator_concurrency)),
            scopes: Arc::new(Mutex::new(HashMap::new())),
            counters: Arc::new(CommandAdmissionCounters::default()),
            config,
        }
    }

    fn scope_state(
        &self,
        scope: &str,
        now: Instant,
    ) -> Result<(Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>), &'static str> {
        let mut states = self.scopes.lock().expect("command admission lock");
        if !states.contains_key(scope) && states.len() >= MAX_COMMAND_ADMISSION_SCOPES {
            let evict = states
                .iter()
                .filter(|(_, state)| {
                    Arc::strong_count(&state.handler) == 1
                        && Arc::strong_count(&state.evaluator) == 1
                })
                .min_by_key(|(_, state)| state.touched_at)
                .map(|(key, _)| key.clone());
            if let Some(key) = evict {
                states.remove(&key);
            } else {
                return Err("command admission principal capacity reached");
            }
        }
        let state = states
            .entry(scope.to_string())
            .or_insert_with(|| CommandScopeState {
                handler: Arc::new(tokio::sync::Semaphore::new(
                    self.config.principal_handler_concurrency,
                )),
                evaluator: Arc::new(tokio::sync::Semaphore::new(
                    self.config.principal_evaluator_concurrency,
                )),
                tokens: f64::from(self.config.evaluator_burst),
                refilled_at: now,
                touched_at: now,
                consecutive_errors: 0,
                circuit_open_until: None,
            });
        state.touched_at = now;
        Ok((state.handler.clone(), state.evaluator.clone()))
    }

    pub(super) fn admit_handler(&self, scope: &str) -> Result<CommandHandlerPermit, &'static str> {
        self.counters
            .handler_attempted
            .fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        let (principal, _) = self.scope_state(scope, now).inspect_err(|_| {
            self.reject_handler("scope_capacity");
        })?;
        let principal = principal.try_acquire_owned().map_err(|_| {
            self.reject_handler("principal_concurrency");
            "command per-principal concurrency limit reached"
        })?;
        let global = self.handler.clone().try_acquire_owned().map_err(|_| {
            self.reject_handler("global_concurrency");
            "command handler concurrency limit reached"
        })?;
        self.counters
            .handler_admitted
            .fetch_add(1, Ordering::Relaxed);
        Ok(CommandHandlerPermit {
            _global: global,
            _principal: principal,
        })
    }

    fn reject_handler(&self, event: &str) {
        self.counters
            .handler_rejected
            .fetch_add(1, Ordering::Relaxed);
        self.audit(event);
    }

    pub(super) fn admit_evaluator(
        &self,
        scope: &str,
    ) -> Result<CommandEvaluatorPermit, &'static str> {
        self.counters
            .evaluator_attempted
            .fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        let (_, principal) = self.scope_state(scope, now).inspect_err(|_| {
            self.counters
                .evaluator_concurrency_limited
                .fetch_add(1, Ordering::Relaxed);
            self.audit("evaluator_scope_capacity");
        })?;
        let principal = principal.try_acquire_owned().map_err(|_| {
            self.counters
                .evaluator_concurrency_limited
                .fetch_add(1, Ordering::Relaxed);
            self.audit("evaluator_principal_concurrency");
            "command evaluator per-principal concurrency limit reached"
        })?;
        let global = self.evaluator.clone().try_acquire_owned().map_err(|_| {
            self.counters
                .evaluator_concurrency_limited
                .fetch_add(1, Ordering::Relaxed);
            self.audit("evaluator_global_concurrency");
            "command evaluator concurrency limit reached"
        })?;
        {
            let mut states = self.scopes.lock().expect("command admission lock");
            let state = states
                .get_mut(scope)
                .expect("admission scope remains registered");
            state.touched_at = now;
            if state.circuit_open_until.is_some_and(|until| now < until) {
                self.counters
                    .evaluator_circuit_rejections
                    .fetch_add(1, Ordering::Relaxed);
                drop(states);
                self.audit("evaluator_circuit_open");
                return Err("command evaluator circuit is open");
            }
            state.circuit_open_until = None;
            let refill = now.duration_since(state.refilled_at).as_secs_f64()
                * f64::from(self.config.evaluator_rate_per_minute)
                / 60.0;
            state.tokens = (state.tokens + refill).min(f64::from(self.config.evaluator_burst));
            state.refilled_at = now;
            if state.tokens < 1.0 {
                self.counters
                    .evaluator_rate_limited
                    .fetch_add(1, Ordering::Relaxed);
                drop(states);
                self.audit("evaluator_rate_limited");
                return Err("command evaluator rate limit reached");
            }
            state.tokens -= 1.0;
        }
        self.counters
            .evaluator_admitted
            .fetch_add(1, Ordering::Relaxed);
        Ok(CommandEvaluatorPermit {
            _global: global,
            _principal: principal,
        })
    }

    pub(super) fn complete_evaluator(&self, scope: &str, error: bool, provider_spend: bool) {
        let now = Instant::now();
        let mut states = self.scopes.lock().expect("command admission lock");
        if let Some(state) = states.get_mut(scope) {
            state.touched_at = now;
            if !provider_spend {
                state.tokens = (state.tokens + 1.0).min(f64::from(self.config.evaluator_burst));
            } else if error {
                self.counters
                    .evaluator_errors
                    .fetch_add(1, Ordering::Relaxed);
                state.consecutive_errors = state.consecutive_errors.saturating_add(1);
                if state.consecutive_errors >= self.config.evaluator_error_threshold {
                    state.circuit_open_until = Some(now + self.config.evaluator_circuit_cooldown);
                }
            } else {
                state.consecutive_errors = 0;
            }
        }
        drop(states);
        self.audit(if !provider_spend {
            "evaluator_no_spend"
        } else if error {
            "evaluator_error"
        } else {
            "evaluator_completed"
        });
    }

    pub(super) fn snapshot(&self) -> CommandAdmissionStatus {
        CommandAdmissionStatus {
            handler_attempted: self.counters.handler_attempted.load(Ordering::Relaxed),
            handler_admitted: self.counters.handler_admitted.load(Ordering::Relaxed),
            handler_rejected: self.counters.handler_rejected.load(Ordering::Relaxed),
            evaluator_attempted: self.counters.evaluator_attempted.load(Ordering::Relaxed),
            evaluator_admitted: self.counters.evaluator_admitted.load(Ordering::Relaxed),
            evaluator_rate_limited: self.counters.evaluator_rate_limited.load(Ordering::Relaxed),
            evaluator_concurrency_limited: self
                .counters
                .evaluator_concurrency_limited
                .load(Ordering::Relaxed),
            evaluator_errors: self.counters.evaluator_errors.load(Ordering::Relaxed),
            evaluator_circuit_rejections: self
                .counters
                .evaluator_circuit_rejections
                .load(Ordering::Relaxed),
        }
    }

    /// Point-in-time concurrency gauges for the read-only metrics surface:
    /// the global handler/evaluator semaphore capacity and how many permits are
    /// currently available (in-flight = capacity - available), plus the number
    /// of live per-principal scopes. Coarse and identifier-free.
    pub(super) fn concurrency_gauges(&self) -> ConcurrencyGauges {
        let active_scopes = self.scopes.lock().map(|states| states.len()).unwrap_or(0);
        ConcurrencyGauges {
            handler_capacity: self.config.handler_concurrency as u64,
            handler_available: self.handler.available_permits() as u64,
            evaluator_capacity: self.config.evaluator_concurrency as u64,
            evaluator_available: self.evaluator.available_permits() as u64,
            active_principal_scopes: active_scopes as u64,
        }
    }

    fn audit(&self, event: &str) {
        let counters = self.snapshot();
        let _ = guard::audit::emit_global(
            &guard::audit::AuditEvent::new(guard::audit::AuditKind::CommandAdmission)
                .field("event", event)
                .field("handler_attempted", counters.handler_attempted)
                .field("handler_admitted", counters.handler_admitted)
                .field("handler_rejected", counters.handler_rejected)
                .field("evaluator_attempted", counters.evaluator_attempted)
                .field("evaluator_admitted", counters.evaluator_admitted)
                .field("evaluator_rate_limited", counters.evaluator_rate_limited)
                .field(
                    "evaluator_concurrency_limited",
                    counters.evaluator_concurrency_limited,
                )
                .field("evaluator_errors", counters.evaluator_errors)
                .field(
                    "evaluator_circuit_rejections",
                    counters.evaluator_circuit_rejections,
                ),
        );
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct NotifyEvent {
    pub event: &'static str,
    pub at_unix: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behavior: Option<serde_json::Value>,
}

#[derive(Clone)]
pub(super) struct NotifyHook {
    command: Arc<Vec<String>>,
    timeout: std::time::Duration,
    concurrency: Arc<tokio::sync::Semaphore>,
}

impl NotifyHook {
    pub(super) fn new(command: Vec<String>, timeout_secs: u64) -> Option<Self> {
        (!command.is_empty()).then(|| Self {
            command: Arc::new(command),
            timeout: std::time::Duration::from_secs(timeout_secs.clamp(1, 60)),
            concurrency: Arc::new(tokio::sync::Semaphore::new(16)),
        })
    }

    pub(super) fn emit(&self, event: NotifyEvent) {
        let event = bounded_notify_event(event);
        let command = self.command.clone();
        let timeout = self.timeout;
        let permit = match self.concurrency.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!("notify hook concurrency limit reached; event dropped");
                return;
            }
        };
        tokio::spawn(async move {
            let _permit = permit;
            let Some((binary, args)) = command.split_first() else {
                return;
            };
            let payload = match serde_json::to_vec(&event) {
                Ok(payload) => payload,
                Err(error) => {
                    tracing::warn!("notify hook event serialization failed: {}", error);
                    return;
                }
            };
            let mut child = tokio::process::Command::new(binary);
            child
                .args(args)
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true);
            if let Some(path) = std::env::var_os("PATH") {
                child.env("PATH", path);
            }
            let mut child = match child.spawn() {
                Ok(child) => child,
                Err(error) => {
                    tracing::warn!("notify hook spawn failed: {}", error);
                    return;
                }
            };
            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                if stdin.write_all(&payload).await.is_err() || stdin.shutdown().await.is_err() {
                    let _ = child.kill().await;
                    tracing::warn!("notify hook stdin failed");
                    return;
                }
            }
            match tokio::time::timeout(timeout, child.wait()).await {
                Ok(Ok(status)) if status.success() => {}
                Ok(Ok(status)) => tracing::warn!("notify hook exited with {}", status),
                Ok(Err(error)) => tracing::warn!("notify hook wait failed: {}", error),
                Err(_) => {
                    let _ = child.kill().await;
                    tracing::warn!("notify hook timed out after {}s", timeout.as_secs());
                }
            }
        });
    }
}

fn bounded_notify_text(value: Option<String>, max_chars: usize) -> Option<String> {
    value.map(|text| {
        if text.chars().count() <= max_chars {
            text
        } else {
            text.chars().take(max_chars).collect()
        }
    })
}

fn bounded_notify_event(mut event: NotifyEvent) -> NotifyEvent {
    event.handle = bounded_notify_text(event.handle, 128);
    event.session_fingerprint = bounded_notify_text(event.session_fingerprint, 96);
    event.reason = bounded_notify_text(event.reason, 1024);
    event.status = bounded_notify_text(event.status, 64);
    event
}

#[derive(Clone, Default)]
pub(super) struct ProcessTracker {
    active: Arc<Mutex<HashMap<u32, u64>>>,
    next_generation: Arc<AtomicU64>,
}

impl ProcessTracker {
    pub(super) fn track(&self, pid: u32) -> ProcessGuard {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        self.active
            .lock()
            .expect("process tracker poisoned")
            .insert(pid, generation);
        ProcessGuard {
            pid,
            generation,
            tracker: self.clone(),
            armed: true,
        }
    }

    fn take(&self, pid: u32, generation: u64) -> bool {
        let mut active = self.active.lock().expect("process tracker poisoned");
        if active.get(&pid) == Some(&generation) {
            active.remove(&pid);
            true
        } else {
            false
        }
    }

    pub(super) fn terminate_all(&self) {
        let active = {
            let mut active = self.active.lock().expect("process tracker poisoned");
            active.drain().map(|(pid, _)| pid).collect::<Vec<_>>()
        };
        for pid in active {
            terminate_process_tree(pid);
        }
    }

    pub(super) fn shutdown_guard(&self) -> ShutdownGuard {
        ShutdownGuard(self.clone())
    }
}

pub(super) struct ShutdownGuard(ProcessTracker);

impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        self.0.terminate_all();
    }
}

pub(super) struct ProcessGuard {
    pid: u32,
    generation: u64,
    tracker: ProcessTracker,
    armed: bool,
}

impl ProcessGuard {
    pub(super) fn complete(mut self) {
        self.tracker.take(self.pid, self.generation);
        self.armed = false;
    }

    pub(super) fn terminate(mut self) {
        if self.tracker.take(self.pid, self.generation) {
            terminate_process_tree(self.pid);
        }
        self.armed = false;
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if self.armed && self.tracker.take(self.pid, self.generation) {
            terminate_process_tree(self.pid);
        }
    }
}

#[cfg(unix)]
fn terminate_process_tree(pid: u32) {
    unsafe {
        // Brokered children are process-group leaders. A negative pid targets
        // the whole group while a setsid descendant remains intentionally
        // outside it.
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
}

#[cfg(windows)]
fn terminate_process_tree(pid: u32) {
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if !handle.is_null() {
            let _ = TerminateProcess(handle, 1);
            windows_sys::Win32::Foundation::CloseHandle(handle);
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn terminate_process_tree(_pid: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_payload_is_stable_and_secret_free() {
        let event = NotifyEvent {
            event: "hold_created",
            at_unix: 42,
            handle: Some("handle-1".into()),
            session_fingerprint: Some("session:abcd".into()),
            reason: Some("operator review".into()),
            status: Some("pending".into()),
            behavior: None,
        };
        let value = serde_json::to_value(event).expect("serialize event");
        assert_eq!(value["event"], "hold_created");
        assert_eq!(value["at_unix"], 42);
        assert_eq!(value["session_fingerprint"], "session:abcd");
        assert!(value.get("behavior").is_none());
        assert_eq!(value.as_object().expect("object").len(), 6);

        let recovery = NotifyEvent {
            event: "startup_recovery_escalated",
            at_unix: 43,
            handle: Some("recovery-1".into()),
            session_fingerprint: Some("sha256:abcd".into()),
            reason: Some("persisted rollback authority is unavailable".into()),
            status: Some("needs_operator_decision".into()),
            behavior: None,
        };
        let encoded = serde_json::to_string(&recovery).unwrap();
        assert!(encoded.contains("startup_recovery_escalated"));
        assert!(
            encoded.len() < 512,
            "recovery notification must stay bounded"
        );
        let bounded = bounded_notify_event(NotifyEvent {
            event: "startup_recovery_escalated",
            at_unix: 44,
            handle: Some("h".repeat(1_000)),
            session_fingerprint: None,
            reason: Some("r".repeat(100_000)),
            status: Some("needs_operator_decision".into()),
            behavior: None,
        });
        assert_eq!(bounded.handle.unwrap().len(), 128);
        assert_eq!(bounded.reason.unwrap().len(), 1024);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn notify_hook_receives_json_on_stdin() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output = temp.path().join("event.json");
        let hook = NotifyHook::new(
            vec![
                "sh".into(),
                "-c".into(),
                "cat > \"$1\"".into(),
                "sh".into(),
                output.display().to_string(),
            ],
            2,
        )
        .expect("hook");
        hook.emit(NotifyEvent {
            event: "provisional_due",
            at_unix: 7,
            handle: Some("p1".into()),
            session_fingerprint: None,
            reason: None,
            status: Some("reverting".into()),
            behavior: None,
        });

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        let value: serde_json::Value = loop {
            match tokio::fs::read(&output).await {
                Ok(bytes) => {
                    if let Ok(value) = serde_json::from_slice(&bytes) {
                        break value;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("notify output: {error}"),
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "notify hook did not produce valid JSON before the deadline"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };
        assert_eq!(value["event"], "provisional_due");
        assert_eq!(value["handle"], "p1");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn process_guard_terminates_the_owned_process_group() {
        use std::os::unix::process::CommandExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let marker = temp.path().join("grandchild-survived");
        let mut command = tokio::process::Command::new("sh");
        command.args([
            "-c",
            "(sleep 0.3; touch \"$1\") & wait",
            "sh",
            &marker.display().to_string(),
        ]);
        command.as_std_mut().process_group(0);
        let mut child = command.spawn().expect("spawn process group");
        let guard = ProcessTracker::default().track(child.id().expect("child pid"));
        guard.terminate();
        let _ = child.wait().await;
        tokio::time::sleep(std::time::Duration::from_millis(450)).await;
        assert!(!marker.exists(), "the grandchild escaped its owned group");
    }

    #[test]
    fn stale_guard_does_not_remove_a_reused_pid() {
        let tracker = ProcessTracker::default();
        let first = tracker.track(42);
        tracker
            .active
            .lock()
            .expect("process tracker poisoned")
            .clear();
        let second = tracker.track(42);

        first.complete();
        assert_eq!(
            tracker
                .active
                .lock()
                .expect("process tracker poisoned")
                .get(&42),
            Some(&second.generation)
        );
        second.complete();
    }

    #[test]
    fn command_handler_admission_is_fair_per_principal() {
        let admission = CommandAdmission::new(CommandAdmissionConfig {
            handler_concurrency: 2,
            principal_handler_concurrency: 1,
            ..CommandAdmissionConfig::default()
        });
        let _alice = admission.admit_handler("alice").expect("alice admitted");
        assert!(admission.admit_handler("alice").is_err());
        let _bob = admission.admit_handler("bob").expect("bob reserve remains");
        let status = admission.snapshot();
        assert_eq!(status.handler_admitted, 2);
        assert_eq!(status.handler_rejected, 1);
    }

    #[test]
    fn command_evaluator_rate_limit_and_circuit_recover() {
        let admission = CommandAdmission::new(CommandAdmissionConfig {
            evaluator_concurrency: 1,
            principal_evaluator_concurrency: 1,
            evaluator_rate_per_minute: 1,
            evaluator_burst: 2,
            evaluator_error_threshold: 1,
            evaluator_circuit_cooldown: Duration::from_millis(10),
            ..CommandAdmissionConfig::default()
        });
        let first = admission.admit_evaluator("alice").expect("first call");
        drop(first);
        admission.complete_evaluator("alice", true, true);
        assert!(admission.admit_evaluator("alice").is_err());
        std::thread::sleep(Duration::from_millis(20));
        let second = admission
            .admit_evaluator("alice")
            .expect("circuit recovered");
        drop(second);
        admission.complete_evaluator("alice", false, true);
        assert!(admission.admit_evaluator("alice").is_err());
        let status = admission.snapshot();
        assert_eq!(status.evaluator_admitted, 2);
        assert_eq!(status.evaluator_circuit_rejections, 1);
        assert_eq!(status.evaluator_rate_limited, 1);
        assert_eq!(status.evaluator_errors, 1);
    }

    #[test]
    fn command_evaluator_refunds_non_provider_decisions() {
        let admission = CommandAdmission::new(CommandAdmissionConfig {
            evaluator_rate_per_minute: 1,
            evaluator_burst: 1,
            ..CommandAdmissionConfig::default()
        });
        let permit = admission.admit_evaluator("alice").unwrap();
        drop(permit);
        admission.complete_evaluator("alice", false, false);
        assert!(admission.admit_evaluator("alice").is_ok());
        assert_eq!(admission.snapshot().evaluator_rate_limited, 0);
    }
}
