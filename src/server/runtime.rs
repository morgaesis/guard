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
        self.admit_evaluator_at(scope, Instant::now())
    }

    fn admit_evaluator_at(
        &self,
        scope: &str,
        now: Instant,
    ) -> Result<CommandEvaluatorPermit, &'static str> {
        self.counters
            .evaluator_attempted
            .fetch_add(1, Ordering::Relaxed);
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
        self.complete_evaluator_at(scope, error, provider_spend, Instant::now());
    }

    fn complete_evaluator_at(&self, scope: &str, error: bool, provider_spend: bool, now: Instant) {
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
    pub requester_principal: Option<String>,
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
    event.requester_principal = event
        .requester_principal
        .map(|principal| guard::redact::audit_escape(&principal).into_owned());
    event.requester_principal = bounded_notify_text(event.requester_principal, 128);
    event.reason = bounded_notify_text(
        event
            .reason
            .map(|reason| guard::gating::sanitize_gate_text(&reason)),
        1024,
    );
    event.status = bounded_notify_text(event.status, 64);
    event
}

// Child ownership is registered with a runtime-independent cleanup worker
// before spawn. Signaling and reaping use the same lock, so a reaped PID is
// never retained as a target for a delayed group signal.
#[derive(Clone)]
pub(super) struct ChildOwnership(Arc<Mutex<OwnedChildState>>);

struct OwnedChildState {
    child: Option<std::process::Child>,
    status: Option<std::process::ExitStatus>,
    pending_launch: bool,
    cleanup: ChildCleanup,
    secret_files: Option<super::secure_fs::SecretFileLease>,
    #[cfg(test)]
    signals: usize,
}

#[derive(Clone, Copy)]
enum ChildCleanup {
    Running,
    Graceful(Instant),
    Forced,
}

impl OwnedChildState {
    fn signal(&mut self, graceful: bool) {
        if let Some(child) = self.child.as_mut() {
            #[cfg(test)]
            {
                self.signals += 1;
            }
            #[cfg(unix)]
            unsafe {
                libc::kill(
                    -(child.id() as i32),
                    if graceful {
                        libc::SIGTERM
                    } else {
                        libc::SIGKILL
                    },
                );
            }
            // Windows uses the retained process handle. On Unix this also
            // covers a leader that moved itself out of its original group.
            if !graceful || !cfg!(unix) {
                let _ = child.kill();
            }
        }
    }

    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        // Keep the leader unreaped until the final group signal. Its PID
        // cannot be reused while the grace deadline is outstanding.
        if matches!(self.cleanup, ChildCleanup::Graceful(_)) {
            return Ok(None);
        }
        let Some(child) = self.child.as_mut() else {
            return Ok(None);
        };
        let status = child.try_wait()?;
        if let Some(status) = status {
            self.status = Some(status);
            self.child = None;
            self.secret_files = None;
        }
        Ok(status)
    }

    fn cleanup_tick(&mut self) -> bool {
        if let ChildCleanup::Graceful(deadline) = self.cleanup {
            if Instant::now() >= deadline {
                self.signal(false);
                self.cleanup = ChildCleanup::Forced;
            }
        }
        if matches!(self.cleanup, ChildCleanup::Forced) {
            // Errors retain ownership for a later attempt; a foreground
            // timeout never discards an unreaped child or its secret lease.
            let _ = self.try_wait();
        }
        !self.pending_launch && self.child.is_none()
    }
}

fn register_child_cleanup(state: Arc<Mutex<OwnedChildState>>) -> std::io::Result<()> {
    type Sender = std::sync::mpsc::Sender<Arc<Mutex<OwnedChildState>>>;
    static WORKER: std::sync::OnceLock<Mutex<Option<Sender>>> = std::sync::OnceLock::new();
    let mut sender = WORKER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if sender.is_none() {
        let (tx, rx) = std::sync::mpsc::channel::<Arc<Mutex<OwnedChildState>>>();
        std::thread::Builder::new()
            .name("guard-child-cleanup".into())
            .spawn(move || {
                let mut children = Vec::new();
                loop {
                    let received = if children.is_empty() {
                        rx.recv()
                            .map_err(|_| std::sync::mpsc::RecvTimeoutError::Disconnected)
                    } else {
                        rx.recv_timeout(Duration::from_millis(10))
                    };
                    match received {
                        Ok(child) => children.push(child),
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
                            if children.is_empty() =>
                        {
                            break
                        }
                        Err(_) => {}
                    }
                    children.extend(rx.try_iter());
                    children.retain(|child| {
                        !child
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .cleanup_tick()
                    });
                }
            })?;
        *sender = Some(tx);
    }
    if sender
        .as_ref()
        .expect("cleanup sender initialized")
        .send(state)
        .is_err()
    {
        *sender = None;
        return Err(std::io::Error::other("child cleanup worker is unavailable"));
    }
    Ok(())
}

impl ChildOwnership {
    pub(super) fn prepare(
        secret_files: Option<super::secure_fs::SecretFileLease>,
    ) -> std::io::Result<Self> {
        let state = Arc::new(Mutex::new(OwnedChildState {
            child: None,
            status: None,
            pending_launch: true,
            cleanup: ChildCleanup::Running,
            secret_files,
            #[cfg(test)]
            signals: 0,
        }));
        register_child_cleanup(state.clone())?;
        Ok(Self(state))
    }

    pub(super) fn adopt(&self, child: std::process::Child) {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.child = Some(child);
        state.pending_launch = false;
    }

    pub(super) fn id(&self) -> Option<u32> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .child
            .as_ref()
            .map(std::process::Child::id)
    }

    pub(super) fn take_stdout(&self) -> Option<std::process::ChildStdout> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .child
            .as_mut()?
            .stdout
            .take()
    }

    pub(super) fn take_stderr(&self) -> Option<std::process::ChildStderr> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .child
            .as_mut()?
            .stderr
            .take()
    }

    pub(super) fn try_wait(&self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .try_wait()
    }

    pub(super) fn terminate(&self, graceful: bool) {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.pending_launch = false;
        if state.child.is_none() {
            state.secret_files = None;
            return;
        }
        if graceful && matches!(state.cleanup, ChildCleanup::Running) {
            state.signal(true);
            state.cleanup = if cfg!(unix) {
                ChildCleanup::Graceful(Instant::now() + Duration::from_secs(2))
            } else {
                ChildCleanup::Forced
            };
        } else if !graceful {
            state.signal(false);
            state.cleanup = ChildCleanup::Forced;
        }
    }

    pub(super) async fn wait_for_cleanup(&self) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while self.id().is_some() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

#[derive(Clone, Default)]
pub(super) struct ProcessTracker {
    active: Arc<Mutex<HashMap<u64, ChildOwnership>>>,
    next_generation: Arc<AtomicU64>,
}

impl ProcessTracker {
    pub(super) fn track(&self, child: ChildOwnership) -> ProcessGuard {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        self.active
            .lock()
            .expect("process tracker poisoned")
            .insert(generation, child);
        ProcessGuard {
            generation,
            tracker: self.clone(),
            armed: true,
        }
    }

    fn take(&self, generation: u64) -> Option<ChildOwnership> {
        self.active
            .lock()
            .expect("process tracker poisoned")
            .remove(&generation)
    }

    pub(super) fn terminate_all(&self) {
        let active = {
            let mut active = self.active.lock().expect("process tracker poisoned");
            active.drain().map(|(_, child)| child).collect::<Vec<_>>()
        };
        for child in active {
            child.terminate(false);
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
    generation: u64,
    tracker: ProcessTracker,
    armed: bool,
}

impl ProcessGuard {
    pub(super) fn complete(mut self) {
        self.tracker.take(self.generation);
        self.armed = false;
    }

    pub(super) async fn terminate_gracefully(mut self) {
        if let Some(child) = self.tracker.take(self.generation) {
            child.terminate(true);
            self.armed = false;
            child.wait_for_cleanup().await;
        }
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if self.armed {
            if let Some(child) = self.tracker.take(self.generation) {
                child.terminate(false);
            }
        }
    }
}

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
            requester_principal: None,
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
            requester_principal: None,
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
        let value = ["q", "7"].concat();
        let bounded = bounded_notify_event(NotifyEvent {
            event: "startup_recovery_escalated",
            at_unix: 44,
            handle: Some("h".repeat(1_000)),
            session_fingerprint: None,
            requester_principal: None,
            reason: Some(format!("password={value}{}", "r".repeat(100_000))),
            status: Some("needs_operator_decision".into()),
            behavior: None,
        });
        assert_eq!(bounded.handle.unwrap().len(), 128);
        let reason = bounded.reason.unwrap();
        assert!(reason.chars().count() <= 1024);
        assert!(!reason.contains(&value));
        assert!(reason.contains("[REDACTED]"));
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
            requester_principal: None,
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
        let child = ChildOwnership::prepare(None).expect("cleanup owner");
        child.adopt(command.as_std_mut().spawn().expect("spawn process group"));
        let guard = ProcessTracker::default().track(child.clone());
        drop(guard);
        child.wait_for_cleanup().await;
        assert!(child.id().is_none(), "child must be reaped");
        tokio::time::sleep(std::time::Duration::from_millis(450)).await;
        assert!(!marker.exists(), "the grandchild escaped its owned group");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn graceful_termination_sends_sigterm_before_sigkill() {
        use std::os::unix::process::CommandExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let marker = temp.path().join("term-observed");
        let ready = temp.path().join("trap-ready");
        let mut command = tokio::process::Command::new("sh");
        command.arg("-c").arg(format!(
            "trap 'printf term > {}; exit 0' TERM; printf ready > {}; while :; do sleep 1; done",
            marker.display(),
            ready.display()
        ));
        command.as_std_mut().process_group(0);
        let child = ChildOwnership::prepare(None).expect("cleanup owner");
        child.adopt(command.as_std_mut().spawn().expect("spawn process group"));
        let guard = ProcessTracker::default().track(child.clone());
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !ready.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("shell installed its SIGTERM trap");

        guard.terminate_gracefully().await;
        assert!(child.try_wait().unwrap().is_some(), "child must be reaped");
        assert_eq!(std::fs::read_to_string(marker).unwrap(), "term");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn cleanup_retains_leader_and_secret_lease_until_final_signal() {
        use std::os::unix::process::CommandExt;
        let directory = tempfile::tempdir().unwrap();
        let (lease, bindings) = super::super::secure_fs::SecretFileLease::create(
            directory.path(),
            &[("FIXTURE_FILE".into(), "fixture-value".into())],
        )
        .unwrap();
        let child = ChildOwnership::prepare(Some(lease)).unwrap();
        let mut command = std::process::Command::new("true");
        command.process_group(0);
        child.adopt(command.spawn().unwrap());
        let pid = child.id().unwrap();
        child.terminate(true);
        // Even an exited leader remains waitable, anchoring the process group
        // until the cleanup owner has sent its last signal.
        assert_eq!(child.try_wait().unwrap(), None);
        assert_eq!(child.id(), Some(pid));
        assert!(bindings[0].1.exists());
        child.terminate(false);
        child.wait_for_cleanup().await;
        assert!(child.try_wait().unwrap().is_some());
        assert!(child.id().is_none());
        assert!(!bindings[0].1.exists());
        let signals = child.0.lock().unwrap().signals;
        child.terminate(true);
        child.terminate(false);
        assert_eq!(child.0.lock().unwrap().signals, signals);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn cleanup_deadline_retains_unreaped_child_and_secret_lease() {
        use std::os::unix::process::CommandExt;
        let directory = tempfile::tempdir().unwrap();
        let (lease, bindings) = super::super::secure_fs::SecretFileLease::create(
            directory.path(),
            &[("FIXTURE_FILE".into(), "fixture-value".into())],
        )
        .unwrap();
        let child = ChildOwnership::prepare(Some(lease)).unwrap();
        let mut command = std::process::Command::new("sleep");
        command.arg("30").process_group(0);
        child.adopt(command.spawn().unwrap());
        child.terminate(true);
        child.0.lock().unwrap().cleanup =
            ChildCleanup::Graceful(Instant::now() + Duration::from_secs(60));
        tokio::time::timeout(Duration::from_secs(4), child.wait_for_cleanup())
            .await
            .unwrap();
        let retained_child = child.id().is_some();
        let retained_lease = bindings[0].1.exists();
        child.terminate(false);
        child.wait_for_cleanup().await;
        assert!(retained_child, "foreground timeout must retain ownership");
        assert!(
            retained_lease,
            "foreground timeout must retain secret files"
        );
        assert!(child.id().is_none());
        assert!(!bindings[0].1.exists());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn tracker_shutdown_and_guard_drop_do_not_signal_reaped_children() {
        use std::os::unix::process::CommandExt;
        let child = ChildOwnership::prepare(None).unwrap();
        let mut command = std::process::Command::new("true");
        command.process_group(0);
        child.adopt(command.spawn().unwrap());
        let tracker = ProcessTracker::default();
        let guard = tracker.track(child.clone());
        tokio::time::timeout(Duration::from_secs(2), async {
            while child.try_wait().unwrap().is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        tracker.terminate_all();
        drop(guard);
        assert_eq!(child.0.lock().unwrap().signals, 0);
    }

    #[test]
    fn stale_guard_does_not_remove_a_new_registration() {
        let tracker = ProcessTracker::default();
        let child = ChildOwnership::prepare(None).unwrap();
        let first = tracker.track(child.clone());
        let second = tracker.track(child.clone());
        first.complete();
        assert!(tracker
            .active
            .lock()
            .unwrap()
            .contains_key(&second.generation));
        second.complete();
        child.terminate(false);
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
        let now = Instant::now();
        let first = admission
            .admit_evaluator_at("alice", now)
            .expect("first call");
        drop(first);
        admission.complete_evaluator_at("alice", true, true, now);
        assert!(admission
            .admit_evaluator_at("alice", now + Duration::from_millis(9))
            .is_err());
        let recovered_at = now + Duration::from_millis(10);
        let second = admission
            .admit_evaluator_at("alice", recovered_at)
            .expect("circuit recovered");
        drop(second);
        admission.complete_evaluator_at("alice", false, true, recovered_at);
        assert!(admission.admit_evaluator_at("alice", recovered_at).is_err());
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
