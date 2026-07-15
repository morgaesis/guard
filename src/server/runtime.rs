//! Daemon runtime side effects: operator notifications and child ownership.

use serde::Serialize;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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
        while !output.exists() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let value: serde_json::Value =
            serde_json::from_slice(&tokio::fs::read(&output).await.expect("notify output"))
                .expect("valid JSON");
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
}
