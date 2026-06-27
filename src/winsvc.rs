//! Windows service host.
//!
//! `guard.exe` is a console binary. The Windows installer registers it as a
//! service whose binPath is `guard.exe server start ... --service`. When the
//! Service Control Manager launches that command the process must answer the
//! SCM start/stop handshake from a dispatcher thread, or the SCM kills it with
//! error 1053 ("the service did not respond to the start or control request in
//! a timely fashion"). This module provides that handshake and then runs the
//! exact same [`crate::run_server`] path a foreground daemon runs, so the
//! service and the interactive daemon share one configuration surface and one
//! code path — there is no separate service config or policy.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tokio::sync::Notify;
use tracing_subscriber::EnvFilter;
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

/// Service name. Must match the name the installer registers and the
/// `NT SERVICE\guard` virtual account that owns the bypass boundary.
const SERVICE_NAME: &str = "guard";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// True when this process was launched as the Windows service. The installer's
/// binPath is `... server start ... --service`; the SCM relaunches that exact
/// command line, so detecting the `server start` subcommand plus the hidden
/// `--service` marker in argv (here without argv[0]) identifies the service
/// start. An interactive `guard server start` never sets `--service`, so the
/// foreground path is never mistaken for a service start.
pub fn is_service_invocation(args: &[String]) -> bool {
    let is_server_start = args.windows(2).any(|w| w[0] == "server" && w[1] == "start");
    is_server_start && args.iter().any(|a| a == "--service")
}

/// Hand control to the SCM dispatcher. Blocks until the service stops, then
/// returns. Call only when [`is_service_invocation`] is true.
pub fn run() -> Result<()> {
    init_service_logging();
    tracing::info!("guard service: connecting to the Service Control Manager");
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("failed to start the service control dispatcher (StartServiceCtrlDispatcher)")?;
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

/// Entry point the SCM invokes through the generated FFI shim. Errors can only
/// be logged here; they cannot cross the FFI boundary.
fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!("guard service exited with error: {e:#}");
    }
}

fn run_service() -> Result<()> {
    // Stop signal shared with the SCM control handler. tokio's `Notify` retains
    // a single permit when notified with no waiter present, so a Stop that
    // races startup is delivered to the first subsequent `notified()` rather
    // than lost.
    let stop = Arc::new(Notify::new());
    let stop_for_handler = stop.clone();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                stop_for_handler.notify_one();
                ServiceControlHandlerResult::NoError
            }
            // The SCM polls Interrogate; acknowledging keeps the reported state.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("failed to register the service control handler")?;

    let status = |state: ServiceState, accept: ServiceControlAccept, exit: u32| ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: Duration::from_secs(0),
        process_id: None,
    };

    // The daemon binds its listener early; report RUNNING and accept Stop. If
    // the daemon fails immediately the select below returns an error and we
    // report STOPPED with a non-zero exit, which trips the installer-configured
    // SCM restart action.
    status_handle
        .set_service_status(status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            0,
        ))
        .context("failed to report SERVICE_RUNNING")?;

    let cmd = parse_server_command().context("parsing the service command line")?;

    // The service owns the only tokio runtime in this code path: `main` hands
    // off to the dispatcher before building a foreground runtime, and this
    // function runs on the SCM-created service thread, which has no ambient
    // runtime. Building one here is therefore safe.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the service tokio runtime")?;

    let run_result = runtime.block_on(async move {
        tokio::select! {
            r = crate::run_server(cmd) => r,
            _ = stop.notified() => {
                tracing::info!("guard service: stop requested; shutting down");
                Ok(())
            }
        }
    });

    if let Err(e) = &run_result {
        tracing::error!("guard service: daemon terminated with error: {e:#}");
    }

    let exit = if run_result.is_ok() { 0 } else { 1 };
    status_handle
        .set_service_status(status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            exit,
        ))
        .context("failed to report SERVICE_STOPPED")?;

    run_result
}

/// Re-parse the process argv into the `server start` command. The service is
/// launched with the full flag set in its binPath, so this reuses the exact
/// clap definition the foreground CLI uses; the service has no bespoke config.
fn parse_server_command() -> Result<crate::ServerCommands> {
    match crate::MainArgs::try_parse_from(std::env::args()) {
        Ok(crate::MainArgs::Server(cmd)) => Ok(cmd),
        Ok(_) => Err(anyhow!(
            "service launched without a `server start` command line"
        )),
        Err(e) => Err(anyhow!("could not parse the service command line: {e}")),
    }
}

/// Directory for the service log file: `%ProgramData%\guard`. It sits inside
/// the ACL-locked data directory the installer creates, so only the operator
/// (`NT SERVICE\guard`) and administrators can read it.
fn service_log_dir() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(base).join("guard")
}

/// Initialize logging to a file under the data directory. A service has no
/// console, so foreground stderr logging would be invisible and a failed start
/// would be undiagnosable. Level comes from `RUST_LOG`, then `GUARD_LOG_LEVEL`,
/// else `info`.
fn init_service_logging() {
    let dir = service_log_dir();
    let _ = std::fs::create_dir_all(&dir);
    let log_path = dir.join("guard.log");
    let level = std::env::var("RUST_LOG")
        .ok()
        .or_else(|| crate::guard_env("LOG_LEVEL"))
        .unwrap_or_else(|| "info".to_string());
    // Reopen-on-write (append) keeps the daemon from holding a long-lived
    // handle; guard's logging is sparse (startup plus per-command), so the cost
    // is negligible. A failed open degrades to a sink rather than panicking
    // inside the logging path.
    let make_writer = move || {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map(|f| Box::new(f) as Box<dyn std::io::Write>)
            .unwrap_or_else(|_| Box::new(std::io::sink()))
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(level))
        .with_ansi(false)
        .with_writer(make_writer)
        .try_init();
}
