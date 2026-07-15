use crate::evaluate::Evaluator;
use crate::grant_profile::SavedGrantCatalog;
use crate::secrets::SecretManager;
use crate::session::SessionRegistry;
use crate::session_store::SessionStore;
use crate::tool_config::ToolRegistry;
#[cfg(unix)]
use anyhow::bail;
use anyhow::{Context, Result};
use guard::gating::approval::{ApprovalRegistry, ApprovalStatus};
use guard::gating::provisional::ProvisionalRegistry;
#[cfg(windows)]
use guard::gating::provisional::ProvisionalStatus;
#[cfg(unix)]
use guard::gating::read_grant::{GrantReadRegistry, ReadGrantStatus};
use guard::gating::verb::VerbCatalog;
use guard::gating::GateMode;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
#[cfg(unix)]
use tokio::process::Command;
use tokio::sync::RwLock;

use super::admin::handle_admin_request;
use super::execute::{execute_command, execute_command_streaming, record_live_session_interaction};
#[cfg(unix)]
use super::gate_runtime::revert_dir_is_owner_only;
use super::gate_runtime::{gating_sweeper, is_api_proxy_sentinel, now_unix, DaemonGateSink};
#[cfg(unix)]
use super::grants::{delete_read_grant_row, revoke_read_grant_acls};
use super::wire::{
    AdminRequest, AdminResponse, CallerIdentity, ExecOutcome, ExecuteResponse, ExecuteResult,
    ExecuteStreamMessage, IncomingMessage,
};
use super::{
    ServerConfig, DEFAULT_CONFIRM_WITHIN_SECS, MAX_REQUEST_BYTES, SESSION_MAINTENANCE_INTERVAL_SECS,
};
use crate::session::{SessionDecisionSource, SessionExecStatus, SessionInteraction};

#[derive(Clone)]
struct DaemonApiSessionSink {
    config: ServerConfig,
}

fn api_session_exec_status(allowed: bool, held: bool) -> SessionExecStatus {
    if held && allowed {
        SessionExecStatus::CompletedAfterApproval
    } else if held {
        SessionExecStatus::Held
    } else if allowed {
        SessionExecStatus::Completed
    } else {
        SessionExecStatus::NotAttempted
    }
}

#[async_trait::async_trait]
impl guard::proxy::ApiSessionSink for DaemonApiSessionSink {
    async fn resolve(&self, token: &str) -> Option<guard::proxy::ApiSessionContext> {
        let registry = self.config.sessions.read().await;
        if registry
            .suspension_reason(token, &self.config.behavior_limits)
            .is_some()
        {
            return None;
        }
        let (fingerprint, intent) = registry.api_authority_for(token)?;
        let (revision, secret_entitlements) = registry.authority_snapshot(token)?;
        let evaluation_mode = registry.evaluation_mode_for(token).unwrap_or_default();
        Some(guard::proxy::ApiSessionContext {
            fingerprint,
            revision,
            secret_entitlements,
            can_evaluate_api_override: evaluation_mode
                == crate::grant_profile::EvaluationMode::Evaluator
                && intent
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty()),
            evaluation_mode: match evaluation_mode {
                crate::grant_profile::EvaluationMode::Evaluator => {
                    guard::proxy::ApiEvaluationMode::Evaluator
                }
                crate::grant_profile::EvaluationMode::PolicyOnly => {
                    guard::proxy::ApiEvaluationMode::PolicyOnly
                }
                crate::grant_profile::EvaluationMode::ReadOnly => {
                    guard::proxy::ApiEvaluationMode::ReadOnly
                }
            },
            intent,
        })
    }

    async fn record(&self, token: &str, event: guard::proxy::ApiSessionEvent) {
        record_live_session_interaction(
            &self.config,
            Some(token),
            SessionInteraction {
                at_unix: 0,
                command: format!("api:{} {}", event.endpoint, event.operation),
                allowed: event.allowed,
                source: SessionDecisionSource::ApiProxy,
                reason: format!("API proxy returned HTTP {}", event.status),
                risk: None,
                exec_status: api_session_exec_status(event.allowed, event.held),
                exit_code: None,
                exposed_secret_refs: if event.allowed {
                    vec![event.credential_ref]
                } else {
                    Vec::new()
                },
            },
        )
        .await;
    }
}

#[cfg(test)]
mod api_session_event_tests {
    use super::*;

    #[test]
    fn approved_api_hold_records_both_approval_and_completion() {
        assert_eq!(
            api_session_exec_status(true, true),
            SessionExecStatus::CompletedAfterApproval
        );
        assert_eq!(
            api_session_exec_status(false, true),
            SessionExecStatus::Held
        );
        assert_eq!(
            api_session_exec_status(true, false),
            SessionExecStatus::Completed
        );
    }
}

#[derive(Clone)]
pub struct Server {
    config: ServerConfig,
}

impl Server {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        socket_path: Option<PathBuf>,
        tcp_port: Option<u16>,
        evaluator: Evaluator,
        secrets: SecretManager,
        redact: bool,
        auth_token: Option<String>,
        admin_token: Option<String>,
        socket_group: Option<String>,
        allowed_uids: Option<Vec<u32>>,
        shim_dir: Option<PathBuf>,
        dry_run: bool,
        tool_registry: ToolRegistry,
        redact_secrets: Vec<String>,
        preflight: bool,
        sessions: SessionRegistry,
        session_store: Option<SessionStore>,
        exec_as_caller: bool,
        state_db_path: Option<PathBuf>,
    ) -> Result<Self> {
        let config = ServerConfig::new(
            socket_path,
            tcp_port,
            evaluator,
            secrets,
            redact,
            auth_token,
            admin_token,
            socket_group,
            allowed_uids,
            shim_dir,
            dry_run,
            tool_registry,
            redact_secrets,
            preflight,
            sessions,
            session_store,
            exec_as_caller,
            state_db_path,
        );
        let mut server = Self { config };
        let root = server
            .config
            .state_db_path
            .as_ref()
            .and_then(|path| path.parent())
            .map(|path| path.join("secret-files"))
            .unwrap_or_else(|| std::env::temp_dir().join("guard-secret-files"));
        super::secure_fs::prepare_private_root(&root)
            .with_context(|| format!("prepare secret-file root {}", root.display()))?;
        server.config.secret_file_root = Some(root);
        Ok(server)
    }

    /// Enable consequence gating. Must be called before `run`.
    pub fn set_gate(&mut self, gate: GateMode) {
        self.config.gate = gate;
    }

    pub fn set_approval_ttl(&mut self, ttl_secs: u64) {
        self.config.approval_ttl_secs = ttl_secs;
    }

    /// Configure the optional operator notification command.
    pub fn set_notify_hook(&mut self, command: Vec<String>, timeout_secs: u64) {
        self.config.notify_hook = super::runtime::NotifyHook::new(command, timeout_secs);
    }

    pub fn set_behavior_limits(&mut self, limits: crate::session::SessionBehaviorLimits) {
        self.config.behavior_limits = limits;
    }

    /// Install the operator-defined verb catalog. Must be called before `run`.
    pub fn set_verbs(&mut self, catalog: VerbCatalog) {
        self.config.verbs = Arc::new(RwLock::new(catalog));
    }

    /// Install reusable grants. Must be called before `run`.
    pub fn set_saved_grants(&mut self, catalog: SavedGrantCatalog) {
        self.config.saved_grants = Arc::new(RwLock::new(catalog));
    }

    /// Restrict which binaries may execute. `None` imposes no restriction (the
    /// default); an empty list denies everything. Must be called before `run`.
    pub fn set_allowed_binaries(&mut self, allowed: Option<Vec<String>>) {
        self.config.allowed_binaries = allowed;
    }

    /// Set the operator-declared extra child-env passthrough list (see
    /// [`ServerConfig::extra_child_env`]). Must be called before `run`.
    pub fn set_extra_child_env(&mut self, vars: Vec<String>) {
        self.config.extra_child_env = vars;
    }

    pub fn set_api_coverage(
        &mut self,
        store: Option<Arc<RwLock<guard::gating::api_promotion::ApiPromotionStore>>>,
    ) {
        self.config.api_coverage = store;
    }

    /// Attach an API proxy to run alongside the gate socket. Must be
    /// called before `run`.
    pub async fn register_api_proxy(
        &mut self,
        name: impl Into<String>,
        proxy: Arc<guard::proxy::ApiProxy>,
    ) {
        proxy.attach_session_sink(Arc::new(DaemonApiSessionSink {
            config: self.config.clone(),
        }));
        self.config
            .protocol_registry
            .write()
            .await
            .insert(name.into(), proxy);
    }

    /// Load persisted provisional/approval state and apply startup recovery:
    /// no revert ever runs unattended at boot. Past-deadline or interrupted
    /// provisionals become `needs_operator_decision`; interrupted approvals
    /// become `exec_failed`. Both are surfaced via a high-severity audit line.
    async fn startup_gating(&self) {
        let Some(store) = &self.config.session_store else {
            self.install_saved_grant_verbs().await;
            tracing::info!(
                "No state database configured: saved grants, grant requests, sessions, and gate state are process-local"
            );
            return;
        };

        match (
            store.load_saved_grants().await,
            store.load_saved_grant_tombstones().await,
        ) {
            (Ok(rows), Ok(tombstones)) => {
                let mut grants = self.config.saved_grants.write().await;
                if let Err(error) = grants.overlay_rows(rows) {
                    tracing::error!("failed to validate saved grants: {}", error);
                    *grants = crate::grant_profile::SavedGrantCatalog::empty();
                } else {
                    grants.apply_tombstones(&tombstones);
                }
            }
            (rows, tombstones) => {
                tracing::error!(
                    "failed to load durable saved-grant state: rows={:?}, tombstones={:?}",
                    rows.err(),
                    tombstones.err()
                );
                *self.config.saved_grants.write().await =
                    crate::grant_profile::SavedGrantCatalog::empty();
            }
        }
        self.install_saved_grant_verbs().await;
        match store.load_grant_requests().await {
            Ok(rows) => {
                *self.config.grant_requests.write().await = rows
                    .into_iter()
                    .map(|request| (request.handle.clone(), request))
                    .collect();
                super::admin::prune_grant_requests(&self.config).await;
            }
            Err(error) => tracing::error!("failed to load grant requests: {}", error),
        }

        match store.load_provisionals().await {
            Ok(rows) => {
                #[cfg(windows)]
                let mut rows = rows;
                #[cfg(windows)]
                if let Some(state_parent) = self
                    .config
                    .state_db_path
                    .as_ref()
                    .and_then(|path| path.parent())
                {
                    let snapshot_dir = state_parent.join("api-proxy-reverts");
                    let dir_safe = std::fs::create_dir_all(&snapshot_dir).is_ok()
                        && super::secure_fs::harden_existing_private_path(&snapshot_dir, true);
                    for row in &mut rows {
                        let Some(body_file) = row
                            .api_revert
                            .as_ref()
                            .and_then(|revert| revert.body_file.as_ref())
                            .cloned()
                        else {
                            continue;
                        };
                        let file_safe = dir_safe
                            && body_file.parent() == Some(snapshot_dir.as_path())
                            && super::secure_fs::harden_existing_private_path(&body_file, false);
                        if !file_safe {
                            row.status = ProvisionalStatus::RevertFailed;
                            row.revert_detail = Some(
                                "persisted API-revert body failed the Windows daemon-only ACL check"
                                    .to_string(),
                            );
                            tracing::error!(
                                "[AUDIT] API_REVERT_FILE_UNSAFE handle={} path=\"{}\"",
                                row.handle,
                                body_file.display()
                            );
                            if let Err(e) = store.save_provisional(row.clone()).await {
                                tracing::warn!(
                                    "failed to persist unsafe API-revert state {}: {}",
                                    row.handle,
                                    e
                                );
                            }
                        }
                    }
                }
                let (reg, moved) = ProvisionalRegistry::from_rows(rows);
                if !moved.is_empty() {
                    tracing::warn!(target: "guard::audit",
                        "[AUDIT] STARTUP_RECOVERY provisionals_needing_decision={} handles={:?} (no revert runs unattended at boot)",
                        moved.len(),
                        moved
                    );
                    for h in &moved {
                        if let Some(p) = reg.get(h) {
                            if let Err(e) = store.save_provisional(p.clone()).await {
                                tracing::warn!(
                                    "failed to persist recovered provisional {}: {}",
                                    h,
                                    e
                                );
                            }
                        }
                    }
                }
                *self.config.provisional.write().await = reg;
            }
            Err(e) => tracing::error!("failed to load provisional state: {}", e),
        }

        match store.load_approvals().await {
            Ok(rows) => {
                let now = now_unix();
                let (mut reg, recovered) = ApprovalRegistry::from_rows(rows, now);
                if !recovered.is_empty() {
                    tracing::warn!(target: "guard::audit",
                        "[AUDIT] STARTUP_RECOVERY approvals_exec_failed={} handles={:?} (exec interrupted by restart)",
                        recovered.len(),
                        recovered
                    );
                    for h in &recovered {
                        if let Some(a) = reg.get(h) {
                            if let Err(e) = store.save_approval(a.clone()).await {
                                tracing::warn!("failed to persist recovered approval {}: {}", h, e);
                            }
                        }
                    }
                }
                // An API-proxy hold cannot survive a restart: the parked HTTP
                // request died with the old process, so a still-pending row
                // would offer the operator an approval that releases nothing.
                // A proxy hold is identified the same way the approve path
                // identifies one: the sentinel binary AND daemon-principal
                // ownership (peer credentials assign that principal only to the
                // daemon's own gate sink).
                let orphaned: Vec<String> = reg
                    .list()
                    .into_iter()
                    .filter(|a| {
                        a.status == ApprovalStatus::Pending
                            && is_api_proxy_sentinel(&a.snapshot.binary)
                            && matches!(&a.snapshot.principal, Some(p) if self.config.daemon_principal.eq_ci(p))
                    })
                    .map(|a| a.handle)
                    .collect();
                for h in &orphaned {
                    reg.set_exec_failed(
                        h,
                        now,
                        "daemon restarted; the held API request is gone".to_string(),
                    );
                    if let Some(a) = reg.get(h) {
                        if let Err(e) = store.save_approval(a.clone()).await {
                            tracing::warn!("failed to persist retired proxy hold {}: {}", h, e);
                        }
                    }
                }
                if !orphaned.is_empty() {
                    tracing::warn!(target: "guard::audit",
                        "[AUDIT] STARTUP_RECOVERY api_proxy_holds_retired={} handles={:?}",
                        orphaned.len(),
                        orphaned
                    );
                }
                *self.config.approvals.write().await = reg;
            }
            Err(e) => tracing::error!("failed to load approval state: {}", e),
        }
    }

    async fn install_saved_grant_verbs(&self) {
        let generated = self
            .config
            .saved_grants
            .read()
            .await
            .list()
            .into_iter()
            .flat_map(|grant| grant.generated_verbs)
            .collect::<Vec<_>>();
        let mut verbs = self.config.verbs.write().await;
        for verb in generated {
            if let Err(error) = verbs.upsert_saved_grant_verb(verb) {
                tracing::error!("failed to install generated saved-grant verb: {}", error);
            }
        }
    }

    /// Load persisted read grants at startup. Any grant already past its TTL is
    /// revoked immediately (a read grant only removes access, so this is always
    /// safe to do unattended, unlike a provisional revert); a grant still within
    /// its TTL is re-armed by loading it Active so the sweeper fires at its
    /// deadline.
    #[cfg(unix)]
    async fn startup_read_grants(&self) {
        let Some(store) = &self.config.session_store else {
            return;
        };
        let rows = match store.load_read_grants().await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!("failed to load read-grant state: {}", e);
                return;
            }
        };
        let reg = GrantReadRegistry::from_rows(rows);
        let now = now_unix();
        let mut surviving = GrantReadRegistry::new();
        for grant in reg.list() {
            if grant.status == ReadGrantStatus::Active && now >= grant.expires_unix {
                match revoke_read_grant_acls(&grant).await {
                    Ok(()) => {
                        tracing::warn!(target: "guard::audit",
                            "[AUDIT] READ_GRANT_REVOKED handle={} path=\"{}\" source=startup-expired",
                            grant.handle,
                            grant.target_path
                        );
                        delete_read_grant_row(&self.config, &grant.target_path).await;
                    }
                    Err(e) => {
                        tracing::warn!(target: "guard::audit",
                            "[AUDIT] READ_GRANT_REVOKE_FAILED handle={} path=\"{}\" source=startup-expired detail=\"{}\"",
                            grant.handle,
                            grant.target_path,
                            e
                        );
                        surviving.insert(grant);
                    }
                }
            } else {
                surviving.insert(grant);
            }
        }
        *self.config.read_grants.write().await = surviving;
    }

    pub async fn run(&self) -> Result<()> {
        tracing::info!("Server::run() called");
        let _process_shutdown = self.config.process_tracker.shutdown_guard();

        // Load durable authorization state. Consequence rows also receive
        // boot-safe recovery when gating is enabled.
        if self.config.gate.is_on() {
            tracing::info!("Consequence gating: {}", self.config.gate);
        }
        self.startup_gating().await;
        // Reconcile persisted read grants (revoke expired, re-arm live).
        #[cfg(unix)]
        self.startup_read_grants().await;

        // The single sweeper drives both consequence-gate reverts (gate-on only)
        // and read-grant expiries (Unix, gate-independent), so it runs whenever
        // either is live. Without this a read grant could outlive its TTL simply
        // because the daemon runs without consequence gating.
        if self.config.gate.is_on() || cfg!(unix) {
            let config = self.config.clone();
            tokio::spawn(async move { gating_sweeper(config).await });
        }
        if self.config.session_store.is_some() && claim_session_maintenance(&self.config) {
            let config = self.config.clone();
            tokio::spawn(async move { session_maintenance(config).await });
        }

        let mut futures = Vec::new();

        if let Some(ref socket_path) = self.config.socket_path {
            tracing::info!("Starting local listener on {}", socket_path.display());
            let path = socket_path.clone();
            let config = self.config.clone();
            futures.push(tokio::spawn(async move {
                Self::run_local_static(&path, &config).await
            }));
        }

        if let Some(port) = self.config.tcp_port {
            tracing::info!("Starting TCP listener on port {}", port);
            let config = self.config.clone();
            futures.push(tokio::spawn(async move {
                Self::run_tcp_static(port, &config).await
            }));
        }

        let proxies: Vec<_> = self
            .config
            .protocol_registry
            .read()
            .await
            .iter()
            .map(|(name, proxy)| (name.clone(), proxy.clone()))
            .collect();
        for (endpoint, proxy) in proxies {
            // The auto-revert envelope needs the consequence sweeper, which only
            // runs under `--gate consequence`. Without it the proxy still gates
            // (allow/deny/hold/redact) but forwards recoverable writes unwrapped.
            if self.config.gate.is_on() {
                // With a state DB the revert dir lives beside it (systemd
                // StateDirectory, 0700). Without one, provisionals are
                // process-local and not recovered across restart, so a fresh
                // private directory (unpredictable name, created owner-only) is
                // both sufficient and immune to a pre-created fixed-name dir a
                // local attacker could own.
                let snapshot_dir = match self
                    .config
                    .state_db_path
                    .as_ref()
                    .and_then(|p| p.parent())
                    .map(|d| d.join("api-proxy-reverts"))
                {
                    Some(dir) => {
                        if let Err(e) = std::fs::create_dir_all(&dir) {
                            tracing::warn!(
                                "could not create api-proxy revert dir {}: {}",
                                dir.display(),
                                e
                            );
                        }
                        dir
                    }
                    None => tempfile::Builder::new()
                        .prefix("guard-api-proxy-reverts-")
                        .tempdir()
                        .map(|d| d.keep())
                        .unwrap_or_else(|e| {
                            tracing::warn!("could not create private api-proxy revert dir: {}", e);
                            std::env::temp_dir().join("guard-api-proxy-reverts")
                        }),
                };
                // Revert bodies can carry secret material, so the directory must
                // be owner-only. Under systemd this sits under StateDirectory
                // (0700, daemon-owned); a bare-invocation fallback under the
                // shared temp dir could be pre-created by another local user, so
                // verify ownership and mode and refuse to arm body-bearing
                // reverts if the directory is not exclusively the daemon's.
                #[cfg(unix)]
                let snapshot_dir_safe = {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &snapshot_dir,
                        std::fs::Permissions::from_mode(0o700),
                    );
                    revert_dir_is_owner_only(&snapshot_dir)
                };
                #[cfg(windows)]
                let snapshot_dir_safe =
                    super::secure_fs::harden_existing_private_path(&snapshot_dir, true);
                #[cfg(not(any(unix, windows)))]
                let snapshot_dir_safe = false;
                if !snapshot_dir_safe {
                    tracing::error!(target: "guard::audit",
                        "[AUDIT] API_REVERT_DIR_UNSAFE path=\"{}\" (not owner-only; body-bearing auto-reverts are disabled)",
                        snapshot_dir.display()
                    );
                }
                proxy.attach_gate(Arc::new(DaemonGateSink {
                    config: self.config.clone(),
                    endpoint,
                    protocol: proxy.protocol_name().to_string(),
                    snapshot_dir,
                    snapshot_dir_safe,
                    window_secs: DEFAULT_CONFIRM_WITHIN_SECS,
                }));
            } else {
                tracing::info!(
                    "api-proxy ({}): --gate consequence not set; recoverable writes forwarded without auto-revert and policy holds deny fail-closed (no approval queue)",
                    proxy.protocol_name()
                );
            }
            tracing::info!(
                "Starting api-proxy ({}) listener on {}",
                proxy.protocol_name(),
                proxy.listen()
            );
            let proxy = proxy.clone();
            futures.push(tokio::spawn(async move { proxy.serve().await }));
        }

        if futures.is_empty() {
            anyhow::bail!("no socket path or TCP port specified");
        }

        let abort_handles = futures
            .iter()
            .map(tokio::task::JoinHandle::abort_handle)
            .collect::<Vec<_>>();
        let first = futures::future::select_all(futures);
        tokio::pin!(first);
        let (result, _, remaining) = tokio::select! {
            result = &mut first => result,
            _ = shutdown_signal() => {
                tracing::info!("shutdown requested; stopping listeners and brokered children");
                for handle in abort_handles {
                    handle.abort();
                }
                self.config.process_tracker.terminate_all();
                return Ok(());
            }
        };

        // A listener loop only returns on a fatal error. Wait for the first one,
        // abort the other infinite loops, and return the failure immediately so
        // one bad named endpoint cannot hide behind healthy listeners forever.
        for task in remaining {
            task.abort();
        }
        self.config.process_tracker.terminate_all();
        match result {
            Ok(Ok(())) => anyhow::bail!("listener exited unexpectedly"),
            Ok(Err(error)) => {
                tracing::error!("listener exited with error: {error:#}");
                Err(error)
            }
            Err(error) => {
                tracing::error!("listener task panicked: {error}");
                Err(anyhow::anyhow!("listener task panicked: {error}"))
            }
        }
    }

    /// Platform dispatch for the local listener: UNIX domain socket on Unix,
    /// named pipe on Windows.
    async fn run_local_static(socket_path: &Path, config: &ServerConfig) -> Result<()> {
        #[cfg(unix)]
        {
            Self::run_unix_static(socket_path, config).await
        }
        #[cfg(windows)]
        {
            Self::run_pipe_static(socket_path, config).await
        }
    }

    #[cfg(windows)]
    async fn run_pipe_static(socket_path: &Path, config: &ServerConfig) -> Result<()> {
        let pipe_name = winplat::pipe_name(socket_path);
        tracing::info!("guard server listening on named pipe {}", pipe_name);

        let mut server = winplat::create_pipe_server(&pipe_name, true)?;

        loop {
            // Wait for a client to connect to the current instance, then hand it
            // off and immediately stand up the next instance for the next client.
            server
                .connect()
                .await
                .context("named pipe connect failed")?;
            let connected = server;
            server = winplat::create_pipe_server(&pipe_name, false)?;

            let config = config.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_client_pipe(connected, &config).await {
                    tracing::error!("client handler error: {}", e);
                }
            });
        }
    }

    #[cfg(unix)]
    async fn run_unix_static(socket_path: &Path, config: &ServerConfig) -> Result<()> {
        let listener =
            Self::prepare_unix_listener(socket_path, config.socket_group.as_deref()).await?;

        tracing::info!("guard server listening on {}", socket_path.display());

        loop {
            match listener.accept().await {
                Ok((stream, _peer_addr)) => {
                    let config = config.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_client_unix(stream, &config).await {
                            tracing::error!("client handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("accept error: {}", e);
                }
            }
        }
    }

    #[cfg(unix)]
    async fn prepare_unix_listener(
        socket_path: &Path,
        socket_group: Option<&str>,
    ) -> Result<UnixListener> {
        if let Some(parent) = socket_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .context("failed to create socket directory")?;
        }

        if socket_path.exists() {
            tokio::fs::remove_file(socket_path).await?;
        }

        let listener = UnixListener::bind(socket_path).context("failed to bind UNIX socket")?;
        Self::chmod_path(socket_path, 0o600).await?;

        if let Some(group) = socket_group {
            Self::chown_to_group(socket_path, group).await?;
            Self::chmod_path(socket_path, 0o660).await?;
            if let Some(parent) = socket_path.parent() {
                Self::chmod_path(parent, 0o755).await?;
            }
        }
        Ok(listener)
    }

    async fn run_tcp_static(port: u16, config: &ServerConfig) -> Result<()> {
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr)
            .await
            .context("failed to bind TCP socket")?;

        tracing::info!("guard server listening on tcp://{}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let config = config.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_client_tcp(stream, &config).await {
                            tracing::error!("client handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("accept error: {}", e);
                }
            }
        }
    }

    #[cfg(unix)]
    async fn chown_to_group(path: &Path, group: &str) -> Result<()> {
        let output = Command::new("chgrp").arg(group).arg(path).output().await?;

        if !output.status.success() {
            bail!(
                "failed to change group of {} to {}: {}",
                path.display(),
                group,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    #[cfg(unix)]
    async fn chmod_path(path: &std::path::Path, mode: u32) -> Result<()> {
        let permissions = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, permissions)
            .with_context(|| format!("failed to chmod {} to {:o}", path.display(), mode))?;
        Ok(())
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => {
                tracing::warn!("failed to install SIGTERM handler: {error}");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Windows-only helpers: named-pipe name normalization and peer-SID resolution.
/// The SID is the Windows analog of a Unix peer UID — the kernel-verified
/// identity of the process on the other end of the local pipe.
#[cfg(windows)]
pub(crate) mod winplat {
    use anyhow::{bail, Context, Result};
    use std::os::windows::io::AsRawHandle;
    use tokio::net::windows::named_pipe::NamedPipeServer;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, RevertToSelf, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Pipes::{CreateNamedPipeW, ImpersonateNamedPipeClient};
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
    };

    // Named pipe creation flags (avoid extra feature imports for the constants).
    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
    const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x0000_0008; // byte type/readmode/wait = 0
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;
    const PIPE_BUF: u32 = 65536;

    /// Create a named-pipe server instance with an explicit security descriptor
    /// so local authenticated users can connect to the gate. A pipe's security
    /// must be set at creation time (the server handle has no WRITE_DAC), so we
    /// call CreateNamedPipeW directly and wrap the handle into tokio.
    ///
    /// Connect access is NOT the trust boundary: the gate enforces policy on
    /// every request and never exposes the brokered credentials. The boundary is
    /// the daemon's account isolation. On a multi-user host every authenticated
    /// local user can submit policy-gated work unless the deployment uses a
    /// build whose pipe DACL names only the intended agent SID.
    pub fn create_pipe_server(pipe_name: &str, first: bool) -> Result<NamedPipeServer> {
        let wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
        // The daemon's own account gets full control so it can create the
        // additional pipe instances each accepted client needs
        // (FILE_CREATE_PIPE_INSTANCE). A non-elevated daemon runs as a plain
        // Authenticated User, so without this it can create the first instance
        // but is denied the second (the AU ACE below excludes create-instance).
        // Administrators/SYSTEM also get full control. Authenticated Users get
        // only FILE_GENERIC_READ|FILE_GENERIC_WRITE (0x0012019b) so they can
        // CONNECT but NOT stand up rogue instances.
        let owner_sid =
            unsafe { process_user_sid() }.context("resolve daemon SID for pipe DACL")?;
        let sddl: Vec<u16> =
            format!("D:(A;;GA;;;{owner_sid})(A;;GA;;;BA)(A;;GA;;;SY)(A;;0x0012019b;;;AU)\0")
                .encode_utf16()
                .collect();
        unsafe {
            let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut psd,
                std::ptr::null_mut(),
            ) == 0
            {
                bail!(
                    "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: psd,
                bInheritHandle: 0,
            };
            let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
            if first {
                open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
            }
            let handle = CreateNamedPipeW(
                wide.as_ptr(),
                open_mode,
                PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_BUF,
                PIPE_BUF,
                0,
                &sa,
            );
            LocalFree(psd as _);
            if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                bail!(
                    "CreateNamedPipeW failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            NamedPipeServer::from_raw_handle(handle as _)
                .context("NamedPipeServer::from_raw_handle failed")
        }
    }

    /// Normalize a configured path/name into a `\\.\pipe\<name>` pipe name so the
    /// same `--socket` flag works on Windows.
    pub fn pipe_name(path: &std::path::Path) -> String {
        let s = path.to_string_lossy().to_string();
        if s.starts_with(r"\\.\pipe\") || s.starts_with(r"\\?\pipe\") {
            s
        } else {
            let base = path.file_name().and_then(|f| f.to_str()).unwrap_or("guard");
            format!(r"\\.\pipe\{}", base)
        }
    }

    /// SID string of the daemon's own process token. Used to grant the daemon
    /// full control of the pipe DACL so it can create additional instances.
    pub(crate) unsafe fn process_user_sid() -> Result<String> {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            bail!(
                "OpenProcessToken failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let result = sid_string_from_token(token);
        CloseHandle(token);
        result
    }

    /// Resolve the SID string of the connected pipe client by briefly
    /// impersonating it and reading the impersonation token's user.
    pub fn client_sid(server: &NamedPipeServer) -> Result<String> {
        let pipe = server.as_raw_handle() as HANDLE;
        unsafe {
            if ImpersonateNamedPipeClient(pipe) == 0 {
                bail!(
                    "ImpersonateNamedPipeClient failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            let outcome = sid_from_current_thread();
            // Always drop impersonation. A failed revert would leave this pooled
            // tokio worker thread impersonating the lower-privilege client for
            // subsequent tasks (policy eval, credential reads), so a failure here
            // is unrecoverable for the process: abort rather than risk running
            // privileged work under the client's token.
            if RevertToSelf() == 0 {
                tracing::error!(
                    "RevertToSelf failed after named-pipe impersonation ({}); aborting",
                    std::io::Error::last_os_error()
                );
                std::process::abort();
            }
            outcome
        }
    }

    unsafe fn sid_from_current_thread() -> Result<String> {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) == 0 {
            bail!(
                "OpenThreadToken failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let result = sid_string_from_token(token);
        CloseHandle(token);
        result
    }

    unsafe fn sid_string_from_token(token: HANDLE) -> Result<String> {
        let mut len: u32 = 0;
        // First call sizes the buffer (it is expected to "fail" with the length).
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
        if len == 0 {
            bail!("GetTokenInformation returned a zero length");
        }
        let mut buf = vec![0u8; len as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            len,
            &mut len,
        ) == 0
        {
            bail!(
                "GetTokenInformation failed: {}",
                std::io::Error::last_os_error()
            );
        }
        // buf is a Vec<u8> (alignment 1); forming a &TOKEN_USER to it would be UB
        // because TOKEN_USER's embedded PSID forces 8-byte alignment. Read the SID
        // pointer out with an unaligned read instead of taking a reference.
        let sid = core::ptr::read_unaligned(core::ptr::addr_of!(
            (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid
        ));
        let mut wide: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut wide) == 0 {
            bail!(
                "ConvertSidToStringSidW failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let s = widestring_to_string(wide);
        LocalFree(wide as _);
        Ok(s)
    }

    pub(crate) unsafe fn widestring_to_string(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}

#[cfg(unix)]
async fn handle_client_unix(stream: UnixStream, config: &ServerConfig) -> Result<()> {
    let uid = stream
        .peer_cred()
        .context("failed to read peer credentials")?
        .uid();
    tracing::info!("handle_client_unix: peer uid = {}", uid);

    if let Err(e) = config.validate_uid(uid) {
        tracing::warn!("uid {} rejected: {}", uid, e);
        return Err(e);
    }

    serve_connection(stream, CallerIdentity::Unix { uid }, config).await
}

#[cfg(windows)]
async fn handle_client_pipe(stream: NamedPipeServer, config: &ServerConfig) -> Result<()> {
    let caller = match winplat::client_sid(&stream) {
        Ok(sid) => {
            tracing::info!("named pipe client sid = {}", sid);
            CallerIdentity::Windows { sid }
        }
        Err(e) => {
            // Fail closed: a local pipe peer whose SID we cannot resolve is not
            // trustworthy for per-identity state (secret namespaces, pending-op
            // caps). Drop the connection rather than admit a shared synthetic
            // identity that multiple degraded callers would collapse onto.
            tracing::warn!(
                "could not resolve pipe client SID ({}); rejecting connection",
                e
            );
            return Err(e);
        }
    };
    serve_connection(stream, caller, config).await
}

/// Drive the request/response protocol for one connected client, independent of
/// the underlying transport (UNIX socket or Windows named pipe).
async fn serve_connection<S>(stream: S, caller: CallerIdentity, config: &ServerConfig) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    tracing::info!("serve_connection: waiting for request...");
    while let Ok(Some(line)) = lines.next_line().await {
        if line.len() > MAX_REQUEST_BYTES {
            tracing::warn!("request too large ({} bytes), dropping", line.len());
            continue;
        }
        tracing::debug!("serve_connection: received request (raw)");
        let incoming: IncomingMessage = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = ExecuteResponse {
                    allowed: false,
                    reason: format!("invalid request: {}", e),
                    exit_code: None,
                    stdout: None,
                    stderr: None,
                    status: None,
                    handle: None,
                    coverage: None,
                    verb_matches: Vec::new(),
                    verb_guidance: None,
                };
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
        };

        let request = match incoming {
            IncomingMessage::Admin { admin, .. } => {
                let resp = handle_admin_request(config, &caller, *admin).await;
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
            IncomingMessage::Execute(req) => *req,
        };

        if let Err(_e) = config.validate_token(request.auth_token.as_deref()) {
            config.log_audit_policy(
                &caller,
                request.session_token.as_deref(),
                &request.binary,
                &request.args,
                false,
                "invalid auth token",
            );
            let resp = ExecuteResponse {
                allowed: false,
                reason: "invalid auth token".to_string(),
                exit_code: None,
                stdout: None,
                stderr: None,
                status: None,
                handle: None,
                coverage: None,
                verb_matches: Vec::new(),
                verb_guidance: None,
            };
            writer
                .write_all(serde_json::to_string(&resp)?.as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
            continue;
        }

        let result = if request.stream {
            execute_command_streaming(request.clone(), config, &caller, &mut writer).await
        } else {
            execute_command(request.clone(), config, &caller).await
        };
        emit_exec_audit_events(
            config,
            &caller,
            request.session_token.as_deref(),
            &request.binary,
            &request.args,
            &result,
        );

        let resp = result.into_response();
        if request.stream {
            write_stream_message(
                &mut writer,
                &ExecuteStreamMessage::Result { response: resp },
            )
            .await?;
        } else {
            writer
                .write_all(serde_json::to_string(&resp)?.as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
        }
    }

    Ok(())
}

/// Emit POLICY and (optionally) EXEC_FAILED audit events for a single
/// request, mirroring what the execute handlers emit inline. Test-only:
/// the audit-format tests assert on both events through one entry point.
#[cfg(test)]
pub(super) fn emit_audit_events(
    config: &ServerConfig,
    caller: &CallerIdentity,
    binary: &str,
    args: &[String],
    result: &ExecuteResult,
) {
    // Always emit the policy decision — this is the event historical
    // grep patterns (`[AUDIT] ALLOWED` / `[AUDIT] DENIED`) key on.
    config.log_audit_policy(
        caller,
        None,
        binary,
        args,
        result.policy_allowed(),
        result.policy_reason(),
    );

    // If the policy allowed but exec failed, emit a second event so the
    // audit stream can distinguish "LLM denied" from "LLM approved but
    // exec failed". Ignored by legacy grep patterns.
    if let ExecOutcome::Failed { reason, .. } = &result.exec {
        config.log_audit_exec_failed(caller, None, binary, args, reason);
    }
}

fn emit_exec_audit_events(
    config: &ServerConfig,
    caller: &CallerIdentity,
    session_token: Option<&str>,
    binary: &str,
    args: &[String],
    result: &ExecuteResult,
) {
    if let ExecOutcome::Failed { reason, .. } = &result.exec {
        config.log_audit_exec_failed(caller, session_token, binary, args, reason);
    }
}

async fn session_maintenance(config: ServerConfig) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(
        SESSION_MAINTENANCE_INTERVAL_SECS,
    ));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // `interval` ticks immediately. Consume that tick because opening the store
    // already performs the startup prune.
    tick.tick().await;
    loop {
        tick.tick().await;
        if let Err(error) = session_maintenance_once(&config).await {
            tracing::warn!("session state maintenance failed: {}", error);
        }
    }
}

pub(super) fn claim_session_maintenance(config: &ServerConfig) -> bool {
    config
        .session_maintenance_started
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .is_ok()
}

pub(super) async fn session_maintenance_once(config: &ServerConfig) -> Result<bool> {
    let Some(store) = &config.session_store else {
        return Ok(false);
    };
    let snapshot = {
        let mut sessions = config.sessions.write().await;
        if !sessions.purge_expired() {
            return Ok(false);
        }
        sessions.clone()
    };
    store.persist_registry(&snapshot).await?;
    if store.compact_if_needed().await? {
        tracing::info!("compacted session state database");
    }
    Ok(true)
}

async fn handle_client_tcp(stream: tokio::net::TcpStream, config: &ServerConfig) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        if line.len() > MAX_REQUEST_BYTES {
            tracing::warn!("request too large ({} bytes), dropping", line.len());
            continue;
        }
        let incoming: IncomingMessage = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = ExecuteResponse {
                    allowed: false,
                    reason: format!("invalid request: {}", e),
                    exit_code: None,
                    stdout: None,
                    stderr: None,
                    status: None,
                    handle: None,
                    coverage: None,
                    verb_matches: Vec::new(),
                    verb_guidance: None,
                };
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
        };

        let request = match incoming {
            IncomingMessage::Admin { admin, admin_token } => {
                let caller = if matches!(admin.as_ref(), AdminRequest::Ping) {
                    CallerIdentity::Tcp {
                        token: "<tcp>".to_string(),
                    }
                } else if let Err(e) = config.validate_admin_token(admin_token.as_deref()) {
                    let resp = AdminResponse::Error {
                        message: format!("admin RPC refused: {}", e),
                    };
                    writer
                        .write_all(serde_json::to_string(&resp)?.as_bytes())
                        .await?;
                    writer.write_all(b"\n").await?;
                    continue;
                } else {
                    CallerIdentity::TcpAdmin {
                        token: admin_token.unwrap_or_else(|| "<missing>".to_string()),
                    }
                };
                let resp = handle_admin_request(config, &caller, *admin).await;
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
            IncomingMessage::Execute(req) => *req,
        };

        if let Err(_e) = config.validate_token(request.auth_token.as_deref()) {
            let caller = CallerIdentity::Unknown;
            config.log_audit_policy(
                &caller,
                request.session_token.as_deref(),
                &request.binary,
                &request.args,
                false,
                "invalid auth token",
            );
            let resp = ExecuteResponse {
                allowed: false,
                reason: "invalid auth token".to_string(),
                exit_code: None,
                stdout: None,
                stderr: None,
                status: None,
                handle: None,
                coverage: None,
                verb_matches: Vec::new(),
                verb_guidance: None,
            };
            writer
                .write_all(serde_json::to_string(&resp)?.as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
            continue;
        }

        let caller = CallerIdentity::Tcp {
            token: request
                .auth_token
                .clone()
                .unwrap_or_else(|| "<none>".to_string()),
        };
        let result = if request.stream {
            execute_command_streaming(request.clone(), config, &caller, &mut writer).await
        } else {
            execute_command(request.clone(), config, &caller).await
        };
        emit_exec_audit_events(
            config,
            &caller,
            request.session_token.as_deref(),
            &request.binary,
            &request.args,
            &result,
        );

        let resp = result.into_response();
        if request.stream {
            write_stream_message(
                &mut writer,
                &ExecuteStreamMessage::Result { response: resp },
            )
            .await?;
        } else {
            writer
                .write_all(serde_json::to_string(&resp)?.as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
        }
    }

    Ok(())
}

pub(super) async fn write_stream_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &ExecuteStreamMessage,
) -> Result<()> {
    writer
        .write_all(serde_json::to_string(message)?.as_bytes())
        .await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

pub(super) async fn write_policy_decision<W: AsyncWrite + Unpin>(
    stream_output: bool,
    writer: &mut W,
    allowed: bool,
    reason: &str,
) -> Result<()> {
    if stream_output {
        write_stream_message(
            writer,
            &ExecuteStreamMessage::PolicyDecision {
                allowed,
                reason: reason.to_string(),
            },
        )
        .await?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod unix_listener_tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path).unwrap().mode() & 0o777
    }

    #[tokio::test]
    async fn unix_socket_defaults_to_owner_only() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("guard.sock");
        let listener = Server::prepare_unix_listener(&socket, None).await.unwrap();
        assert_eq!(mode(&socket), 0o600);
        drop(listener);
    }

    #[tokio::test]
    async fn unix_socket_becomes_group_accessible_only_after_chgrp() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("guard.sock");
        let gid = unsafe { libc::getegid() };
        let group = uzers::get_group_by_gid(gid).expect("effective group must resolve");
        let group = group.name().to_string_lossy();
        let listener = Server::prepare_unix_listener(&socket, Some(&group))
            .await
            .unwrap();
        let metadata = std::fs::symlink_metadata(&socket).unwrap();
        assert_eq!(metadata.gid(), gid);
        assert_eq!(metadata.mode() & 0o777, 0o660);
        drop(listener);
    }

    #[tokio::test]
    async fn failed_socket_group_change_never_opens_socket_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("guard.sock");
        let error = Server::prepare_unix_listener(
            &socket,
            Some("guard-group-that-must-not-exist-9fce06b7"),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("failed to change group"));
        assert_eq!(mode(&socket), 0o600);
    }
}
