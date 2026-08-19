use crate::grant_profile::SavedGrantCatalog;
use crate::secrets::SecretManager;
use crate::session::SessionRegistry;
use crate::session_store::SessionStore;
use crate::tool_config::ToolRegistry;
#[cfg(unix)]
use anyhow::bail;
use anyhow::{Context, Result};
use guard::audit::{AuditEvent, AuditKind};
use guard::evaluate::Evaluator;
use guard::gating::approval::{ApprovalRegistry, ApprovalStatus, WaiterLease};
use guard::gating::provisional::{Provisional, ProvisionalRegistry, ProvisionalStatus};
#[cfg(unix)]
use guard::gating::read_grant::{GrantReadRegistry, ReadGrantStatus};
use guard::gating::verb::VerbCatalog;
use guard::gating::GateMode;
use std::collections::HashSet;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
#[cfg(unix)]
use tokio::process::Command;
use tokio::sync::RwLock;

use super::admin::handle_admin_request_owned;
use super::execute::{execute_command, execute_command_streaming, record_live_session_interaction};
#[cfg(unix)]
use super::gate_runtime::revert_dir_is_owner_only;
use super::gate_runtime::{gating_sweeper, is_api_proxy_sentinel, now_unix, DaemonGateSink};
#[cfg(unix)]
use super::grants::{delete_read_grant_row, revoke_read_grant_acls};
use super::runtime::NotifyEvent;
use super::wire::{
    AdminRequest, AdminResponse, CallerIdentity, ExecOutcome, ExecuteRequest, ExecuteResponse,
    ExecuteResult, ExecuteStreamMessage, IncomingMessage, OwnedAdminResponse,
};
use super::{
    ServerConfig, ServerContext, ServerState, DEFAULT_CONFIRM_WITHIN_SECS, MAX_REQUEST_BYTES,
    SESSION_MAINTENANCE_INTERVAL_SECS,
};
use crate::session::{SessionDecisionSource, SessionExecStatus, SessionInteraction};

fn is_revert_body_name(name: &str) -> bool {
    let Some(handle) = name
        .strip_prefix("api-revert-")
        .and_then(|name| name.strip_suffix(".body"))
    else {
        return false;
    };
    handle.len() == 32
        && handle
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

/// Reconcile only transaction-owned revert bodies in the daemon-private
/// directory. Unrelated names are untouched; an ambiguous or unsafe owned name
/// fails startup instead of risking deletion of another file.
fn reconcile_revert_body_files(snapshot_dir: &Path, rows: &[Provisional]) -> Result<()> {
    if !snapshot_dir.try_exists()? {
        return Ok(());
    }
    if !super::secure_fs::private_path_is_safe(snapshot_dir, true) {
        anyhow::bail!("API-revert body directory is not daemon-only");
    }

    let mut referenced = HashSet::new();
    for row in rows {
        let Some(body_file) = row
            .api_revert
            .as_ref()
            .and_then(|revert| revert.body_file.as_ref())
        else {
            continue;
        };
        let expected = snapshot_dir.join(format!("api-revert-{}.body", row.handle));
        if body_file != &expected
            || !is_revert_body_name(&format!("api-revert-{}.body", row.handle))
        {
            anyhow::bail!("persisted API-revert body path is outside its owned namespace");
        }
        referenced.insert(expected);
    }

    #[cfg(unix)]
    let mut removed = false;
    for entry in std::fs::read_dir(snapshot_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !is_revert_body_name(&name) || referenced.contains(&entry.path()) {
            continue;
        }
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || !super::secure_fs::private_path_is_safe(&entry.path(), false)
        {
            anyhow::bail!("orphan API-revert body is not a daemon-only regular file");
        }
        std::fs::remove_file(entry.path())?;
        #[cfg(unix)]
        {
            removed = true;
        }
    }
    #[cfg(unix)]
    if removed {
        std::fs::File::open(snapshot_dir)?.sync_all()?;
    }
    Ok(())
}

#[derive(Clone)]
struct DaemonApiSessionSink {
    server: ServerContext,
}

impl DaemonApiSessionSink {
    fn context_from_registry(
        &self,
        registry: &SessionRegistry,
        token: &str,
    ) -> Option<guard::proxy::ApiSessionContext> {
        if registry
            .suspension_reason(token, &self.server.config.behavior_limits)
            .is_some()
            || matches!(
                registry.owner_for(token),
                Some(crate::session::SessionOwner::Unowned)
            )
            || registry.is_access_managed(token)
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
}

struct ReplyWaiterGuard(Option<WaiterLease>);

impl ReplyWaiterGuard {
    fn new(lease: Option<WaiterLease>) -> Self {
        Self(lease)
    }
}

impl Drop for ReplyWaiterGuard {
    fn drop(&mut self) {
        if let Some(mut lease) = self.0.take() {
            lease.release_once();
        }
    }
}

async fn write_admin_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    owned: OwnedAdminResponse,
    exact_secrets: &[String],
) -> Result<()> {
    let OwnedAdminResponse {
        response,
        waiter_lease,
    } = owned;
    let _reply_guard = ReplyWaiterGuard::new(waiter_lease);
    let mut response = serde_json::to_value(response)?;
    let exact_secrets = exact_secrets.iter().map(String::as_str).collect::<Vec<_>>();
    guard::redact::redact_json_exact_secrets(&mut response, &exact_secrets);
    let bytes = serde_json::to_vec(&response)?;
    writer.write_all(&bytes).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

async fn write_redacted_json_line<W: AsyncWrite + Unpin, T: serde::Serialize>(
    writer: &mut W,
    response: &T,
    exact_secrets: &[String],
) -> Result<()> {
    let mut value = serde_json::to_value(response)?;
    let exact_secrets = exact_secrets.iter().map(String::as_str).collect::<Vec<_>>();
    guard::redact::redact_json_exact_secrets(&mut value, &exact_secrets);
    writer.write_all(&serde_json::to_vec(&value)?).await?;
    writer.write_all(b"\n").await?;
    Ok(())
}

#[cfg(test)]
mod admin_response_lease_tests {
    use super::*;
    use guard::gating::approval::{Approval, ApprovalSnapshot};
    use guard::gating::Reversibility;
    use std::collections::BTreeMap;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    fn approval() -> Approval {
        Approval {
            handle: "lease-test".to_string(),
            snapshot: ApprovalSnapshot {
                binary: "true".to_string(),
                args: Vec::new(),
                cwd: None,
                env: BTreeMap::new(),
                secret_keys: BTreeMap::new(),
                session_fingerprint: None,
                session_revision: None,
                secret_entitlements: None,
                secret_file_keys: BTreeMap::new(),
                verb_name: None,
                verb_params: BTreeMap::new(),
                catalog_version: None,
                verb_digest: None,
                verb_composition_digest: None,
                exec_timeout_secs: None,
                access_verbs: Vec::new(),
                access_requests: Vec::new(),
                principal: None,
                secret_binding: None,
            },
            reason: "test".to_string(),
            risk: Some(8),
            reversibility: Some(Reversibility::Irreversible),
            decision_trace: None,
            created_unix: 1,
            ttl_secs: 3600,
            status: ApprovalStatus::Pending,
            decided_unix: None,
            decided_reason: None,
            result_exit: None,
            result_stdout: None,
            result_stderr: None,
            notes: Vec::new(),
        }
    }

    fn owned_response(registry: &mut ApprovalRegistry) -> OwnedAdminResponse {
        registry.enqueue(approval());
        let (_, lease) = registry
            .register_waiter("lease-test")
            .expect("waiter registered");
        OwnedAdminResponse {
            response: AdminResponse::Ok,
            waiter_lease: Some(lease),
        }
    }

    struct FailedWriter;

    impl AsyncWrite for FailedWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "connection closed",
            )))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct PendingWriter;

    impl AsyncWrite for PendingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn response_lease_spans_serialization_and_successful_flush() {
        let mut registry = ApprovalRegistry::new();
        let owned = owned_response(&mut registry);
        assert_eq!(registry.active_waiters("lease-test"), 1);
        let (mut writer, mut reader) = tokio::io::duplex(128);

        write_admin_response(&mut writer, owned, &[]).await.unwrap();
        assert_eq!(registry.active_waiters("lease-test"), 0);
        drop(writer);
        let mut frame = String::new();
        reader.read_to_string(&mut frame).await.unwrap();
        assert!(matches!(
            serde_json::from_str::<AdminResponse>(frame.trim()).unwrap(),
            AdminResponse::Ok
        ));
    }

    #[tokio::test]
    async fn rpc_projection_redacts_exact_literals_in_values_and_map_keys() {
        let value = ["r", "!"].concat();
        let mut output = Vec::new();
        write_admin_response(
            &mut output,
            OwnedAdminResponse {
                response: AdminResponse::Error {
                    message: format!("failure {value}"),
                },
                waiter_lease: None,
            },
            std::slice::from_ref(&value),
        )
        .await
        .unwrap();
        let mut keyed = Vec::new();
        write_redacted_json_line(
            &mut keyed,
            &serde_json::json!({ value.clone(): value.clone() }),
            std::slice::from_ref(&value),
        )
        .await
        .unwrap();
        assert!(!output
            .windows(value.len())
            .any(|bytes| bytes == value.as_bytes()));
        assert!(!keyed
            .windows(value.len())
            .any(|bytes| bytes == value.as_bytes()));
    }

    #[tokio::test]
    async fn response_lease_releases_on_write_failure() {
        let mut registry = ApprovalRegistry::new();
        let owned = owned_response(&mut registry);
        assert!(write_admin_response(&mut FailedWriter, owned, &[])
            .await
            .is_err());
        assert_eq!(registry.active_waiters("lease-test"), 0);
    }

    #[tokio::test]
    async fn response_lease_releases_when_write_is_cancelled() {
        let mut registry = ApprovalRegistry::new();
        let owned = owned_response(&mut registry);
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(10),
            write_admin_response(&mut PendingWriter, owned, &[]),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(registry.active_waiters("lease-test"), 0);
    }
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
        let registry = self.server.state.sessions.read().await;
        // The API proxy is a loopback TLS listener that carries a session bearer
        // but no kernel-authenticated local principal, so owner==caller cannot be
        // re-verified per request (see the security model's TCP/principal note);
        // ownership is bound at issuance, where `KubeconfigIssue` requires the
        // owning local peer. A session that predates principal binding has no
        // verifiable owner and is refused fail-closed here, matching the execute
        // path, so a legacy bearer cannot be replayed through the proxy.
        // Public access approvals authorize brokered command verbs. They never
        // mint a reusable API bearer, which would bypass per-request admission
        // and bounded-use accounting at the command spawn boundary.
        self.context_from_registry(&registry, token)
    }

    async fn authorize_forward(
        &self,
        token: &str,
        expected: &guard::proxy::ApiSessionContext,
        handoff: &mut dyn guard::proxy::ApiForwardHandoff,
    ) -> std::result::Result<(), String> {
        let registry = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.server.state.sessions.read(),
        )
        .await
        .map_err(|_| "timed out acquiring session authority coordination".to_string())?;
        if self.context_from_registry(&registry, token).as_ref() != Some(expected) {
            return Err("session expired, was revoked, or changed".to_string());
        }
        handoff.forward().await
    }

    async fn record(&self, token: &str, event: guard::proxy::ApiSessionEvent) {
        record_live_session_interaction(
            &self.server,
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
                decision_trace: Some(guard::gating::DecisionTrace::source("api_proxy")),
            },
        )
        .await;
    }
}

/// Validate the immutable authority that a persisted rollback depends on.
/// This checks identities and secret names only. Secret values never enter the
/// recovery reason, audit stream, or notification payload.
async fn provisional_recovery_error(server: &ServerContext, row: &Provisional) -> Option<String> {
    if row.status != ProvisionalStatus::Armed || !row.forward_done {
        return None;
    }
    if row.session_fingerprint.is_some() != row.session_revision.is_some() {
        return Some("persisted session identity is incomplete".to_string());
    }
    let secret_names = row
        .secret_keys
        .values()
        .chain(row.secret_file_keys.values())
        .collect::<std::collections::BTreeSet<_>>();
    if !secret_names.is_empty() {
        let Some(principal) = row.principal.as_ref() else {
            return Some("persisted secret references have no frozen principal".to_string());
        };
        if let Some(entitlements) = &row.secret_entitlements {
            if secret_names
                .iter()
                .any(|name| !entitlements.iter().any(|allowed| allowed == *name))
            {
                return Some(
                    "persisted secret references exceed frozen session entitlements".to_string(),
                );
            }
        }
        for name in secret_names {
            match server.state.secrets.get(principal, name).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return Some(format!(
                        "persisted rollback secret reference '{}' is unavailable",
                        name
                    ))
                }
                Err(_) => {
                    return Some(format!(
                        "persisted rollback secret reference '{}' could not be revalidated",
                        name
                    ))
                }
            }
        }
    }
    if let Some(api) = &row.api_revert {
        if !row
            .principal
            .as_ref()
            .is_some_and(|principal| server.config.daemon_principal.eq_ci(principal))
        {
            return Some(
                "persisted API rollback principal is not the daemon principal".to_string(),
            );
        }
        if api.endpoint.is_empty()
            || api.upstream_target.is_empty()
            || api.upstream_identity.is_empty()
        {
            return Some(
                "persisted API rollback lacks exact endpoint or credential identity".to_string(),
            );
        }
        let registry = server.state.protocol_registry.read().await;
        let Some(proxy) = registry.get(&api.endpoint) else {
            return Some(format!(
                "persisted API rollback endpoint '{}' is unavailable",
                api.endpoint
            ));
        };
        if !proxy.matches_upstream_identity(
            &api.protocol,
            &api.upstream_target,
            &api.upstream_identity,
        ) {
            return Some(format!(
                "persisted API rollback endpoint '{}' no longer has the frozen protocol, target, and credential identity",
                api.endpoint
            ));
        }
    } else if row.revert_binary.is_empty() {
        return Some("persisted command rollback has no revert binary".to_string());
    }
    None
}

#[cfg(test)]
mod api_session_event_tests {
    use super::*;
    use crate::secrets::{EnvBackend, SecretManager};
    use crate::session::SessionRegistry;
    use crate::tool_config::ToolRegistry;
    use guard::evaluate::{EvalConfig, Evaluator};
    use std::collections::BTreeMap;

    fn recovery_context() -> ServerContext {
        ServerContext {
            config: ServerConfig::default(),
            state: ServerState::new(
                Evaluator::new(EvalConfig::default().llm_enabled(false)).unwrap(),
                SecretManager::with_backend(EnvBackend::default()),
                ToolRegistry::isolated_for_tests(),
                SessionRegistry::new(),
                None,
            ),
        }
    }

    fn armed_command() -> Provisional {
        Provisional {
            handle: "recovery".to_string(),
            principal: Some(guard::principal::PrincipalKey::from_uid(1_001)),
            requester_principal: None,
            binary: "true".to_string(),
            args: Vec::new(),
            cwd: None,
            secret_keys: BTreeMap::new(),
            secret_file_keys: BTreeMap::new(),
            revert_binary: "true".to_string(),
            revert_args: Vec::new(),
            confirm_check_binary: None,
            confirm_check_args: Vec::new(),
            control_path: Some("local".to_string()),
            session_fingerprint: None,
            session_revision: None,
            secret_entitlements: None,
            api_revert: None,
            reason: "test".to_string(),
            decision_trace: None,
            created_unix: 1,
            deadline_unix: u64::MAX,
            window_secs: 0,
            auto_reverted_unix: None,
            forward_done: true,
            forward_exit: Some(0),
            forward_persistence_failed: false,
            status: ProvisionalStatus::Armed,
            revert_exit: None,
            revert_detail: None,
        }
    }

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

    #[tokio::test]
    async fn restart_authority_revalidation_rejects_missing_secret() {
        let server = recovery_context();
        let mut row = armed_command();
        row.secret_keys
            .insert("TOKEN".to_string(), "rollback/token".to_string());
        row.secret_entitlements = Some(vec!["rollback/token".to_string()]);
        let error = provisional_recovery_error(&server, &row)
            .await
            .expect("missing secret invalidates recovery authority");
        assert!(error.contains("unavailable"));

        server
            .state
            .secrets
            .set(
                row.principal.as_ref().unwrap(),
                "rollback/token",
                "test-only",
            )
            .await
            .unwrap();
        assert!(provisional_recovery_error(&server, &row).await.is_none());
    }

    #[tokio::test]
    async fn restart_authority_revalidation_rejects_api_identity_change() {
        let server = recovery_context();
        let proxy = Arc::new(guard::proxy::ApiProxy::new(
            "127.0.0.1:18443".parse().unwrap(),
            guard::proxy::ProxyTls::generate().unwrap(),
            guard::proxy::Upstream::from_base_url(
                "https://127.0.0.1:16443",
                guard::proxy::UpstreamAuth::Bearer("upstream-test-only".to_string()),
            )
            .unwrap(),
            guard::proxy::ApiPolicy::deny_all(),
            None,
        ));
        server
            .state
            .protocol_registry
            .write()
            .await
            .insert("cluster-a".to_string(), proxy.clone());
        let mut row = armed_command();
        row.principal = Some(server.config.daemon_principal.clone());
        row.api_revert = Some(guard::gating::provisional::ApiRevertPlan {
            endpoint: "cluster-a".to_string(),
            protocol: "kubernetes".to_string(),
            upstream_target: proxy.upstream().base().to_string(),
            upstream_identity: "changed-credential-identity".to_string(),
            method: "DELETE".to_string(),
            path: "/api/v1/namespaces/dev/configmaps/test".to_string(),
            requires_uid_precondition: false,
            resource_uid: None,
            create_provenance: None,
            body_file: None,
        });
        let error = provisional_recovery_error(&server, &row)
            .await
            .expect("changed endpoint identity invalidates recovery authority");
        assert!(error.contains("frozen protocol, target, and credential identity"));

        row.api_revert.as_mut().unwrap().upstream_identity = proxy.upstream_identity_fingerprint();
        assert!(provisional_recovery_error(&server, &row).await.is_none());
    }
}

#[derive(Clone)]
pub struct Server {
    context: ServerContext,
}

impl Server {
    pub fn new(
        config: ServerConfig,
        evaluator: Evaluator,
        secrets: SecretManager,
        tool_registry: ToolRegistry,
        sessions: SessionRegistry,
        session_store: Option<SessionStore>,
    ) -> Result<Self> {
        let trusted_exact_secret_scope =
            guard::redact::register_trusted_exact_secrets(&config.redact_secrets)
                .context("register daemon exact-redaction literals")?;
        let mut state =
            ServerState::new(evaluator, secrets, tool_registry, sessions, session_store);
        state._trusted_exact_secret_scope = trusted_exact_secret_scope;
        // Count every audited event at the single audit emission choke point by
        // installing this daemon's metrics as the process-global observer, so
        // the read-only metrics surface and the audit log share one source of
        // truth. First install wins, matching the audit sink.
        guard::audit::install_event_observer(state.metrics.clone());
        // Open the durable audit sink before serving anything: a daemon that
        // cannot record audit events refuses to start (fail closed).
        if let Some(path) = &config.audit_log_path {
            let log = guard::audit::AuditLog::open(path)
                .with_context(|| format!("open audit log {}", path.display()))?;
            #[cfg(windows)]
            if !super::secure_fs::harden_existing_private_path(path, false) {
                anyhow::bail!(
                    "audit log {} could not be restricted to the daemon principal",
                    path.display()
                );
            }
            let log = Arc::new(log);
            // The same chain also backs context-free emitters (the API proxy,
            // admission/spend telemetry) via the process-global sink.
            guard::audit::install_global_sink(log.clone());
            state.audit = Some(log);
        }
        let mut server = Self {
            context: ServerContext { config, state },
        };
        let root = server
            .context
            .config
            .state_db_path
            .as_ref()
            .and_then(|path| path.parent())
            .map(|path| path.join("secret-files"))
            .unwrap_or_else(|| std::env::temp_dir().join("guard-secret-files"));
        super::secure_fs::prepare_private_root(&root)
            .with_context(|| format!("prepare secret-file root {}", root.display()))?;
        server.context.config.secret_file_root = Some(root);
        Ok(server)
    }

    /// Enable consequence gating. Must be called before `run`.
    pub fn set_gate(&mut self, gate: GateMode) {
        self.context.config.gate = gate;
    }

    pub fn set_approval_ttl(&mut self, ttl_secs: u64) {
        self.context.config.approval_ttl_secs = ttl_secs;
    }

    /// Configure the optional operator notification command.
    pub fn set_notify_hook(&mut self, command: Vec<String>, timeout_secs: u64) {
        self.context.state.notify_hook = super::runtime::NotifyHook::new(command, timeout_secs);
    }

    pub fn set_behavior_limits(&mut self, limits: crate::session::SessionBehaviorLimits) {
        self.context.config.behavior_limits = limits;
    }

    pub fn set_command_admission(&mut self, admission: super::runtime::CommandAdmissionConfig) {
        self.context.state.command_admission = super::runtime::CommandAdmission::new(admission);
    }

    /// Enable the optional read-only metrics/health listener. `None` (the
    /// default) runs no listener. Must be called before `run`.
    pub fn set_metrics_addr(&mut self, addr: Option<std::net::SocketAddr>) {
        self.context.config.metrics_addr = addr;
    }

    /// Install the operator-defined verb catalog. Must be called before `run`.
    pub fn set_verbs(&mut self, catalog: VerbCatalog) {
        self.context.state.verbs = Arc::new(RwLock::new(catalog));
    }

    /// Install reusable grants. Must be called before `run`.
    pub fn set_saved_grants(&mut self, catalog: SavedGrantCatalog) {
        self.context.state.saved_grants = Arc::new(RwLock::new(catalog));
    }

    /// Restrict which binaries may execute. `None` imposes no restriction (the
    /// default); an empty list denies everything. Must be called before `run`.
    pub fn set_allowed_binaries(&mut self, allowed: Option<Vec<String>>) {
        self.context.config.allowed_binaries = allowed;
    }

    /// Set the operator-declared extra child-env passthrough list (see
    /// [`ServerConfig::extra_child_env`]). Must be called before `run`.
    pub fn set_extra_child_env(&mut self, vars: Vec<String>) {
        self.context.config.extra_child_env = vars;
    }

    pub fn set_api_coverage(
        &mut self,
        store: Option<Arc<RwLock<guard::gating::api_promotion::ApiPromotionStore>>>,
    ) {
        self.context.state.api_coverage = store;
    }

    /// Attach an API proxy to run alongside the gate socket. Must be
    /// called before `run`.
    pub async fn register_api_proxy(
        &mut self,
        name: impl Into<String>,
        proxy: Arc<guard::proxy::ApiProxy>,
    ) {
        proxy.attach_session_sink(Arc::new(DaemonApiSessionSink {
            server: self.context.clone(),
        }));
        self.context
            .state
            .protocol_registry
            .write()
            .await
            .insert(name.into(), proxy);
    }

    /// Load persisted provisional/approval state and apply startup recovery:
    /// no revert ever runs unattended at boot. Past-deadline or interrupted
    /// provisionals become `needs_operator_decision`; interrupted approvals
    /// become `exec_failed`. Both are surfaced via a high-severity audit line.
    async fn startup_gating(&self) -> Result<()> {
        let Some(store) = &self.context.state.session_store else {
            self.install_saved_grant_verbs().await;
            tracing::info!(
                "No state database configured: saved grants, grant requests, sessions, and gate state are process-local"
            );
            return Ok(());
        };

        match (
            store.load_saved_grants().await,
            store.load_saved_grant_tombstones().await,
        ) {
            (Ok(rows), Ok(tombstones)) => {
                let mut grants = self.context.state.saved_grants.write().await;
                if let Err(error) = grants.overlay_rows(rows) {
                    return Err(anyhow::anyhow!("failed to validate saved grants: {error}"));
                } else {
                    grants.apply_tombstones(&tombstones);
                }
            }
            (rows, tombstones) => {
                return Err(anyhow::anyhow!(
                    "failed to load complete durable saved-grant state: rows={}, tombstones={}",
                    rows.err()
                        .map(|error| error.to_string())
                        .unwrap_or_else(|| "ok".to_string()),
                    tombstones
                        .err()
                        .map(|error| error.to_string())
                        .unwrap_or_else(|| "ok".to_string())
                ));
            }
        }
        self.install_saved_grant_verbs().await;
        match store.load_grant_requests().await {
            Ok(rows) => {
                *self.context.state.grant_requests.write().await = rows
                    .into_iter()
                    .map(|request| (request.handle.clone(), request))
                    .collect();
                super::admin::validate_durable_access_provenance(&self.context)
                    .await
                    .map_err(anyhow::Error::msg)
                    .context("validate durable access provenance")?;
                if let Err(error) = super::admin::install_approved_access_verbs(&self.context).await
                {
                    return Err(anyhow::anyhow!(
                        "failed to restore approved access coverage: {error}"
                    ));
                }
                super::admin::prune_grant_requests(&self.context).await;
            }
            Err(error) => return Err(error).context("load durable grant requests"),
        }

        match store.load_provisionals().await {
            Ok(rows) => {
                let mut rows = rows;
                if let Some(snapshot_dir) = self
                    .context
                    .config
                    .state_db_path
                    .as_ref()
                    .and_then(|path| path.parent())
                    .map(|parent| parent.join("api-proxy-reverts"))
                {
                    reconcile_revert_body_files(&snapshot_dir, &rows)
                        .context("reconcile durable API-revert bodies")?;
                }
                #[cfg(windows)]
                if let Some(state_parent) = self
                    .context
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
                            self.context.emit_audit_ungated(
                                AuditEvent::new(AuditKind::ApiRevertFileUnsafe)
                                    .handle(&row.handle)
                                    .field("path", body_file.display()),
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
                let mut invalid = Vec::new();
                for row in &mut rows {
                    if let Some(reason) = provisional_recovery_error(&self.context, row).await {
                        row.status = ProvisionalStatus::NeedsOperatorDecision;
                        row.revert_detail = Some(reason.clone());
                        invalid.push((row.handle.clone(), reason));
                    }
                }
                let durable_rows = rows.clone();
                let (mut reg, moved, retired) = ProvisionalRegistry::recover_rows(rows);
                for handle in retired {
                    if let Some(row) = durable_rows.iter().find(|row| row.handle == handle) {
                        super::gate_runtime::remove_revert_body(row).with_context(|| {
                            format!("remove inert pre-handoff revert body for {handle}")
                        })?;
                    }
                    store
                        .delete_provisional(handle.clone())
                        .await
                        .with_context(|| {
                            format!("retire inert pre-handoff provisional {handle}")
                        })?;
                }
                let mut escalated = invalid;
                for handle in moved {
                    let reason = "daemon stopped before the forward outcome or rollback completion was unambiguous"
                        .to_string();
                    reg.set_needs_operator_decision(&handle, reason.clone());
                    escalated.push((handle, reason));
                }
                escalated.sort_by(|left, right| left.0.cmp(&right.0));
                if !escalated.is_empty() {
                    self.context.emit_audit_ungated(
                        AuditEvent::new(AuditKind::StartupRecovery)
                            .field("provisionals_needing_decision", escalated.len())
                            .field(
                                "handles",
                                format!(
                                    "{:?}",
                                    escalated
                                        .iter()
                                        .map(|(handle, _)| handle)
                                        .collect::<Vec<_>>()
                                ),
                            ),
                    );
                    for (handle, reason) in &escalated {
                        if let Some(p) = reg.get(handle) {
                            if let Err(e) = store.save_provisional(p.clone()).await {
                                tracing::warn!(
                                    "failed to persist recovered provisional {}: {}",
                                    handle,
                                    e
                                );
                            }
                            self.context.emit_event(NotifyEvent {
                                event: "startup_recovery_escalated",
                                at_unix: now_unix(),
                                handle: Some(handle.clone()),
                                session_fingerprint: p.session_fingerprint.clone(),
                                requester_principal: None,
                                reason: Some(reason.clone()),
                                status: Some("needs_operator_decision".to_string()),
                                behavior: None,
                            });
                        }
                    }
                }
                *self.context.state.provisional.write().await = reg;
            }
            Err(e) => return Err(e).context("load durable provisional state"),
        }
        match store.load_approvals().await {
            Ok(rows) => {
                let now = now_unix();
                let (mut reg, recovered) = ApprovalRegistry::from_rows(rows, now);
                let expired = reg.expire_due(now);
                for handle in &expired {
                    if let Some(approval) = reg.get(handle) {
                        if let Err(error) = store.save_approval(approval.clone()).await {
                            tracing::warn!(
                                "failed to persist expired approval {}: {}",
                                handle,
                                error
                            );
                        }
                    }
                }
                if !expired.is_empty() {
                    self.context.emit_audit_ungated(
                        AuditEvent::new(AuditKind::StartupRecovery)
                            .reason("pending approvals expired while daemon was stopped")
                            .field("approvals_expired", expired.len())
                            .field("handles", format!("{expired:?}")),
                    );
                }
                if !recovered.is_empty() {
                    self.context.emit_audit_ungated(
                        AuditEvent::new(AuditKind::StartupRecovery)
                            .reason("exec interrupted by restart")
                            .field("approvals_exec_failed", recovered.len())
                            .field("handles", format!("{recovered:?}")),
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
                            && matches!(&a.snapshot.principal, Some(p) if self.context.config.daemon_principal.eq_ci(p))
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
                    self.context.emit_audit_ungated(
                        AuditEvent::new(AuditKind::StartupRecovery)
                            .field("api_proxy_holds_retired", orphaned.len())
                            .field("handles", format!("{orphaned:?}")),
                    );
                }
                let pending = reg
                    .list()
                    .into_iter()
                    .filter(|approval| approval.status == ApprovalStatus::Pending)
                    .map(|approval| approval.handle)
                    .collect::<std::collections::BTreeSet<_>>();
                let baseline_sessions = self.context.state.sessions.read().await.clone();
                let mut reconciled = baseline_sessions.clone();
                let removed = reconciled.retain_pending_access_grants(&pending);
                if removed > 0 {
                    match super::execute::persist_session_snapshot(
                        self.context.state.session_store.clone(),
                        reconciled.clone(),
                    )
                    .await
                    {
                        Ok(()) => {
                            let mut sessions = self.context.state.sessions.write().await;
                            if sessions.revision() != baseline_sessions.revision() {
                                return Err(anyhow::anyhow!(
                                    "session authority changed during startup approval reconciliation"
                                ));
                            }
                            *sessions = reconciled;
                            self.context.emit_audit_ungated(
                                AuditEvent::new(AuditKind::StartupRecovery)
                                    .field("staged_access_grants_removed", removed),
                            );
                        }
                        Err(error) => tracing::error!(
                            "failed to persist staged access-grant recovery: {}",
                            error
                        ),
                    }
                }
                *self.context.state.approvals.write().await = reg;
            }
            Err(e) => return Err(e).context("load durable approval state"),
        }
        Ok(())
    }

    async fn install_saved_grant_verbs(&self) {
        let generated = self
            .context
            .state
            .saved_grants
            .read()
            .await
            .list()
            .into_iter()
            .flat_map(|grant| grant.generated_verbs)
            .collect::<Vec<_>>();
        let mut verbs = self.context.state.verbs.write().await;
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
    async fn startup_read_grants(&self) -> Result<()> {
        let Some(store) = &self.context.state.session_store else {
            return Ok(());
        };
        let rows = store
            .load_read_grants()
            .await
            .context("load complete durable read-grant state")?;
        let reg = GrantReadRegistry::from_rows(rows);
        let now = now_unix();
        let mut surviving = GrantReadRegistry::new();
        for grant in reg.list() {
            if grant.status == ReadGrantStatus::Active && now >= grant.expires_unix {
                match revoke_read_grant_acls(&grant).await {
                    Ok(()) => {
                        self.context.emit_audit_ungated(
                            AuditEvent::new(AuditKind::ReadGrantRevoked)
                                .handle(&grant.handle)
                                .field("path", &grant.target_path)
                                .field("source", "startup-expired"),
                        );
                        delete_read_grant_row(&self.context, &grant.target_path).await;
                    }
                    Err(e) => {
                        self.context.emit_audit_ungated(
                            AuditEvent::new(AuditKind::ReadGrantRevokeFailed)
                                .handle(&grant.handle)
                                .field("path", &grant.target_path)
                                .field("source", "startup-expired")
                                .field("detail", e),
                        );
                        surviving.insert(grant);
                    }
                }
            } else {
                surviving.insert(grant);
            }
        }
        *self.context.state.read_grants.write().await = surviving;
        Ok(())
    }

    pub async fn run(&self) -> Result<()> {
        tracing::info!("Server::run() called");
        let _process_shutdown = self.context.state.process_tracker.shutdown_guard();

        // A state database belongs to exactly one running daemon. The CLI
        // acquires the crash-safe path lease before opening SQLite, so startup
        // migration and recovery cannot touch another daemon's live database.
        if let Some(store) = &self.context.state.session_store {
            if !store.has_daemon_lease() {
                anyhow::bail!("daemon state database was opened without an exclusive lease");
            }
            let registry = store
                .load_registry()
                .await
                .context("reload leased session registry before startup recovery")?;
            *self.context.state.sessions.write().await = registry;
        }

        // Load durable authorization state. Consequence rows also receive
        // boot-safe recovery when gating is enabled.
        if self.context.config.gate.is_on() {
            tracing::info!("Consequence gating: {}", self.context.config.gate);
        }
        self.startup_gating().await?;
        // Reconcile persisted read grants (revoke expired, re-arm live).
        #[cfg(unix)]
        self.startup_read_grants().await?;

        // The single sweeper drives both consequence-gate reverts (gate-on only)
        // and read-grant expiries (Unix, gate-independent), so it runs whenever
        // either is live. Without this a read grant could outlive its TTL simply
        // because the daemon runs without consequence gating.
        if self.context.config.gate.is_on() || cfg!(unix) {
            let server = self.context.clone();
            tokio::spawn(async move { gating_sweeper(server).await });
        }
        if self.context.state.session_store.is_some() && claim_session_maintenance(&self.context) {
            let server = self.context.clone();
            tokio::spawn(async move { session_maintenance(server).await });
        }

        let mut futures = Vec::new();

        if let Some(ref socket_path) = self.context.config.socket_path {
            tracing::info!("Starting local listener on {}", socket_path.display());
            let path = socket_path.clone();
            let server = self.context.clone();
            futures.push(tokio::spawn(async move {
                Self::run_local_static(&path, &server).await
            }));
        }

        if let Some(port) = self.context.config.tcp_port {
            tracing::info!("Starting TCP listener on port {}", port);
            let server = self.context.clone();
            futures.push(tokio::spawn(async move {
                Self::run_tcp_static(port, &server).await
            }));
        }

        let proxies: Vec<_> = self
            .context
            .state
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
            if self.context.config.gate.is_on() {
                // With a state DB the revert dir lives beside it (systemd
                // StateDirectory, 0700). Without one, provisionals are
                // process-local and not recovered across restart, so a fresh
                // private directory (unpredictable name, created owner-only) is
                // both sufficient and immune to a pre-created fixed-name dir a
                // local attacker could own.
                let snapshot_dir = match self
                    .context
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
                    self.context.emit_audit_ungated(
                        AuditEvent::new(AuditKind::ApiRevertDirUnsafe)
                            .reason("not owner-only; body-bearing auto-reverts are disabled")
                            .field("path", snapshot_dir.display()),
                    );
                }
                proxy.attach_gate(Arc::new(DaemonGateSink {
                    server: self.context.clone(),
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

        // Optional read-only metrics/health listener. Bind synchronously so an
        // explicitly requested listener that cannot bind fails startup loudly,
        // before the daemon reports itself up. The metrics path never gates or
        // slows a request: counters are lock-free atomics and gauges are read
        // only here, at scrape time.
        if let Some(addr) = self.context.config.metrics_addr {
            let listener = super::metrics::bind(addr).await?;
            let state = self.context.state.clone();
            futures.push(tokio::spawn(async move {
                super::metrics::serve(listener, state).await
            }));
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
                self.context.state.process_tracker.terminate_all();
                return Ok(());
            }
        };

        // A listener loop only returns on a fatal error. Wait for the first one,
        // abort the other infinite loops, and return the failure immediately so
        // one bad named endpoint cannot hide behind healthy listeners forever.
        for task in remaining {
            task.abort();
        }
        self.context.state.process_tracker.terminate_all();
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
    async fn run_local_static(socket_path: &Path, server: &ServerContext) -> Result<()> {
        #[cfg(unix)]
        {
            Self::run_unix_static(socket_path, server).await
        }
        #[cfg(windows)]
        {
            Self::run_pipe_static(socket_path, server).await
        }
    }

    #[cfg(windows)]
    async fn run_pipe_static(socket_path: &Path, context: &ServerContext) -> Result<()> {
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

            let context = context.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_client_pipe(connected, &context).await {
                    tracing::error!("client handler error: {}", e);
                }
            });
        }
    }

    #[cfg(unix)]
    async fn run_unix_static(socket_path: &Path, server: &ServerContext) -> Result<()> {
        let listener =
            Self::prepare_unix_listener(socket_path, server.config.socket_group.as_deref()).await?;

        tracing::info!("guard server listening on {}", socket_path.display());

        loop {
            match listener.accept().await {
                Ok((stream, _peer_addr)) => {
                    let server = server.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_client_unix(stream, &server).await {
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
            // Keep the path unreachable to other principals across the
            // bind-to-chmod interval. Group traversal is published only after
            // the socket group and mode are both installed below.
            Self::chmod_path(parent, 0o700)
                .await
                .context("failed to restrict socket directory before binding")?;
        }

        if socket_path.exists() {
            tokio::fs::remove_file(socket_path).await?;
        }

        let listener = UnixListener::bind(socket_path).context("failed to bind UNIX socket")?;
        if let Err(error) = Self::chmod_path(socket_path, 0o600).await {
            return Err(Self::fail_closed_socket(socket_path, error).await);
        }

        if let Some(group) = socket_group {
            if let Err(error) = Self::chown_to_group(socket_path, group).await {
                return Err(Self::fail_closed_socket(socket_path, error).await);
            }
            if let Err(error) = Self::chmod_path(socket_path, 0o660).await {
                return Err(Self::fail_closed_socket(socket_path, error).await);
            }
            if let Some(parent) = socket_path.parent() {
                Self::chmod_path(parent, 0o755).await?;
            }
        }
        Ok(listener)
    }

    #[cfg(unix)]
    async fn fail_closed_socket(socket_path: &Path, setup_error: anyhow::Error) -> anyhow::Error {
        let permission_error = Self::chmod_path(socket_path, 0o600).await.err();
        let removal_error = tokio::fs::remove_file(socket_path).await.err();

        match (permission_error, removal_error) {
            (None, None) => setup_error,
            (Some(permission_error), None) => setup_error.context(format!(
                "failed to restore owner-only socket permissions before removing the socket: {permission_error}"
            )),
            (None, Some(removal_error)) => setup_error.context(format!(
                "restored owner-only socket permissions but failed to remove the socket: {removal_error}"
            )),
            (Some(permission_error), Some(removal_error)) => setup_error.context(format!(
                "failed to restore owner-only socket permissions ({permission_error}) and failed to remove the socket ({removal_error})"
            )),
        }
    }

    async fn run_tcp_static(port: u16, server: &ServerContext) -> Result<()> {
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr)
            .await
            .context("failed to bind TCP socket")?;

        tracing::info!("guard server listening on tcp://{}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let server = server.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_client_tcp(stream, &server).await {
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
/// The SID is the Windows analog of a Unix peer UID - the kernel-verified
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
async fn handle_client_unix(stream: UnixStream, server: &ServerContext) -> Result<()> {
    let uid = stream
        .peer_cred()
        .context("failed to read peer credentials")?
        .uid();
    tracing::info!("handle_client_unix: peer uid = {}", uid);

    if let Err(e) = server.validate_uid(uid) {
        tracing::warn!("uid {} rejected: {}", uid, e);
        return Err(e);
    }

    serve_connection(stream, CallerIdentity::Unix { uid }, server).await
}

#[cfg(windows)]
async fn handle_client_pipe(stream: NamedPipeServer, server: &ServerContext) -> Result<()> {
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
    serve_connection(stream, caller, server).await
}

/// One request line read under the transport size cap.
enum BoundedLine {
    /// A complete line within the cap (also the final unterminated line at EOF).
    Line(String),
    /// Clean end of stream.
    Eof,
    /// The peer sent more than `MAX_REQUEST_BYTES` before a newline arrived.
    /// The remainder of the oversized line is still in flight, so the caller
    /// must close the connection rather than keep reading.
    TooLong,
}

/// Read one newline-delimited request without ever buffering more than
/// `MAX_REQUEST_BYTES + 1` bytes. `Lines::next_line` grows its buffer until it
/// sees `\n`, so a peer that never sends one could exhaust memory before any
/// size check runs; this enforces the cap while the line is still streaming
/// in. Matches `next_line` semantics for in-cap input: strips `\n`/`\r\n`,
/// yields a final unterminated line at EOF, and errors on invalid UTF-8.
async fn read_bounded_line<R>(reader: &mut R) -> std::io::Result<BoundedLine>
where
    R: AsyncBufRead + Unpin,
{
    let mut buf = Vec::new();
    let read = (&mut *reader)
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_until(b'\n', &mut buf)
        .await?;
    if read == 0 {
        return Ok(BoundedLine::Eof);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    } else if buf.len() > MAX_REQUEST_BYTES {
        return Ok(BoundedLine::TooLong);
    }
    String::from_utf8(buf)
        .map(BoundedLine::Line)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Denial response for a request rejected before policy evaluation.
fn validation_error_response(reason: String) -> ExecuteResponse {
    ExecuteResponse {
        allowed: false,
        reason,
        exit_code: None,
        stdout: None,
        stderr: None,
        status: None,
        handle: None,
        approval_options: Vec::new(),
        access_requests: Vec::new(),
        coverage: None,
        verb_matches: Vec::new(),
        verb_guidance: None,
        confirm_deadline_unix: None,
        confirm_window_secs: None,
        auto_revert_durable: None,
        containment_failure: None,
        decision_source: "validation".to_string(),
        decision_trace: Some(guard::gating::DecisionTrace::source("validation")),
    }
}

fn caller_with_valid_admin_bearer(
    caller: &CallerIdentity,
    admin_token: Option<&str>,
) -> CallerIdentity {
    match caller {
        CallerIdentity::Unix { uid } => CallerIdentity::UnixAdmin { uid: *uid },
        _ => CallerIdentity::TcpAdmin {
            token: admin_token.unwrap_or("<missing>").to_string(),
        },
    }
}

/// Drive the request/response protocol for one connected client, independent of
/// the underlying transport (UNIX socket or Windows named pipe).
async fn serve_connection<S>(
    stream: S,
    caller: CallerIdentity,
    server: &ServerContext,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    tracing::info!("serve_connection: waiting for request...");
    loop {
        let line = match read_bounded_line(&mut reader).await {
            Ok(BoundedLine::Line(line)) => line,
            Ok(BoundedLine::Eof) | Err(_) => break,
            Ok(BoundedLine::TooLong) => {
                tracing::warn!(
                    "request exceeds {} bytes, closing connection",
                    MAX_REQUEST_BYTES
                );
                let resp = validation_error_response(format!(
                    "request exceeds {} bytes",
                    MAX_REQUEST_BYTES
                ));
                write_redacted_json_line(&mut writer, &resp, &server.config.redact_secrets).await?;
                break;
            }
        };
        tracing::debug!("serve_connection: received request (raw)");
        let incoming: IncomingMessage = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let reason = classify_execute_protocol_parse_error(&line)
                    .unwrap_or_else(|| format!("invalid request: {e}"));
                let resp = validation_error_response(reason);
                write_redacted_json_line(&mut writer, &resp, &server.config.redact_secrets).await?;
                continue;
            }
        };

        let request = match incoming {
            IncomingMessage::Admin { admin, admin_token } => {
                // Admin authority is the admin bearer token, never the Unix
                // peer uid or Windows service SID: brokered children inherit
                // the daemon identity and must not inherit its operator
                // surface. Kernel-authenticated Windows SYSTEM is the one
                // local exception used by the packaged operator task. Ping
                // stays open for health probes, matching the TCP listener.
                let caller = if matches!(admin.as_ref(), AdminRequest::Ping) {
                    caller.clone()
                } else {
                    let token_result = server.validate_admin_token(admin_token.as_deref());
                    if admin.requires_admin_token() {
                        // Operator-only operations require the bearer except
                        // for a tokenless, kernel-authenticated Windows SYSTEM
                        // named-pipe caller. Supplying an invalid bearer still
                        // fails closed, including for SYSTEM.
                        if server.config.allow_windows_system_operator
                            && caller.is_windows_system_operator()
                            && admin_token.is_none()
                        {
                            caller.clone()
                        } else if let Err(e) = token_result {
                            let resp = AdminResponse::Error {
                                message: format!("admin RPC refused: {}", e),
                            };
                            write_redacted_json_line(
                                &mut writer,
                                &resp,
                                &server.config.redact_secrets,
                            )
                            .await?;
                            continue;
                        } else {
                            caller_with_valid_admin_bearer(&caller, admin_token.as_deref())
                        }
                    } else if admin_token.is_some() {
                        // Self-scoped operations accept an optional bearer: a
                        // valid token elevates the caller to the operator view,
                        // an invalid one is refused outright, and its absence
                        // leaves the operation self-scoped.
                        if let Err(e) = token_result {
                            let resp = AdminResponse::Error {
                                message: format!("admin RPC refused: {}", e),
                            };
                            write_redacted_json_line(
                                &mut writer,
                                &resp,
                                &server.config.redact_secrets,
                            )
                            .await?;
                            continue;
                        }
                        caller_with_valid_admin_bearer(&caller, admin_token.as_deref())
                    } else {
                        caller.clone()
                    }
                };
                let trusted = server
                    .config
                    .redact_secrets
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                if serde_json::to_value(admin.as_ref())
                    .ok()
                    .is_some_and(|value| {
                        guard::redact::json_contains_exact_secrets(&value, &trusted)
                    })
                {
                    let response = AdminResponse::Error {
                        message: "admin request contains a daemon-managed credential literal"
                            .to_string(),
                    };
                    write_admin_response(
                        &mut writer,
                        OwnedAdminResponse {
                            response,
                            waiter_lease: None,
                        },
                        &server.config.redact_secrets,
                    )
                    .await?;
                    continue;
                }
                let owned = handle_admin_request_owned(server, &caller, *admin).await;
                write_admin_response(&mut writer, owned, &server.config.redact_secrets).await?;
                continue;
            }
            IncomingMessage::Execute {
                protocol_version,
                features,
                execute,
            } => {
                if let Err(reason) =
                    validate_execute_protocol(protocol_version, &features, &execute, &caller)
                {
                    let resp = validation_error_response(reason);
                    write_redacted_json_line(&mut writer, &resp, &server.config.redact_secrets)
                        .await?;
                    continue;
                }
                *execute
            }
        };

        if let Err(_e) = server.validate_token(request.auth_token.as_deref()) {
            server.audit_deny(
                &caller,
                request.session_token.as_deref(),
                &request.binary,
                &request.args,
                "invalid auth token",
            );
            let resp = validation_error_response("invalid auth token".to_string());
            write_redacted_json_line(&mut writer, &resp, &server.config.redact_secrets).await?;
            continue;
        }

        let result = if request.stream {
            execute_command_streaming(request.clone(), server, &caller, &mut writer).await
        } else {
            execute_command(request.clone(), server, &caller).await
        };
        emit_exec_audit_events(
            server,
            &caller,
            request.session_token.as_deref(),
            &request.binary,
            &request.args,
            &result,
        );

        let resp = result.into_response();
        if request.stream {
            write_redacted_json_line(
                &mut writer,
                &ExecuteStreamMessage::Result { response: resp },
                &server.config.redact_secrets,
            )
            .await?;
        } else {
            write_redacted_json_line(&mut writer, &resp, &server.config.redact_secrets).await?;
        }
    }

    Ok(())
}

fn classify_execute_protocol_parse_error(line: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let object = value.as_object()?;
    if object.contains_key("binary") && !object.contains_key("execute") {
        return Some(format!(
            "unsupported legacy execute protocol; upgrade the Guard client to protocol version {}",
            super::wire::EXECUTE_PROTOCOL_VERSION
        ));
    }
    if object.contains_key("execute") {
        if !object.contains_key("protocol_version") {
            return Some(format!(
                "execute protocol version is required; upgrade the Guard client to protocol version {}",
                super::wire::EXECUTE_PROTOCOL_VERSION
            ));
        }
        if !object.contains_key("features") {
            return Some(
                "execute protocol features are required; upgrade the Guard client".to_string(),
            );
        }
    }
    None
}

fn validate_execute_protocol(
    protocol_version: u16,
    features: &[String],
    request: &ExecuteRequest,
    caller: &CallerIdentity,
) -> Result<(), String> {
    if protocol_version != super::wire::EXECUTE_PROTOCOL_VERSION {
        return Err(format!(
            "unsupported execute protocol version {protocol_version}; upgrade the Guard client to protocol version {}",
            super::wire::EXECUTE_PROTOCOL_VERSION
        ));
    }
    let tcp = matches!(
        caller,
        CallerIdentity::Tcp { .. } | CallerIdentity::TcpAdmin { .. }
    );
    let required_feature = if tcp {
        super::wire::EXECUTE_FEATURE_TCP_NO_CWD
    } else {
        super::wire::EXECUTE_FEATURE_LOCAL_CWD
    };
    if !features.iter().any(|feature| feature == required_feature) {
        return Err(format!(
            "execute protocol feature '{required_feature}' is required; upgrade the Guard client"
        ));
    }
    if tcp {
        if request.cwd.is_some() {
            return Err("TCP execute protocol must declare tcp-no-cwd-v1 and omit cwd".to_string());
        }
    } else if request.cwd.is_none() {
        return Err("local execute protocol requires cwd; upgrade the Guard client".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod execute_protocol_tests {
    use super::*;

    fn request(cwd: Option<&str>) -> ExecuteRequest {
        ExecuteRequest {
            binary: "id".to_string(),
            args: Vec::new(),
            auth_token: None,
            env: Default::default(),
            secrets: Default::default(),
            secret_files: Default::default(),
            stream: false,
            session_token: None,
            revert: None,
            confirm_within_secs: None,
            require_approval: None,
            wait_approval_secs: None,
            verb: None,
            reevaluate: false,
            ssh_hostkey: None,
            cwd: cwd.map(std::path::PathBuf::from),
        }
    }

    #[test]
    fn legacy_and_incomplete_envelopes_get_direct_upgrade_errors() {
        let legacy = r#"{"binary":"id","args":[]}"#;
        assert!(classify_execute_protocol_parse_error(legacy)
            .unwrap()
            .contains("unsupported legacy execute protocol"));
        let no_version = r#"{"features":["local-cwd-v1"],"execute":{"binary":"id","args":[]}}"#;
        assert!(classify_execute_protocol_parse_error(no_version)
            .unwrap()
            .contains("protocol version is required"));
        let no_features = r#"{"protocol_version":1,"execute":{"binary":"id","args":[]}}"#;
        assert!(classify_execute_protocol_parse_error(no_features)
            .unwrap()
            .contains("features are required"));
    }

    #[test]
    fn local_contract_requires_supported_version_feature_and_cwd() {
        let caller = CallerIdentity::Unix { uid: 1001 };
        let feature = vec![super::super::wire::EXECUTE_FEATURE_LOCAL_CWD.to_string()];
        assert!(validate_execute_protocol(
            super::super::wire::EXECUTE_PROTOCOL_VERSION,
            &feature,
            &request(Some("/work")),
            &caller,
        )
        .is_ok());
        assert!(
            validate_execute_protocol(0, &feature, &request(Some("/work")), &caller)
                .unwrap_err()
                .contains("unsupported execute protocol version")
        );
        assert!(validate_execute_protocol(
            super::super::wire::EXECUTE_PROTOCOL_VERSION,
            &[],
            &request(Some("/work")),
            &caller,
        )
        .unwrap_err()
        .contains("feature 'local-cwd-v1' is required"));
        assert!(validate_execute_protocol(
            super::super::wire::EXECUTE_PROTOCOL_VERSION,
            &feature,
            &request(None),
            &caller,
        )
        .unwrap_err()
        .contains("requires cwd"));
    }
}

/// Emit POLICY and (optionally) EXEC_FAILED audit events for a single
/// request, mirroring what the execute handlers emit inline. Test-only:
/// the audit-format tests assert on both events through one entry point.
#[cfg(test)]
pub(super) fn emit_audit_events(
    server: &ServerContext,
    caller: &CallerIdentity,
    binary: &str,
    args: &[String],
    result: &ExecuteResult,
) {
    // Always emit the policy decision - this is the event historical
    // grep patterns (`[AUDIT] ALLOWED` / `[AUDIT] DENIED`) key on.
    let _ = server.log_audit_policy(
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
        server.log_audit_exec_failed(caller, None, binary, args, reason);
    }
}

fn emit_exec_audit_events(
    server: &ServerContext,
    caller: &CallerIdentity,
    session_token: Option<&str>,
    binary: &str,
    args: &[String],
    result: &ExecuteResult,
) {
    if let ExecOutcome::Failed { reason, .. } = &result.exec {
        server.log_audit_exec_failed(caller, session_token, binary, args, reason);
    }
}

async fn session_maintenance(server: ServerContext) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(
        SESSION_MAINTENANCE_INTERVAL_SECS,
    ));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // `interval` ticks immediately. Consume that tick because opening the store
    // already performs the startup prune.
    tick.tick().await;
    loop {
        tick.tick().await;
        if let Err(error) = session_maintenance_once(&server).await {
            tracing::warn!("session state maintenance failed: {}", error);
        }
    }
}

pub(super) fn claim_session_maintenance(server: &ServerContext) -> bool {
    server
        .state
        .session_maintenance_started
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .is_ok()
}

pub(super) async fn session_maintenance_once(server: &ServerContext) -> Result<bool> {
    let Some(store) = &server.state.session_store else {
        return Ok(false);
    };
    let snapshot = {
        let mut sessions = server.state.sessions.write().await;
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

async fn handle_client_tcp(stream: tokio::net::TcpStream, server: &ServerContext) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    loop {
        let line = match read_bounded_line(&mut reader).await {
            Ok(BoundedLine::Line(line)) => line,
            Ok(BoundedLine::Eof) | Err(_) => break,
            Ok(BoundedLine::TooLong) => {
                tracing::warn!(
                    "request exceeds {} bytes, closing connection",
                    MAX_REQUEST_BYTES
                );
                let resp = validation_error_response(format!(
                    "request exceeds {} bytes",
                    MAX_REQUEST_BYTES
                ));
                write_redacted_json_line(&mut writer, &resp, &server.config.redact_secrets).await?;
                break;
            }
        };
        let incoming: IncomingMessage = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let reason = classify_execute_protocol_parse_error(&line)
                    .unwrap_or_else(|| format!("invalid request: {e}"));
                let resp = validation_error_response(reason);
                write_redacted_json_line(&mut writer, &resp, &server.config.redact_secrets).await?;
                continue;
            }
        };

        let request = match incoming {
            IncomingMessage::Admin { admin, admin_token } => {
                let caller = if matches!(admin.as_ref(), AdminRequest::Ping) {
                    CallerIdentity::Tcp {
                        token: "<tcp>".to_string(),
                    }
                } else if let Err(e) = server.validate_admin_token(admin_token.as_deref()) {
                    let resp = AdminResponse::Error {
                        message: format!("admin RPC refused: {}", e),
                    };
                    write_redacted_json_line(&mut writer, &resp, &server.config.redact_secrets)
                        .await?;
                    continue;
                } else {
                    CallerIdentity::TcpAdmin {
                        token: admin_token.unwrap_or_else(|| "<missing>".to_string()),
                    }
                };
                let trusted = server
                    .config
                    .redact_secrets
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                if serde_json::to_value(admin.as_ref())
                    .ok()
                    .is_some_and(|value| {
                        guard::redact::json_contains_exact_secrets(&value, &trusted)
                    })
                {
                    let response = AdminResponse::Error {
                        message: "admin request contains a daemon-managed credential literal"
                            .to_string(),
                    };
                    write_admin_response(
                        &mut writer,
                        OwnedAdminResponse {
                            response,
                            waiter_lease: None,
                        },
                        &server.config.redact_secrets,
                    )
                    .await?;
                    continue;
                }
                let owned = handle_admin_request_owned(server, &caller, *admin).await;
                write_admin_response(&mut writer, owned, &server.config.redact_secrets).await?;
                continue;
            }
            IncomingMessage::Execute {
                protocol_version,
                features,
                execute,
            } => {
                let tcp_caller = CallerIdentity::Tcp {
                    token: "<tcp>".to_string(),
                };
                if let Err(reason) =
                    validate_execute_protocol(protocol_version, &features, &execute, &tcp_caller)
                {
                    let resp = validation_error_response(reason);
                    write_redacted_json_line(&mut writer, &resp, &server.config.redact_secrets)
                        .await?;
                    continue;
                }
                *execute
            }
        };

        if let Err(_e) = server.validate_token(request.auth_token.as_deref()) {
            let caller = CallerIdentity::Unknown;
            server.audit_deny(
                &caller,
                request.session_token.as_deref(),
                &request.binary,
                &request.args,
                "invalid auth token",
            );
            let resp = validation_error_response("invalid auth token".to_string());
            write_redacted_json_line(&mut writer, &resp, &server.config.redact_secrets).await?;
            continue;
        }

        let caller = CallerIdentity::Tcp {
            token: request
                .auth_token
                .clone()
                .unwrap_or_else(|| "<none>".to_string()),
        };
        let result = if request.stream {
            execute_command_streaming(request.clone(), server, &caller, &mut writer).await
        } else {
            execute_command(request.clone(), server, &caller).await
        };
        emit_exec_audit_events(
            server,
            &caller,
            request.session_token.as_deref(),
            &request.binary,
            &request.args,
            &result,
        );

        let resp = result.into_response();
        if request.stream {
            write_redacted_json_line(
                &mut writer,
                &ExecuteStreamMessage::Result { response: resp },
                &server.config.redact_secrets,
            )
            .await?;
        } else {
            write_redacted_json_line(&mut writer, &resp, &server.config.redact_secrets).await?;
        }
    }

    Ok(())
}

pub(super) async fn write_stream_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &ExecuteStreamMessage,
) -> Result<()> {
    let mut message = serde_json::to_value(message)?;
    guard::redact::redact_json_exact_secrets(&mut message, &[]);
    writer.write_all(&serde_json::to_vec(&message)?).await?;
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
        let reason = guard::gating::sanitize_gate_text(reason);
        write_stream_message(
            writer,
            &ExecuteStreamMessage::PolicyDecision { allowed, reason },
        )
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod line_limit_tests {
    use super::*;
    use std::time::Duration;

    const TEST_TIMEOUT: Duration = Duration::from_secs(30);

    #[test]
    fn startup_reconciles_only_owned_orphan_revert_bodies() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("api-proxy-reverts");
        super::super::secure_fs::create_private_dir(&directory).unwrap();
        let orphan = directory.join(format!("api-revert-{}.body", "a".repeat(32)));
        super::super::secure_fs::write_new_private(&orphan, b"fixture").unwrap();
        let unrelated = directory.join("operator-note");
        super::super::secure_fs::write_new_private(&unrelated, b"fixture").unwrap();

        reconcile_revert_body_files(&directory, &[]).unwrap();

        assert!(!orphan.exists());
        assert!(unrelated.exists());
        reconcile_revert_body_files(&directory, &[]).unwrap();
    }

    #[tokio::test]
    async fn policy_stream_sanitizes_reason_before_serialization() {
        let value = ["sk-", &"Ab1".repeat(8)].concat();
        let mut output = Vec::new();
        write_policy_decision(true, &mut output, false, &format!("rationale {value}"))
            .await
            .unwrap();
        assert!(!output
            .windows(value.len())
            .any(|part| part == value.as_bytes()));
        assert!(String::from_utf8(output).unwrap().contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn malformed_durable_provisional_prevents_listener_startup() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("state.db");
        let socket = temp.path().join("guard.sock");
        let seed = SessionStore::open(database.clone(), 3600).await.unwrap();
        drop(seed);
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection
            .execute(
                "INSERT INTO gating_provisional (handle, json, status, created_unix)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params!["malformed-armed", "{", "armed", 1],
            )
            .unwrap();
        drop(connection);

        let error = SessionStore::open_for_daemon(database, 3600)
            .await
            .expect_err("malformed durable state must prevent daemon startup");
        assert!(
            format!("{error:#}").contains("malformed-armed"),
            "{error:#}"
        );
        assert!(
            !socket.exists(),
            "startup bound a listener from partial state"
        );
    }

    fn durable_fixture_grant(access_managed: bool) -> crate::session::SessionGrant {
        crate::session::SessionGrant {
            allow: Vec::new(),
            deny: Vec::new(),
            allow_exact: Vec::new(),
            deny_exact: Vec::new(),
            activated_verbs: vec!["fixture-inspect".to_string()],
            override_markers: Vec::new(),
            scope: crate::session::IssuedGrantScope {
                access_managed,
                ..crate::session::IssuedGrantScope::default()
            },
            expires_at: None,
            prompt_append: None,
            generated_notes: Vec::new(),
            static_only: true,
            auto_amend: false,
            granted_at: 1,
            owner: crate::session::SessionOwner::Principal(
                guard::principal::PrincipalKey::from_uid(1001),
            ),
        }
    }

    async fn server_for_durable_fixture(
        database: std::path::PathBuf,
        socket: std::path::PathBuf,
    ) -> Server {
        let store = SessionStore::open_for_daemon(database.clone(), 3600)
            .await
            .unwrap();
        let mut context = crate::server::tests::config_for_proposal_test();
        context.config.socket_path = Some(socket);
        context.config.state_db_path = Some(database);
        context.state.session_store = Some(store);
        Server { context }
    }

    async fn valid_durable_access_fixture(
        seed: &SessionStore,
    ) -> (crate::session::SessionRegistry, String) {
        let token = "access-fixture-token".to_string();
        let mut registry = crate::session::SessionRegistry::new();
        assert!(registry.grant(token.clone(), durable_fixture_grant(true)));
        let mut request = crate::grant_profile::GrantRequest::new_access_with_uses(
            guard::principal::PrincipalKey::from_uid(1001),
            Some(token.clone()),
            "agent:1001".to_string(),
            crate::grant_profile::GrantRequestDelta {
                activated_verbs: vec!["fixture-inspect".to_string()],
                ..Default::default()
            },
            "inspect the fixture".to_string(),
            Some(1),
        )
        .unwrap();
        request.authority_verbs = vec!["fixture-inspect".to_string()];
        request.request_key = request.canonical_access_key().unwrap();
        request.target = Some(crate::session::session_reference(&token));
        request.status = crate::grant_profile::GrantRequestStatus::Approved;
        request.decided_unix = Some(guard::env::now_unix());
        assert_eq!(
            registry.install_access_grant(
                &token,
                Some(1),
                request.handle.clone(),
                request.authority_verbs.clone(),
            ),
            Some(true)
        );
        seed.save_grant_request(request.clone()).await.unwrap();
        (registry, request.handle)
    }

    #[tokio::test]
    async fn active_legacy_bearer_session_prevents_listener_startup() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("state.db");
        let socket = temp.path().join("guard.sock");
        let seed = SessionStore::open(database.clone(), 3600).await.unwrap();
        let mut registry = crate::session::SessionRegistry::new();
        assert!(registry.grant(
            "legacy-fixture-token".to_string(),
            durable_fixture_grant(false)
        ));
        seed.persist_registry(&registry).await.unwrap();
        drop(seed);

        let error = server_for_durable_fixture(database, socket.clone())
            .await
            .run()
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("legacy bearer session"));
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn orphaned_access_grant_prevents_listener_startup() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("state.db");
        let socket = temp.path().join("guard.sock");
        let seed = SessionStore::open(database.clone(), 3600).await.unwrap();
        let mut registry = crate::session::SessionRegistry::new();
        assert!(registry.grant(
            "access-fixture-token".to_string(),
            durable_fixture_grant(true)
        ));
        assert_eq!(
            registry.install_access_grant(
                "access-fixture-token",
                Some(1),
                "gr-missing".to_string(),
                vec!["fixture-inspect".to_string()],
            ),
            Some(true)
        );
        seed.persist_registry(&registry).await.unwrap();
        drop(seed);

        let error = server_for_durable_fixture(database, socket.clone())
            .await
            .run()
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("references missing request gr-missing"));
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn bounded_access_without_remaining_counter_prevents_listener_startup() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("state.db");
        let socket = temp.path().join("guard.sock");
        let seed = SessionStore::open(database.clone(), 3600).await.unwrap();
        let (registry, request) = valid_durable_access_fixture(&seed).await;
        let mut grants = registry.grants_snapshot();
        grants
            .get_mut("access-fixture-token")
            .unwrap()
            .scope
            .access_grants[0]
            .remaining_uses = None;
        let malformed = crate::session::SessionRegistry::from_parts(
            grants,
            registry.history_snapshot(),
            registry.interactions_snapshot(),
            3600,
        );
        seed.persist_registry(&malformed).await.unwrap();
        drop(seed);

        let error = server_for_durable_fixture(database, socket.clone())
            .await
            .run()
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("use policy disagrees"),
            "request={request} error={error:#}"
        );
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn duplicate_access_request_provenance_prevents_listener_startup() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("state.db");
        let socket = temp.path().join("guard.sock");
        let seed = SessionStore::open(database.clone(), 3600).await.unwrap();
        let (registry, request) = valid_durable_access_fixture(&seed).await;
        let mut grants = registry.grants_snapshot();
        let grant = grants.get_mut("access-fixture-token").unwrap();
        grant
            .scope
            .access_grants
            .push(grant.scope.access_grants[0].clone());
        let malformed = crate::session::SessionRegistry::from_parts(
            grants,
            registry.history_snapshot(),
            registry.interactions_snapshot(),
            3600,
        );
        seed.persist_registry(&malformed).await.unwrap();
        drop(seed);

        let error = server_for_durable_fixture(database, socket.clone())
            .await
            .run()
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("duplicate request provenance"),
            "request={request} error={error:#}"
        );
        assert!(!socket.exists());
    }

    async fn next_bounded(reader: &mut (impl AsyncBufRead + Unpin)) -> BoundedLine {
        read_bounded_line(reader).await.expect("read line")
    }

    #[tokio::test]
    async fn bounded_reader_matches_next_line_semantics() {
        let mut reader = &b"hello\r\nworld\npartial"[..];
        assert!(matches!(
            next_bounded(&mut reader).await,
            BoundedLine::Line(line) if line == "hello"
        ));
        assert!(matches!(
            next_bounded(&mut reader).await,
            BoundedLine::Line(line) if line == "world"
        ));
        assert!(matches!(
            next_bounded(&mut reader).await,
            BoundedLine::Line(line) if line == "partial"
        ));
        assert!(matches!(next_bounded(&mut reader).await, BoundedLine::Eof));
    }

    #[tokio::test]
    async fn bounded_reader_accepts_line_at_exact_cap() {
        let mut data = vec![b'a'; MAX_REQUEST_BYTES];
        data.push(b'\n');
        data.extend_from_slice(b"next\n");
        let mut reader = &data[..];
        assert!(matches!(
            next_bounded(&mut reader).await,
            BoundedLine::Line(line) if line.len() == MAX_REQUEST_BYTES
        ));
        assert!(matches!(
            next_bounded(&mut reader).await,
            BoundedLine::Line(line) if line == "next"
        ));
    }

    #[tokio::test]
    async fn bounded_reader_rejects_line_over_cap() {
        let data = vec![b'a'; MAX_REQUEST_BYTES + 1];
        let mut reader = &data[..];
        assert!(matches!(
            next_bounded(&mut reader).await,
            BoundedLine::TooLong
        ));
    }

    /// Regression: the daemon's own uid must NOT grant operator authority.
    /// Admin-gated operations require the admin bearer token at the unix
    /// transport, so a brokered child running as the daemon uid cannot
    /// approve or inspect operator state.
    async fn one_admin_roundtrip(
        caller: CallerIdentity,
        admin_token_config: Option<&str>,
        allow_windows_system_operator: bool,
        line: &str,
    ) -> String {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let mut cfg = crate::server::tests::config_for_proposal_test();
        if let Some(token) = admin_token_config {
            cfg.config.admin_token = Some(token.to_string());
        }
        cfg.config.allow_windows_system_operator = allow_windows_system_operator;
        let task = tokio::spawn(async move { serve_connection(server, caller, &cfg).await });
        let (read_half, mut write_half) = tokio::io::split(client);
        write_half
            .write_all(line.as_bytes())
            .await
            .expect("write admin request");
        write_half.write_all(b"\n").await.expect("write newline");
        let mut lines = BufReader::new(read_half).lines();
        let response = tokio::time::timeout(TEST_TIMEOUT, lines.next_line())
            .await
            .expect("admin response timed out")
            .expect("read admin response")
            .expect("admin response line");
        drop(lines);
        drop(write_half);
        let _ = task.await;
        response
    }

    #[tokio::test]
    async fn unix_admin_gated_op_refused_without_token_even_as_daemon_uid() {
        let response = one_admin_roundtrip(
            CallerIdentity::Unix { uid: 1000 },
            Some("operator-token"),
            false,
            r#"{"admin":{"op":"audit_verify"}}"#,
        )
        .await;
        assert!(
            response.contains("admin RPC refused"),
            "gated op must be refused without the token: {response}"
        );
    }

    #[tokio::test]
    async fn unix_admin_gated_op_refused_with_wrong_token() {
        let response = one_admin_roundtrip(
            CallerIdentity::Unix { uid: 1000 },
            Some("operator-token"),
            false,
            r#"{"admin":{"op":"audit_verify"},"admin_token":"wrong"}"#,
        )
        .await;
        assert!(
            response.contains("admin RPC refused"),
            "gated op must be refused with a wrong token: {response}"
        );
    }

    #[tokio::test]
    async fn unix_admin_gated_op_refused_when_token_unconfigured() {
        let response = one_admin_roundtrip(
            CallerIdentity::Unix { uid: 1000 },
            None,
            false,
            r#"{"admin":{"op":"audit_verify"},"admin_token":"anything"}"#,
        )
        .await;
        assert!(
            response.contains("admin RPC refused"),
            "gated op must be refused when no admin token is configured: {response}"
        );
    }

    #[tokio::test]
    async fn unix_admin_self_scoped_ops_do_not_require_token() {
        let response = one_admin_roundtrip(
            CallerIdentity::Unix { uid: 4242 },
            None,
            false,
            r#"{"admin":{"op":"access_list"}}"#,
        )
        .await;
        assert!(
            !response.contains("admin RPC refused"),
            "self-scoped op must not require the token: {response}"
        );
    }

    #[tokio::test]
    async fn unix_admin_exempt_op_with_valid_token_gets_operator_identity() {
        // An exempt op with a valid bearer must not be refused; without it,
        // the operator's see-all view is silently lost.
        let response = one_admin_roundtrip(
            CallerIdentity::Unix { uid: 1000 },
            Some("operator-token"),
            false,
            r#"{"admin":{"op":"access_list"},"admin_token":"operator-token"}"#,
        )
        .await;
        assert!(
            !response.contains("admin RPC refused"),
            "exempt op with a valid token must be served: {response}"
        );
    }

    #[tokio::test]
    async fn unix_admin_exempt_op_with_wrong_token_is_refused() {
        let response = one_admin_roundtrip(
            CallerIdentity::Unix { uid: 1000 },
            Some("operator-token"),
            false,
            r#"{"admin":{"op":"access_list"},"admin_token":"wrong"}"#,
        )
        .await;
        assert!(
            response.contains("admin RPC refused"),
            "an invalid bearer must be refused even on exempt ops: {response}"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_system_operator_does_not_require_an_admin_bearer() {
        let response = one_admin_roundtrip(
            CallerIdentity::Windows {
                sid: "S-1-5-18".to_string(),
            },
            None,
            true,
            r#"{"admin":{"op":"status"}}"#,
        )
        .await;
        let parsed: AdminResponse = serde_json::from_str(&response).expect("admin response");
        assert!(matches!(parsed, AdminResponse::Status { .. }), "{parsed:?}");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_service_sid_does_not_inherit_operator_authority() {
        let response = one_admin_roundtrip(
            CallerIdentity::Windows {
                sid: "S-1-5-80-12345".to_string(),
            },
            None,
            true,
            r#"{"admin":{"op":"status"}}"#,
        )
        .await;
        let parsed: AdminResponse = serde_json::from_str(&response).expect("admin response");
        assert!(
            matches!(parsed, AdminResponse::Error { ref message } if message == "admin RPC refused: admin token is not configured"),
            "{parsed:?}"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_ordinary_user_sid_does_not_inherit_operator_authority() {
        let response = one_admin_roundtrip(
            CallerIdentity::Windows {
                sid: "S-1-5-21-1000-1000-1000-1001".to_string(),
            },
            None,
            true,
            r#"{"admin":{"op":"status"}}"#,
        )
        .await;
        let parsed: AdminResponse = serde_json::from_str(&response).expect("admin response");
        assert!(
            matches!(parsed, AdminResponse::Error { ref message } if message == "admin RPC refused: admin token is not configured"),
            "{parsed:?}"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn foreground_windows_system_does_not_inherit_packaged_operator_authority() {
        let response = one_admin_roundtrip(
            CallerIdentity::Windows {
                sid: "S-1-5-18".to_string(),
            },
            None,
            false,
            r#"{"admin":{"op":"status"}}"#,
        )
        .await;
        let parsed: AdminResponse = serde_json::from_str(&response).expect("admin response");
        assert!(
            matches!(parsed, AdminResponse::Error { ref message } if message == "admin RPC refused: admin token is not configured"),
            "{parsed:?}"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_system_operator_with_an_invalid_bearer_is_refused() {
        let response = one_admin_roundtrip(
            CallerIdentity::Windows {
                sid: "S-1-5-18".to_string(),
            },
            Some("operator-token"),
            true,
            r#"{"admin":{"op":"status"},"admin_token":"wrong"}"#,
        )
        .await;
        let parsed: AdminResponse = serde_json::from_str(&response).expect("admin response");
        assert!(
            matches!(parsed, AdminResponse::Error { ref message } if message == "admin RPC refused: invalid admin token"),
            "{parsed:?}"
        );
    }

    /// A peer that streams more than the cap without a newline gets a denial
    /// response and a closed connection instead of an unbounded server buffer.
    #[tokio::test]
    async fn serve_connection_closes_on_oversized_request() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let config = crate::server::tests::config_for_proposal_test();
        let task = tokio::spawn(async move {
            serve_connection(server, CallerIdentity::Unknown, &config).await
        });

        let (read_half, mut write_half) = tokio::io::split(client);
        tokio::time::timeout(TEST_TIMEOUT, async {
            write_half
                .write_all(&vec![b'x'; MAX_REQUEST_BYTES + 1])
                .await
                .expect("stream oversized request");
            let mut lines = BufReader::new(read_half).lines();
            let response = lines
                .next_line()
                .await
                .expect("read denial")
                .expect("denial line before close");
            let response: ExecuteResponse =
                serde_json::from_str(&response).expect("parse denial response");
            assert!(!response.allowed);
            assert!(response.reason.contains("exceeds"), "{}", response.reason);
            assert_eq!(response.decision_source, "validation");
            // The server closes the connection after the denial.
            assert_eq!(lines.next_line().await.expect("read EOF"), None);
        })
        .await
        .expect("connection must terminate instead of buffering indefinitely");
        task.await.expect("server task").expect("serve_connection");
    }

    /// A line exactly at the cap still reaches request parsing, and the
    /// connection stays open for further requests.
    #[tokio::test]
    async fn serve_connection_accepts_line_at_exact_cap() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let config = crate::server::tests::config_for_proposal_test();
        let task = tokio::spawn(async move {
            serve_connection(server, CallerIdentity::Unknown, &config).await
        });

        let (read_half, mut write_half) = tokio::io::split(client);
        tokio::time::timeout(TEST_TIMEOUT, async {
            let mut request = vec![b'x'; MAX_REQUEST_BYTES];
            request.push(b'\n');
            write_half.write_all(&request).await.expect("send request");
            let mut lines = BufReader::new(read_half).lines();
            let response = lines
                .next_line()
                .await
                .expect("read response")
                .expect("response line");
            let response: ExecuteResponse =
                serde_json::from_str(&response).expect("parse response");
            assert!(!response.allowed);
            // Not JSON, so it must fail at parsing, not at the size gate.
            assert!(
                response.reason.contains("invalid request"),
                "{}",
                response.reason
            );
            // The connection survives an at-cap line.
            write_half
                .write_all(b"also-not-json\n")
                .await
                .expect("send follow-up");
            let response = lines
                .next_line()
                .await
                .expect("read follow-up response")
                .expect("follow-up response line");
            let response: ExecuteResponse =
                serde_json::from_str(&response).expect("parse follow-up response");
            assert!(response.reason.contains("invalid request"));
            write_half.shutdown().await.expect("shutdown write half");
            assert_eq!(lines.next_line().await.expect("read EOF"), None);
        })
        .await
        .expect("responses must arrive");
        task.await.expect("server task").expect("serve_connection");
    }

    /// The oversized-line cap holds on TCP before any token validation runs.
    #[tokio::test]
    async fn tcp_oversized_preauth_request_closes_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let config = crate::server::tests::config_for_proposal_test();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            handle_client_tcp(stream, &config).await
        });

        let client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (read_half, mut write_half) = client.into_split();
        tokio::time::timeout(TEST_TIMEOUT, async {
            write_half
                .write_all(&vec![b'x'; MAX_REQUEST_BYTES + 1])
                .await
                .expect("stream oversized request");
            let mut lines = BufReader::new(read_half).lines();
            let response = lines
                .next_line()
                .await
                .expect("read denial")
                .expect("denial line before close");
            let response: ExecuteResponse =
                serde_json::from_str(&response).expect("parse denial response");
            assert!(!response.allowed);
            assert!(response.reason.contains("exceeds"), "{}", response.reason);
            assert_eq!(lines.next_line().await.expect("read EOF"), None);
        })
        .await
        .expect("connection must terminate instead of buffering indefinitely");
        task.await.expect("server task").expect("handle_client_tcp");
    }
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
        assert_eq!(mode(temp.path()), 0o700);
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
        assert_eq!(mode(temp.path()), 0o755);
        drop(listener);
    }

    #[tokio::test]
    async fn failed_socket_group_change_leaves_private_directory_without_socket() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("guard.sock");
        let error = Server::prepare_unix_listener(
            &socket,
            Some("guard-group-that-must-not-exist-9fce06b7"),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("failed to change group"));
        assert!(!socket.exists());
        assert_eq!(mode(temp.path()), 0o700);
    }
}
