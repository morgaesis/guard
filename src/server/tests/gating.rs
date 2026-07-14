use crate::server::admin::{handle_admin_request, handle_approval_note};
use crate::server::gate_runtime::{
    approval_to_result, execute_snapshot, hash_secret_value, hold_for_approval, new_handle,
    now_unix, route_gated_allow, GateInputs,
};
#[cfg(unix)]
use crate::server::gate_runtime::{arm_containment, finish_revert, DaemonGateSink};
use crate::server::wire::{
    AdminRequest, AdminResponse, CallerIdentity, ExecOutcome, ExecuteRequest, ExecuteResult,
    RevertSpec,
};
use crate::server::{ServerConfig, APPROVAL_TTL_SECS};
use guard::gating::approval::{Approval, ApprovalSnapshot, ApprovalStatus};
#[cfg(unix)]
use guard::gating::provisional::{ApiRevertPlan, Provisional, ProvisionalStatus};
use guard::gating::{Coverage, GateMode, Reversibility};
use guard::principal::PrincipalKey;
use std::collections::HashMap;
#[cfg(unix)]
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use tokio::io::AsyncWrite;

use super::make_test_config;

// ---- Consequence-gating orchestration tests -----------------------------
//
// These drive the daemon orchestration in this file (arm_containment,
// hold_for_approval, handle_admin_request -> confirm/approve/deny/revert,
// and the sweeper's expire/auto-revert steps) directly in-process, so the
// invariants the Docker CTF (ctf/gating) checks end-to-end are also caught
// by `cargo test`. Tests that must spawn a real forward/revert child use
// POSIX `echo`/`true`/`false` and are `#[cfg(unix)]`; the authoritative
// cross-platform run is the Linux container. The pure registry/handler
// invariants (operator gating, TTL expiry, catalog voiding) run everywhere.

// The gating types (Approval, ApprovalSnapshot, ApprovalStatus, Provisional,
// ProvisionalStatus, Coverage, GateMode, Reversibility) and AsyncWrite are
// already in scope via the imports at the top of this file.
use std::collections::BTreeMap;
#[cfg(unix)]
use std::pin::Pin;
#[cfg(unix)]
use std::task::{Context, Poll};

/// Build a containment-gating config: gate on, a distinct operator
/// principal, and the caller uid as the row owner. Returns
/// `(config, operator_caller, agent_caller)`.
fn gating_config(
    operator_uid: u32,
    agent_uid: u32,
) -> (ServerConfig, CallerIdentity, CallerIdentity) {
    let (mut cfg, _) = make_test_config();
    cfg.gate = GateMode::Consequence;
    cfg.daemon_uid = operator_uid;
    cfg.daemon_principal = PrincipalKey::from_uid(operator_uid);
    let operator = CallerIdentity::Unix { uid: operator_uid };
    let agent = CallerIdentity::Unix { uid: agent_uid };
    (cfg, operator, agent)
}

/// A request with a structured revert, used to drive `arm_containment`.
fn contain_request(binary: &str, args: &[&str], revert: RevertSpec) -> ExecuteRequest {
    ExecuteRequest {
        binary: binary.to_string(),
        args: args.iter().map(|s| s.to_string()).collect(),
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        stream: false,
        session_token: None,
        revert: Some(revert),
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        cwd: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    }
}

/// A `tokio::io::AsyncWrite` whose writes succeed `ok_writes` times and then
/// fail with `BrokenPipe`. With `ok_writes == 0` it fails on the very first
/// write, simulating a client stream that drops the instant the daemon
/// begins forwarding the child's output. The forward child still spawns and
/// runs (so the mutation may have applied); only streaming its output fails.
#[cfg(unix)]
struct FlakyWriter {
    remaining_ok: usize,
}

#[cfg(unix)]
impl FlakyWriter {
    fn failing_after(ok_writes: usize) -> Self {
        Self {
            remaining_ok: ok_writes,
        }
    }
}

#[cfg(unix)]
impl AsyncWrite for FlakyWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.remaining_ok == 0 {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "client stream dropped",
            )));
        }
        self.remaining_ok -= 1;
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// CONTAINMENT-LEAK (regression for the just-landed disconnect fix): a
/// contained forward command that LAUNCHES and then fails because the client
/// stream drops mid-run must STAY ARMED — the provisional stays in the
/// registry with `forward_done` set so the auto-revert can still fire. A
/// leak here would let an unconfirmed mutation persist past its deadline.
#[cfg(unix)]
#[tokio::test]
async fn containment_stays_armed_when_client_stream_drops_after_launch() {
    let (cfg, _operator, agent) = gating_config(7001, 1000);
    let agent_principal = agent.principal();

    // Forward `echo` produces a line, so the daemon attempts to stream it;
    // our writer fails on that first write -> exec_failed_after_start.
    let request = contain_request(
        "echo",
        &["contained-change"],
        RevertSpec {
            binary: "true".to_string(),
            args: Vec::new(),
        },
    );
    let mut writer = FlakyWriter::failing_after(0);

    let result = arm_containment(
        request,
        &cfg,
        &agent,
        agent_principal,
        "recoverable change".to_string(),
        0,
        true, // stream_output: exercise the streaming failure path
        &mut writer,
    )
    .await;

    // The forward child launched then failed: started=true.
    match &result.exec {
        ExecOutcome::Failed { started, .. } => {
            assert!(*started, "client stream drop must report started=true");
        }
        other => panic!("expected Failed{{started:true}}, got {:?}", other),
    }

    // Invariant: the provisional is STILL ARMED with forward_done set, so the
    // sweeper's take_due can fire the auto-revert. It must NOT have been
    // dropped (that would leak the unconfirmed mutation).
    let reg = cfg.provisional.read().await;
    let rows = reg.list();
    assert_eq!(rows.len(), 1, "the armed provisional must be retained");
    let p = &rows[0];
    assert_eq!(p.status, ProvisionalStatus::Armed);
    assert!(
        p.forward_done,
        "forward_done must be set so the deadline is honored"
    );
    assert_eq!(reg.outstanding(), 1, "the armed row still occupies a slot");
}

/// Counterpart to the leak test: a contained forward command that FAILS TO
/// SPAWN (nonexistent binary, started=false) has no observable effect, so
/// the provisional is DROPPED — there is nothing to revert.
#[cfg(unix)]
#[tokio::test]
async fn containment_dropped_when_forward_fails_to_spawn() {
    let (cfg, _operator, agent) = gating_config(7002, 1000);
    let agent_principal = agent.principal();

    let request = contain_request(
        "guard-nonexistent-binary-xyz",
        &[],
        RevertSpec {
            binary: "true".to_string(),
            args: Vec::new(),
        },
    );
    let mut sink = tokio::io::sink();

    let result = arm_containment(
        request,
        &cfg,
        &agent,
        agent_principal,
        "recoverable change".to_string(),
        0,
        false,
        &mut sink,
    )
    .await;

    match &result.exec {
        ExecOutcome::Failed { started, .. } => {
            assert!(!*started, "spawn failure must report started=false");
        }
        other => panic!("expected Failed{{started:false}}, got {:?}", other),
    }

    // The provisional was dropped: nothing ran, so nothing to revert.
    let reg = cfg.provisional.read().await;
    assert!(
        reg.list().is_empty(),
        "a never-launched forward must drop its provisional"
    );
}

/// contain -> operator confirm keeps the change (no revert fires), and
/// confirm is daemon-principal-only: a non-operator caller is refused before
/// the registry is touched.
#[cfg(unix)]
#[tokio::test]
async fn contain_then_operator_confirm_keeps_change_nonoperator_refused() {
    let (cfg, operator, agent) = gating_config(7003, 1000);
    let agent_principal = agent.principal();

    let request = contain_request(
        "true",
        &[],
        RevertSpec {
            binary: "true".to_string(),
            args: Vec::new(),
        },
    );
    let mut sink = tokio::io::sink();
    let result = arm_containment(
        request,
        &cfg,
        &agent,
        agent_principal,
        "recoverable change".to_string(),
        0,
        false,
        &mut sink,
    )
    .await;
    let handle = match &result.exec {
        ExecOutcome::Provisional { handle, .. } => handle.clone(),
        other => panic!("expected Provisional, got {:?}", other),
    };

    // A non-operator (uid != daemon_principal) cannot confirm: validate_admin
    // refuses before handle_confirm runs, so the row is untouched.
    let refused = handle_admin_request(
        &cfg,
        &agent,
        AdminRequest::Confirm {
            handle: handle.clone(),
        },
    )
    .await;
    match refused {
        AdminResponse::Error { message } => {
            assert!(
                message.contains("not the daemon principal"),
                "got: {message}"
            );
        }
        other => panic!("non-operator confirm must be refused, got {:?}", other),
    }
    assert_eq!(
        cfg.provisional.read().await.get(&handle).unwrap().status,
        ProvisionalStatus::Armed,
        "a refused confirm must not change state"
    );

    // The operator confirms: the change is kept and the auto-revert is
    // cancelled.
    let ok = handle_admin_request(
        &cfg,
        &operator,
        AdminRequest::Confirm {
            handle: handle.clone(),
        },
    )
    .await;
    assert!(matches!(ok, AdminResponse::GateAction { .. }));
    assert_eq!(
        cfg.provisional.read().await.get(&handle).unwrap().status,
        ProvisionalStatus::Confirmed
    );

    // A confirmed provisional is never due, even far past any deadline: the
    // sweeper's take_due step yields nothing to revert.
    let due = cfg
        .provisional
        .write()
        .await
        .take_due(now_unix() + 10_000_000);
    assert!(due.is_empty(), "a confirmed change must never auto-revert");
}

/// contain -> deadline passes -> the sweeper's auto-revert path fires and
/// rolls the change back. Drives the sweeper's `take_due` + `finish_revert`
/// steps directly (the live `gating_sweeper` is an infinite loop with a
/// startup grace, so its time-driven body is exercised piecewise here).
#[cfg(unix)]
#[tokio::test]
async fn contain_then_deadline_triggers_sweeper_autorevert() {
    let (cfg, _operator, agent) = gating_config(7004, 1000);
    let agent_principal = agent.principal();

    // A 1s window: the smallest the clamp allows.
    let mut request = contain_request(
        "true",
        &[],
        RevertSpec {
            binary: "true".to_string(),
            args: Vec::new(),
        },
    );
    request.confirm_within_secs = Some(1);
    let mut sink = tokio::io::sink();
    let result = arm_containment(
        request,
        &cfg,
        &agent,
        agent_principal,
        "recoverable change".to_string(),
        0,
        false,
        &mut sink,
    )
    .await;
    let handle = match &result.exec {
        ExecOutcome::Provisional { handle, .. } => handle.clone(),
        other => panic!("expected Provisional, got {:?}", other),
    };

    // Sweeper step: claim every armed-and-due provisional (simulate the
    // deadline by passing a `now` well past it), then run each revert.
    let due = cfg
        .provisional
        .write()
        .await
        .take_due(now_unix() + 10_000_000);
    assert_eq!(
        due.len(),
        1,
        "the armed provisional is due past its deadline"
    );
    for p in &due {
        finish_revert(&cfg, p, &CallerIdentity::Unknown, "auto").await;
    }

    // The `true` revert exits 0 -> Reverted.
    assert_eq!(
        cfg.provisional.read().await.get(&handle).unwrap().status,
        ProvisionalStatus::Reverted,
        "auto-revert must roll the unconfirmed change back"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn api_revert_without_running_proxy_defers_to_operator() {
    let (cfg, _operator, _agent) = gating_config(7014, 1000);
    let handle = "api-missing-proxy".to_string();
    let now = now_unix();
    let provisional = Provisional {
        handle: handle.clone(),
        principal: Some(cfg.daemon_principal.clone()),
        binary: "(api-proxy)".to_string(),
        args: vec!["delete labels/bug in o/r".to_string()],
        cwd: None,
        revert_binary: "(api-proxy)".to_string(),
        revert_args: vec![
            "github".to_string(),
            "POST".to_string(),
            "/repos/o/r/labels".to_string(),
        ],
        api_revert: Some(ApiRevertPlan {
            protocol: "github".to_string(),
            method: "POST".to_string(),
            path: "/repos/o/r/labels".to_string(),
            body_file: None,
        }),
        reason: "delete labels/bug in o/r".to_string(),
        created_unix: now,
        deadline_unix: now,
        forward_done: true,
        status: ProvisionalStatus::Reverting,
        revert_exit: None,
        revert_detail: None,
    };
    cfg.provisional.write().await.insert(provisional.clone());

    // A missing proxy is recoverable: the change is still live, so the revert
    // is deferred to the operator (NeedsOperatorDecision) rather than burned as
    // a terminal RevertFailed.
    let (message, exit) = finish_revert(&cfg, &provisional, &CallerIdentity::Unknown, "auto").await;
    assert!(message.contains("deferred"), "got: {message}");
    assert_eq!(exit, None);
    let row = cfg.provisional.read().await.get(&handle).cloned().unwrap();
    assert_eq!(row.status, ProvisionalStatus::NeedsOperatorDecision);
    assert!(row
        .revert_detail
        .as_deref()
        .unwrap()
        .contains("no running api-proxy for protocol 'github'"));
}

/// The sweeper executes a due API revert as an HTTP request through the
/// registered proxy's upstream, carrying the daemon's bearer credential and
/// the persisted body. This is the success half of the fail-loud test above.
#[cfg(unix)]
#[tokio::test]
async fn api_revert_executes_through_registered_proxy_upstream() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Minimal recording upstream: capture the one request, answer 200 JSON.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let captured: Arc<std::sync::Mutex<String>> = Arc::new(std::sync::Mutex::new(String::new()));
    let captured_in = captured.clone();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            *captured_in.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).to_string();
            let _ = stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}",
                )
                .await;
        }
    });

    let (cfg, _operator, _agent) = gating_config(7015, 1000);
    let upstream = guard::proxy::Upstream::from_base_url(
        &format!("http://{upstream_addr}"),
        guard::proxy::UpstreamAuth::Bearer("revert-token".to_string()),
    )
    .expect("upstream");
    let proxy = Arc::new(guard::proxy::ApiProxy::with_protocol(
        Arc::new(guard::proxy::GithubProtocol),
        "127.0.0.1:0".parse().unwrap(),
        guard::proxy::ProxyTls::generate().expect("tls"),
        upstream,
        guard::proxy::ApiPolicy::deny_all(),
        None,
    ));
    cfg.protocol_registry
        .write()
        .await
        .insert("github".to_string(), proxy);

    let body_file = std::env::temp_dir().join(format!("api-revert-body-{}", std::process::id()));
    std::fs::write(&body_file, br#"{"name":"bug","color":"d73a4a"}"#).unwrap();

    let handle = "api-live-proxy".to_string();
    let now = now_unix();
    let provisional = Provisional {
        handle: handle.clone(),
        principal: Some(cfg.daemon_principal.clone()),
        binary: "(api-proxy)".to_string(),
        args: vec!["delete labels/bug in o/r".to_string()],
        cwd: None,
        revert_binary: "(api-proxy)".to_string(),
        revert_args: vec![
            "github".to_string(),
            "POST".to_string(),
            "/repos/o/r/labels".to_string(),
        ],
        api_revert: Some(ApiRevertPlan {
            protocol: "github".to_string(),
            method: "POST".to_string(),
            path: "/repos/o/r/labels".to_string(),
            body_file: Some(body_file.clone()),
        }),
        reason: "delete labels/bug in o/r".to_string(),
        created_unix: now,
        deadline_unix: now,
        forward_done: true,
        status: ProvisionalStatus::Reverting,
        revert_exit: None,
        revert_detail: None,
    };
    cfg.provisional.write().await.insert(provisional.clone());

    let (message, exit) = finish_revert(&cfg, &provisional, &CallerIdentity::Unknown, "auto").await;
    assert!(message.contains("reverted"), "got: {message}");
    assert_eq!(exit, Some(0));
    let row = cfg.provisional.read().await.get(&handle).cloned().unwrap();
    assert_eq!(row.status, ProvisionalStatus::Reverted);

    let raw = captured.lock().unwrap().clone();
    assert!(raw.starts_with("POST /repos/o/r/labels HTTP/1.1"), "{raw}");
    assert!(
        raw.contains("authorization: Bearer revert-token")
            || raw.contains("Authorization: Bearer revert-token"),
        "daemon credential must ride the revert: {raw}"
    );
    assert!(raw.contains(r#"{"name":"bug","color":"d73a4a"}"#), "{raw}");
    // The secret-bearing snapshot body is removed once the revert is terminal.
    assert!(
        !body_file.exists(),
        "revert body file must be unlinked after a terminal revert"
    );
}

/// A recoverable command whose free-form `--revert` cannot be affirmed is
/// HELD for operator review, not armed with an unverified rollback and not
/// silently denied. Here the rollback binary is structurally invalid, so
/// `assess_revert` returns `NeedsReview` before any evaluator call, keeping
/// the test deterministic and cross-platform (the hold path spawns no child).
#[tokio::test]
async fn recoverable_with_unaffirmable_revert_is_held_for_review() {
    let (cfg, _operator, agent) = gating_config(7011, 1000);

    let request = contain_request(
        "systemctl",
        &["restart", "app"],
        RevertSpec {
            binary: "../evil".to_string(), // `..` rejected by invalid_binary_reason
            args: Vec::new(),
        },
    );
    let inputs = GateInputs {
        reason: "recoverable restart".to_string(),
        risk: Some(2),
        reversibility: Some(Reversibility::Recoverable),
        revert_preauthorized: false,
        verb: None,
        bypass: false,
    };
    let mut sink = tokio::io::sink();
    let result = route_gated_allow(request, &cfg, &agent, inputs, 0, false, &mut sink).await;

    let handle = match &result.exec {
        ExecOutcome::Held { handle, .. } => handle.clone(),
        other => panic!("expected Held, got {:?}", other),
    };
    assert!(
        result.policy_reason().contains("held for operator review"),
        "reason should explain the escalation: {}",
        result.policy_reason()
    );
    assert_eq!(
        cfg.provisional.read().await.outstanding(),
        0,
        "an unaffirmable rollback must never arm a containment envelope"
    );
    assert_eq!(
        cfg.approvals.read().await.get(&handle).unwrap().status,
        ApprovalStatus::Pending,
        "the forward command must be queued for an operator decision"
    );
}

/// hold -> operator approve executes from the bound snapshot; a non-operator
/// caller cannot approve (validate_admin refuses before any state change).
#[cfg(unix)]
#[tokio::test]
async fn hold_then_operator_approve_executes_snapshot_nonoperator_refused() {
    let (cfg, operator, agent) = gating_config(7005, 1000);
    let agent_principal = agent.principal();

    // Hold a command. `true` is the bound binary; approval must run exactly
    // this snapshot.
    let request = ExecuteRequest {
        binary: "true".to_string(),
        args: Vec::new(),
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        stream: false,
        session_token: None,
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        cwd: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    };
    let mut sink = tokio::io::sink();
    let held = hold_for_approval(
        request,
        &cfg,
        &agent,
        agent_principal,
        "needs sign-off".to_string(),
        Some(9),
        Some(Reversibility::Irreversible),
        None,
        false,
        &mut sink,
    )
    .await;
    let handle = match &held.exec {
        ExecOutcome::Held { handle, .. } => handle.clone(),
        other => panic!("expected Held, got {:?}", other),
    };

    // Non-operator approve is refused; the hold stays pending.
    let refused = handle_admin_request(
        &cfg,
        &agent,
        AdminRequest::Approve {
            handle: handle.clone(),
        },
    )
    .await;
    match refused {
        AdminResponse::Error { message } => {
            assert!(
                message.contains("not the daemon principal"),
                "got: {message}"
            );
        }
        other => panic!("non-operator approve must be refused, got {:?}", other),
    }
    assert_eq!(
        cfg.approvals.read().await.get(&handle).unwrap().status,
        ApprovalStatus::Pending,
        "a refused approve must not change state"
    );

    // Operator approves: the snapshot executes (`true` -> exit 0) and the row
    // becomes Approved.
    let ok = handle_admin_request(
        &cfg,
        &operator,
        AdminRequest::Approve {
            handle: handle.clone(),
        },
    )
    .await;
    match ok {
        AdminResponse::GateAction { exit_code, .. } => {
            assert_eq!(exit_code, Some(0), "approved `true` exits 0");
        }
        other => panic!("operator approve should execute, got {:?}", other),
    }
    assert_eq!(
        cfg.approvals.read().await.get(&handle).unwrap().status,
        ApprovalStatus::Approved
    );
}

/// Wait (bounded) for a pending approval row to appear and return its handle.
async fn wait_for_pending_hold(cfg: &ServerConfig) -> String {
    for _ in 0..100 {
        let pending: Vec<String> = cfg
            .approvals
            .read()
            .await
            .list()
            .into_iter()
            .filter(|a| a.status == ApprovalStatus::Pending)
            .map(|a| a.handle)
            .collect();
        if let Some(h) = pending.into_iter().next() {
            return h;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("no pending hold appeared");
}

/// A kube-proxy `hold` parks the request in the approval queue: an operator
/// approve releases the waiter without spawning any process, an operator
/// deny fails it closed, and a waiter that vanishes undecided (client
/// disconnect) retires its row so the queue never offers a dead approval.
#[cfg(unix)]
#[tokio::test]
async fn kube_proxy_hold_routes_through_approval_queue() {
    let (cfg, operator, _agent) = gating_config(7013, 1000);
    let sink = Arc::new(DaemonGateSink {
        config: cfg.clone(),
        protocol: "kubernetes".to_string(),
        snapshot_dir: std::env::temp_dir(),
        snapshot_dir_safe: true,
        window_secs: 60,
    });

    // Approve: the waiter returns Approved with the queue handle; the row is
    // Approved and carries no exec result (nothing ran).
    let s = sink.clone();
    let waiter = tokio::spawn(async move {
        guard::proxy::GateSink::hold_request(&*s, "delete namespaces/prod", "namespace delete")
            .await
    });
    let handle = wait_for_pending_hold(&cfg).await;
    let resp = handle_admin_request(
        &cfg,
        &operator,
        AdminRequest::Approve {
            handle: handle.clone(),
        },
    )
    .await;
    match resp {
        AdminResponse::GateAction {
            message, exit_code, ..
        } => {
            assert!(message.contains("forwarding"), "got: {message}");
            assert_eq!(exit_code, None, "a released API hold executes nothing");
        }
        other => panic!("operator approve should release the hold, got {:?}", other),
    }
    match waiter.await.unwrap() {
        guard::proxy::HoldDecision::Approved { handle: h } => assert_eq!(h, handle),
        other => panic!("expected Approved, got {:?}", other),
    }
    assert_eq!(
        cfg.approvals.read().await.get(&handle).unwrap().status,
        ApprovalStatus::Approved
    );

    // Deny: the waiter fails closed with the operator's reason.
    let s = sink.clone();
    let waiter = tokio::spawn(async move {
        guard::proxy::GateSink::hold_request(&*s, "delete namespaces/prod", "namespace delete")
            .await
    });
    let handle = wait_for_pending_hold(&cfg).await;
    let resp = handle_admin_request(
        &cfg,
        &operator,
        AdminRequest::Deny {
            handle: handle.clone(),
        },
    )
    .await;
    assert!(
        !matches!(resp, AdminResponse::Error { .. }),
        "operator deny should succeed: {:?}",
        resp
    );
    match waiter.await.unwrap() {
        guard::proxy::HoldDecision::Denied { .. } => {}
        other => panic!("expected Denied, got {:?}", other),
    }
    assert_eq!(
        cfg.approvals.read().await.get(&handle).unwrap().status,
        ApprovalStatus::Denied
    );

    // Disconnect: dropping the waiter mid-hold retires the pending row.
    let s = sink.clone();
    let waiter = tokio::spawn(async move {
        guard::proxy::GateSink::hold_request(&*s, "delete namespaces/prod", "namespace delete")
            .await
    });
    let handle = wait_for_pending_hold(&cfg).await;
    waiter.abort();
    let mut retired = false;
    for _ in 0..100 {
        if cfg.approvals.read().await.get(&handle).unwrap().status == ApprovalStatus::ExecFailed {
            retired = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        retired,
        "an abandoned hold must be retired, not left pending"
    );
}

/// A non-streaming `--wait-approval` waiter must return as soon as the
/// operator decides, not park until its timeout: the waiter registers with
/// the notifier before checking status, so a decision landing in the gap
/// still completes the park immediately.
#[tokio::test]
async fn nonstreaming_wait_approval_returns_promptly_on_decision() {
    let (cfg, _operator, agent) = gating_config(7014, 1000);
    let agent_principal = agent.principal();

    let request = ExecuteRequest {
        binary: "rm".to_string(),
        args: vec!["-rf".to_string(), "/data".to_string()],
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        stream: false,
        session_token: None,
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        cwd: None,
        require_approval: None,
        wait_approval_secs: Some(30),
        verb: None,
    };
    let cfg2 = cfg.clone();
    let waiter = tokio::spawn(async move {
        let mut sink = tokio::io::sink();
        hold_for_approval(
            request,
            &cfg2,
            &agent,
            agent_principal,
            "destructive".to_string(),
            Some(10),
            Some(Reversibility::Irreversible),
            None,
            false,
            &mut sink,
        )
        .await
    });

    let handle = wait_for_pending_hold(&cfg).await;
    {
        let mut reg = cfg.approvals.write().await;
        reg.deny(&handle, now_unix(), "operator rejected".to_string())
            .unwrap();
    }

    // Well under the 30s wait: the deny must wake the waiter.
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
        .await
        .expect("waiter must wake on the decision, not sit out its timeout")
        .unwrap();
    assert!(!result.policy_allowed(), "denied decision is returned");
    assert!(
        result.policy_reason().contains("operator rejected"),
        "got: {}",
        result.policy_reason()
    );
}

/// hold -> TTL expiry -> the sweeper denies (fail-closed); the command never
/// executes. Cross-platform: no child is spawned on this path.
#[tokio::test]
async fn hold_then_ttl_expiry_denies_fail_closed() {
    let (cfg, _operator, agent) = gating_config(7006, 1000);
    let agent_principal = agent.principal();

    let request = ExecuteRequest {
        binary: "rm".to_string(),
        args: vec!["-rf".to_string(), "/data".to_string()],
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        stream: false,
        session_token: None,
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        cwd: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    };
    let mut sink = tokio::io::sink();
    let held = hold_for_approval(
        request,
        &cfg,
        &agent,
        agent_principal,
        "destructive".to_string(),
        Some(10),
        Some(Reversibility::Irreversible),
        None,
        false,
        &mut sink,
    )
    .await;
    let handle = match &held.exec {
        ExecOutcome::Held { handle, .. } => handle.clone(),
        other => panic!("expected Held, got {:?}", other),
    };

    // Sweeper step: expire every pending hold past its TTL. Pass a `now` far
    // beyond the TTL so the deadline has certainly passed.
    let expired = cfg
        .approvals
        .write()
        .await
        .expire_due(now_unix() + APPROVAL_TTL_SECS + 10_000);
    assert_eq!(expired, vec![handle.clone()]);

    let row = cfg.approvals.read().await.get(&handle).cloned().unwrap();
    assert_eq!(
        row.status,
        ApprovalStatus::Expired,
        "an unattended hold must fail closed (deny), not execute"
    );
    // The client-facing result is a denial, never an execution.
    let result = approval_to_result(&row);
    assert!(!result.policy_allowed());
    assert!(result.policy_reason().contains("expired"));
    assert!(matches!(result.exec, ExecOutcome::NotAttempted));
}

#[test]
fn hash_secret_value_is_salted_and_value_sensitive() {
    let a = hash_secret_value("salt1", "v1");
    // Deterministic for the same (salt, value).
    assert_eq!(a, hash_secret_value("salt1", "v1"));
    // Sensitive to the value.
    assert_ne!(a, hash_secret_value("salt1", "v2"));
    // Sensitive to the salt (so a persisted digest is not a plain value hash).
    assert_ne!(a, hash_secret_value("salt2", "v1"));
    // 32-byte SHA-256 -> 64 hex chars.
    assert_eq!(a.len(), 64);
}

/// A held command captures a salted hash of its mapped secret VALUES. If the
/// same-principal caller swaps a value between hold and approval, approval
/// fails closed before the command runs.
#[tokio::test]
async fn approve_rejected_when_bound_secret_value_changed() {
    let (cfg, _operator, agent) = gating_config(7201, 4201);
    let agent_principal = agent.principal();
    let p = agent_principal.clone().expect("agent principal");
    cfg.secrets.set(&p, "BIND_TEST_KEY", "v1").await.unwrap();

    let mut secrets = HashMap::new();
    secrets.insert("INJECTED".to_string(), "BIND_TEST_KEY".to_string());
    let request = ExecuteRequest {
        binary: "true".to_string(),
        args: Vec::new(),
        auth_token: None,
        env: HashMap::new(),
        secrets,
        stream: false,
        session_token: None,
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        cwd: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    };
    let mut sink = tokio::io::sink();
    let held = hold_for_approval(
        request,
        &cfg,
        &agent,
        agent_principal.clone(),
        "needs review".to_string(),
        Some(8),
        Some(Reversibility::Irreversible),
        None,
        false,
        &mut sink,
    )
    .await;
    let handle = match &held.exec {
        ExecOutcome::Held { handle, .. } => handle.clone(),
        other => panic!("expected Held, got {:?}", other),
    };

    let snapshot = cfg
        .approvals
        .read()
        .await
        .get(&handle)
        .cloned()
        .unwrap()
        .snapshot;
    assert!(
        snapshot.secret_binding.is_some(),
        "a secret-value binding must be captured at hold time"
    );

    // The same principal swaps the value the operator was reviewing.
    cfg.secrets
        .set(&p, "BIND_TEST_KEY", "v2-tampered")
        .await
        .unwrap();

    let result = execute_snapshot(&cfg, &snapshot, "operator approved").await;
    match &result.exec {
        ExecOutcome::Failed { reason, started } => {
            assert!(!started, "the command must not have started");
            assert!(
                reason.contains("changed since the command was held"),
                "got: {}",
                reason
            );
        }
        other => panic!("expected a fail-closed rejection, got {:?}", other),
    }

    let _ = cfg.secrets.delete(&p, "BIND_TEST_KEY").await;
}

/// When the bound value is unchanged, the binding check passes (it does not
/// reject), so the approved command proceeds to execution.
#[tokio::test]
async fn approve_passes_binding_when_secret_value_unchanged() {
    let (cfg, _operator, agent) = gating_config(7202, 4202);
    let agent_principal = agent.principal();
    let p = agent_principal.clone().expect("agent principal");
    cfg.secrets.set(&p, "BIND_OK_KEY", "stable").await.unwrap();

    let mut secrets = HashMap::new();
    secrets.insert("INJECTED".to_string(), "BIND_OK_KEY".to_string());
    let request = ExecuteRequest {
        binary: "true".to_string(),
        args: Vec::new(),
        auth_token: None,
        env: HashMap::new(),
        secrets,
        stream: false,
        session_token: None,
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        cwd: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    };
    let mut sink = tokio::io::sink();
    let held = hold_for_approval(
        request,
        &cfg,
        &agent,
        agent_principal.clone(),
        "needs review".to_string(),
        Some(8),
        Some(Reversibility::Irreversible),
        None,
        false,
        &mut sink,
    )
    .await;
    let handle = match &held.exec {
        ExecOutcome::Held { handle, .. } => handle.clone(),
        other => panic!("expected Held, got {:?}", other),
    };
    let snapshot = cfg
        .approvals
        .read()
        .await
        .get(&handle)
        .cloned()
        .unwrap()
        .snapshot;

    // Value unchanged -> the binding check must NOT reject. The subsequent
    // exec of `true` succeeds on Unix; on Windows there is no `true` binary,
    // so it may fail to spawn — either way it is not the binding rejection,
    // which is what this test asserts.
    let result = execute_snapshot(&cfg, &snapshot, "operator approved").await;
    if let ExecOutcome::Failed { reason, .. } = &result.exec {
        assert!(
            !reason.contains("changed since the command was held"),
            "binding check must not reject an unchanged value; got: {}",
            reason
        );
    }

    let _ = cfg.secrets.delete(&p, "BIND_OK_KEY").await;
}

/// The binding is mandatory: a secret that is UNRESOLVED at hold is bound by
/// a sentinel, so a same-principal caller cannot disable verification by
/// making a secret absent at hold and then creating it with a chosen value
/// before approval. Approval fails closed when the absent secret appears.
#[tokio::test]
async fn approve_rejected_when_unresolved_secret_appears_after_hold() {
    let (cfg, _operator, agent) = gating_config(7203, 4203);
    let agent_principal = agent.principal();
    let p = agent_principal.clone().expect("agent principal");
    // The secret does NOT exist at hold time.
    let _ = cfg.secrets.delete(&p, "BIND_LATE_KEY").await;

    let mut secrets = HashMap::new();
    secrets.insert("INJECTED".to_string(), "BIND_LATE_KEY".to_string());
    let request = ExecuteRequest {
        binary: "true".to_string(),
        args: Vec::new(),
        auth_token: None,
        env: HashMap::new(),
        secrets,
        stream: false,
        session_token: None,
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        cwd: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    };
    let mut sink = tokio::io::sink();
    let held = hold_for_approval(
        request,
        &cfg,
        &agent,
        agent_principal.clone(),
        "needs review".to_string(),
        Some(8),
        Some(Reversibility::Irreversible),
        None,
        false,
        &mut sink,
    )
    .await;
    let handle = match &held.exec {
        ExecOutcome::Held { handle, .. } => handle.clone(),
        other => panic!("expected Held, got {:?}", other),
    };
    let snapshot = cfg
        .approvals
        .read()
        .await
        .get(&handle)
        .cloned()
        .unwrap()
        .snapshot;
    // A binding is captured even though the secret was unresolved at hold.
    assert!(
        snapshot.secret_binding.is_some(),
        "the binding must be mandatory, capturing a sentinel for the absent secret"
    );

    // The caller now creates the previously-absent secret with a chosen value.
    cfg.secrets
        .set(&p, "BIND_LATE_KEY", "sneaked-in")
        .await
        .unwrap();

    let result = execute_snapshot(&cfg, &snapshot, "operator approved").await;
    match &result.exec {
        ExecOutcome::Failed { reason, started } => {
            assert!(!started, "the command must not have started");
            assert!(
                reason.contains("changed since the command was held"),
                "got: {}",
                reason
            );
        }
        other => panic!("expected a fail-closed rejection, got {:?}", other),
    }

    let _ = cfg.secrets.delete(&p, "BIND_LATE_KEY").await;
}

/// The approval discussion thread accepts notes from the operator and from
/// the hold's original requester, refuses everyone else, and freezes once
/// the hold is decided.
#[tokio::test]
async fn approval_note_operator_and_owner_post_others_refused() {
    let (cfg, operator, agent) = gating_config(7301, 4301);
    let agent_principal = agent.principal();
    let request = ExecuteRequest {
        binary: "true".to_string(),
        args: Vec::new(),
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        stream: false,
        session_token: None,
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        cwd: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    };
    let mut sink = tokio::io::sink();
    let held = hold_for_approval(
        request,
        &cfg,
        &agent,
        agent_principal.clone(),
        "review".to_string(),
        Some(8),
        Some(Reversibility::Irreversible),
        None,
        false,
        &mut sink,
    )
    .await;
    let handle = match &held.exec {
        ExecOutcome::Held { handle, .. } => handle.clone(),
        other => panic!("expected Held, got {:?}", other),
    };

    // The requester (hold owner) can post.
    let r = handle_approval_note(&cfg, &agent, &handle, "why is this needed?").await;
    assert!(
        matches!(r, AdminResponse::ApprovalShow { .. }),
        "owner should post: {:?}",
        r
    );

    // The operator can post; the thread now has both turns, labeled.
    let r = handle_approval_note(&cfg, &operator, &handle, "ok, approving").await;
    match r {
        AdminResponse::ApprovalShow { item } => {
            assert_eq!(item.notes.len(), 2);
            assert_eq!(item.notes[0].author, "requester");
            assert_eq!(item.notes[1].author, "operator");
        }
        other => panic!("operator should post: {:?}", other),
    }

    // A different non-operator principal is refused (NotFound, no leak).
    let stranger = CallerIdentity::Unix { uid: 9999 };
    assert!(
        matches!(
            handle_approval_note(&cfg, &stranger, &handle, "let me in").await,
            AdminResponse::Error { .. }
        ),
        "a stranger must be refused"
    );

    // Empty text is rejected.
    assert!(matches!(
        handle_approval_note(&cfg, &operator, &handle, "   ").await,
        AdminResponse::Error { .. }
    ));

    // Once decided, the thread is frozen.
    cfg.approvals
        .write()
        .await
        .deny(&handle, now_unix(), "denied".to_string())
        .unwrap();
    assert!(
        matches!(
            handle_approval_note(&cfg, &operator, &handle, "too late").await,
            AdminResponse::Error { .. }
        ),
        "a decided hold's thread must be frozen"
    );
}

/// approve after the verb catalog version changed is voided: the approved
/// artifact may no longer mean what the operator reviewed, so the daemon
/// fails it closed rather than executing a stale rendering. Cross-platform:
/// the void check returns before any child is spawned.
#[tokio::test]
async fn approve_voided_when_verb_catalog_version_changed() {
    let (cfg, operator, agent) = gating_config(7007, 1000);

    // Enqueue a hold that originated from a verb, stamped with a catalog
    // version that differs from the live (empty) catalog's version. Use a
    // binary that would clearly execute if the void check were skipped, so a
    // false pass is detectable.
    let handle = new_handle();
    let snapshot = ApprovalSnapshot {
        binary: "true".to_string(),
        args: Vec::new(),
        cwd: None,
        env: BTreeMap::new(),
        secret_keys: BTreeMap::new(),
        verb_name: Some("restart-service".to_string()),
        verb_params: BTreeMap::new(),
        // Live catalog (VerbCatalog::empty()) has version 0; a stale stamp.
        catalog_version: Some(424_242),
        principal: agent.principal(),
        secret_binding: None,
    };
    let approval = Approval {
        handle: handle.clone(),
        snapshot,
        reason: "verb hold".to_string(),
        risk: Some(8),
        reversibility: Some(Reversibility::Irreversible),
        created_unix: now_unix(),
        ttl_secs: APPROVAL_TTL_SECS,
        status: ApprovalStatus::Pending,
        decided_unix: None,
        decided_reason: None,
        result_exit: None,
        result_stdout: None,
        result_stderr: None,
        notes: Vec::new(),
    };
    assert_ne!(
        approval.snapshot.catalog_version,
        Some(cfg.verbs.read().await.version()),
        "test precondition: the stamped version must differ from live"
    );
    cfg.approvals.write().await.enqueue(approval);

    let voided = handle_admin_request(
        &cfg,
        &operator,
        AdminRequest::Approve {
            handle: handle.clone(),
        },
    )
    .await;
    match voided {
        AdminResponse::Error { message } => {
            assert!(
                message.contains("catalog changed") && message.contains("voided"),
                "got: {message}"
            );
        }
        other => panic!("a stale-catalog approve must be voided, got {:?}", other),
    }

    // The hold is terminal (ExecFailed), not Approved: nothing executed.
    assert_eq!(
        cfg.approvals.read().await.get(&handle).unwrap().status,
        ApprovalStatus::ExecFailed
    );
}

#[tokio::test]
async fn approved_snapshot_rechecks_binary_floor_before_exec() {
    let (mut cfg, _, agent) = gating_config(7015, 1000);
    cfg.allowed_binaries = Some(vec!["echo".to_string()]);
    let snapshot = ApprovalSnapshot {
        binary: "sh".to_string(),
        args: vec!["-c".to_string(), "true".to_string()],
        cwd: None,
        env: BTreeMap::new(),
        secret_keys: BTreeMap::new(),
        verb_name: None,
        verb_params: BTreeMap::new(),
        catalog_version: None,
        principal: agent.principal(),
        secret_binding: None,
    };

    let result = execute_snapshot(&cfg, &snapshot, "operator approved").await;

    assert!(matches!(
        result.exec,
        ExecOutcome::Failed { started: false, .. }
    ));
    assert_eq!(result.policy_reason(), "operator approved");
    if let ExecOutcome::Failed { reason, .. } = result.exec {
        assert!(reason.contains("not in the server allow-list"));
    }
}

#[tokio::test]
async fn approved_snapshot_rejects_dangerous_request_env_before_exec() {
    let (cfg, _, agent) = gating_config(7018, 1000);
    let snapshot = ApprovalSnapshot {
        binary: "sh".to_string(),
        args: vec!["-c".to_string(), "printf should-not-run".to_string()],
        cwd: None,
        env: BTreeMap::from([(
            "SSH_AUTH_SOCK".to_string(),
            "/tmp/caller-agent.sock".to_string(),
        )]),
        secret_keys: BTreeMap::new(),
        verb_name: None,
        verb_params: BTreeMap::new(),
        catalog_version: None,
        principal: agent.principal(),
        secret_binding: None,
    };

    let result = execute_snapshot(&cfg, &snapshot, "operator approved").await;

    assert!(matches!(
        result.exec,
        ExecOutcome::Failed { started: false, .. }
    ));
    assert_eq!(result.policy_reason(), "operator approved");
    if let ExecOutcome::Failed { reason, .. } = result.exec {
        assert!(reason.contains("dangerous injected environment variable name: 'SSH_AUTH_SOCK'"));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn approved_snapshot_executes_in_snapshotted_cwd() {
    let (cfg, _, agent) = gating_config(7016, 1000);
    let temp = tempfile::tempdir().unwrap();
    let snapshot = ApprovalSnapshot {
        binary: "sh".to_string(),
        args: vec![
            "-c".to_string(),
            "printf approved > approval-cwd.txt".to_string(),
        ],
        cwd: Some(temp.path().to_path_buf()),
        env: BTreeMap::new(),
        secret_keys: BTreeMap::new(),
        verb_name: None,
        verb_params: BTreeMap::new(),
        catalog_version: None,
        principal: agent.principal(),
        secret_binding: None,
    };

    let result = execute_snapshot(&cfg, &snapshot, "operator approved").await;

    assert!(matches!(
        result.exec,
        ExecOutcome::Completed {
            exit_code: Some(0),
            ..
        }
    ));
    assert_eq!(
        std::fs::read_to_string(temp.path().join("approval-cwd.txt")).unwrap(),
        "approved"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn approved_snapshot_rejects_missing_snapshotted_cwd_before_exec() {
    let (cfg, _, agent) = gating_config(7017, 1000);
    let temp = tempfile::tempdir().unwrap();
    let cwd = temp.path().to_path_buf();
    let snapshot = ApprovalSnapshot {
        binary: "sh".to_string(),
        args: vec!["-c".to_string(), "printf approved".to_string()],
        cwd: Some(cwd.clone()),
        env: BTreeMap::new(),
        secret_keys: BTreeMap::new(),
        verb_name: None,
        verb_params: BTreeMap::new(),
        catalog_version: None,
        principal: agent.principal(),
        secret_binding: None,
    };
    drop(temp);

    let result = execute_snapshot(&cfg, &snapshot, "operator approved").await;

    match result.exec {
        ExecOutcome::Failed {
            started, reason, ..
        } => {
            assert!(!started);
            assert!(
                reason.contains("working directory")
                    && reason.contains("changed before exec")
                    && reason.contains(cwd.to_str().unwrap()),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected stale cwd rejection, got {other:?}"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn provisional_revert_executes_in_snapshotted_cwd() {
    let (cfg, _operator, agent) = gating_config(7017, 1000);
    let temp = tempfile::tempdir().unwrap();
    let provisional = Provisional {
        handle: "cwd-revert".to_string(),
        principal: agent.principal(),
        binary: "true".to_string(),
        args: Vec::new(),
        cwd: Some(temp.path().to_path_buf()),
        revert_binary: "sh".to_string(),
        revert_args: vec![
            "-c".to_string(),
            "printf reverted > provisional-cwd.txt".to_string(),
        ],
        api_revert: None,
        reason: "cwd revert".to_string(),
        created_unix: now_unix(),
        deadline_unix: now_unix(),
        forward_done: true,
        status: ProvisionalStatus::Reverting,
        revert_exit: None,
        revert_detail: None,
    };
    cfg.provisional.write().await.insert(provisional.clone());

    let (_message, exit) = finish_revert(&cfg, &provisional, &agent, "test").await;

    assert_eq!(exit, Some(0));
    assert_eq!(
        std::fs::read_to_string(temp.path().join("provisional-cwd.txt")).unwrap(),
        "reverted"
    );
}

/// Sanity: `Coverage::contain` is what a provisional carries, so the
/// client-facing result of a contained action advertises the residual risk
/// the operator owns (the gate did not verify the rollback inverts the
/// change). Guards against silently dropping coverage from the result.
#[test]
fn provisional_result_carries_contain_coverage() {
    let r = ExecuteResult::provisional(
        "recoverable".to_string(),
        "handle123".to_string(),
        Coverage::contain(),
        Some(0),
        None,
        None,
    );
    match &r.exec {
        ExecOutcome::Provisional {
            coverage, handle, ..
        } => {
            assert_eq!(handle, "handle123");
            assert!(coverage.not_checked.iter().any(|s| s.contains("invert")));
        }
        other => panic!("expected Provisional, got {:?}", other),
    }
}
