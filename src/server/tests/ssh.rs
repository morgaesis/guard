use crate::server::deterministic_safe_allow_reason;
use crate::server::execute::execute_command;
use crate::server::wire::{CallerIdentity, ExecuteRequest, SshHostKeyMode};
use guard::gating::ssh_readonly::{
    is_fixed_readonly_diagnostic, ssh_o_directive_readonly_safe, ssh_options_all_readonly_safe,
};
use guard::gating::verb::VerbCatalog;
use guard::principal::PrincipalKey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{args, make_test_config};

#[test]
fn safe_allow_accepts_fixed_ssh_diagnostic() {
    let (cfg, _buf) = make_test_config();
    let reason = deterministic_safe_allow_reason(&cfg, "ssh", &args(&["host01", "id"]));
    assert!(reason.is_some(), "fixed ssh diagnostic should be allowed");
}

#[test]
fn safe_allow_accepts_vetted_option_before_remote_command() {
    let (cfg, _buf) = make_test_config();
    let reason = deterministic_safe_allow_reason(
        &cfg,
        "ssh",
        &args(&["host01", "-o", "ConnectTimeout=5", "id"]),
    );
    assert!(
        reason.is_some(),
        "vetted option should stay in the SSH option zone"
    );
}

#[tokio::test]
async fn explicit_access_overlay_leaves_unmatched_fixed_ssh_on_baseline_policy() {
    let (mut cfg, _buf) = make_test_config();
    cfg.config.dry_run = true;
    cfg.state.verbs = Arc::new(RwLock::new(
        VerbCatalog::from_yaml(
            r#"
verbs:
  - name: approved-local-check
    binary: true
    args: ["--approved"]
    baseline: false
    consequence: reversible
    trusted: true
"#,
        )
        .unwrap(),
    ));
    {
        let mut sessions = cfg.state.sessions.write().await;
        assert!(sessions.grant_policy_only_access_overlay(
            "ssh-access-overlay".to_string(),
            PrincipalKey::from_uid(1001),
            "approved local check".to_string(),
            guard::env::now_unix().saturating_add(60),
        ));
        assert_eq!(
            sessions.apply_delta(
                "ssh-access-overlay",
                &crate::grant_profile::GrantRequestDelta {
                    activated_verbs: vec!["approved-local-check".to_string()],
                    ..Default::default()
                },
            ),
            Some(true)
        );
        assert_eq!(
            sessions.install_access_grant(
                "ssh-access-overlay",
                Some(1),
                "approved-ssh-regression".to_string(),
                vec!["approved-local-check".to_string()],
            ),
            Some(true)
        );
    }
    let caller = CallerIdentity::Unix { uid: 1001 };

    let baseline = execute_command(ssh_request(None, &["host01", "id"]), &cfg, &caller)
        .await
        .into_response();
    assert!(baseline.allowed, "baseline SSH diagnostic: {baseline:?}");

    let mut explicit_request = ssh_request(None, &["host01", "id"]);
    explicit_request.session_token = Some("ssh-access-overlay".to_string());
    let explicit = execute_command(explicit_request, &cfg, &caller)
        .await
        .into_response();
    assert!(
        explicit.allowed,
        "an unmatched access overlay must not narrow fixed SSH: {explicit:?}"
    );
    assert_eq!(explicit.reason, baseline.reason);
    assert!(!explicit.reason.contains("session policy-only mode"));
    assert_eq!(
        cfg.state
            .sessions
            .read()
            .await
            .aggregate_access_uses("ssh-access-overlay")
            .flatten(),
        Some(1),
        "an unmatched SSH command must not consume approved access authority"
    );
}

fn ssh_request(mode: Option<SshHostKeyMode>, argv: &[&str]) -> ExecuteRequest {
    ExecuteRequest {
        binary: "ssh".to_string(),
        args: args(argv),
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        secret_files: HashMap::new(),
        stream: false,
        session_token: None,
        revert: None,
        confirm_within_secs: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
        reevaluate: false,
        ssh_hostkey: mode,
        cwd: None,
    }
}

#[test]
fn apply_ssh_hostkey_injects_options_by_mode() {
    // OnlyExisting / absent: no change, ssh keeps its strict default.
    for mode in [None, Some(SshHostKeyMode::OnlyExisting)] {
        let mut req = ssh_request(mode, &["host01", "id"]);
        req.apply_ssh_hostkey_options();
        assert_eq!(req.args, args(&["host01", "id"]), "mode {mode:?}");
    }

    // AcceptNew prepends accept-new + UpdateHostKeys ahead of the host.
    let mut req = ssh_request(Some(SshHostKeyMode::AcceptNew), &["host01", "id"]);
    req.apply_ssh_hostkey_options();
    assert_eq!(
        req.args,
        args(&[
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "UpdateHostKeys=yes",
            "host01",
            "id",
        ])
    );

    // AcceptAll gives up host verification.
    let mut req = ssh_request(Some(SshHostKeyMode::AcceptAll), &["host01", "id"]);
    req.apply_ssh_hostkey_options();
    assert_eq!(
        req.args,
        args(&[
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "host01",
            "id",
        ])
    );
}

#[test]
fn apply_ssh_hostkey_is_noop_for_non_ssh() {
    let mut req = ssh_request(Some(SshHostKeyMode::AcceptAll), &["get", "pods"]);
    req.binary = "kubectl".to_string();
    req.apply_ssh_hostkey_options();
    assert_eq!(req.args, args(&["get", "pods"]));
}

#[test]
fn accept_new_hostkey_keeps_fixed_diagnostic_on_fast_path() {
    // The options accept-new injects are allow-listed, so a fixed
    // diagnostic still qualifies for the deterministic fast path.
    let (cfg, _buf) = make_test_config();
    let mut req = ssh_request(Some(SshHostKeyMode::AcceptNew), &["host01", "id"]);
    req.apply_ssh_hostkey_options();
    assert!(deterministic_safe_allow_reason(&cfg, "ssh", &req.args).is_some());
}

#[test]
fn accept_all_hostkey_forfeits_fast_path() {
    // accept-all injects StrictHostKeyChecking=no, which the option
    // allow-list rejects, so even a fixed diagnostic forfeits to the
    // evaluator rather than auto-allowing over an unauthenticated channel.
    let (cfg, _buf) = make_test_config();
    let mut req = ssh_request(Some(SshHostKeyMode::AcceptAll), &["host01", "id"]);
    req.apply_ssh_hostkey_options();
    assert!(deterministic_safe_allow_reason(&cfg, "ssh", &req.args).is_none());
}

#[test]
fn safe_allow_rejects_ssh_arbitrary_remote_command() {
    let (cfg, _buf) = make_test_config();
    assert!(
        deterministic_safe_allow_reason(&cfg, "ssh", &args(&["host01", "rm", "-rf", "/"]))
            .is_none()
    );
}

#[test]
fn safe_allow_rejects_ssh_chained_remote_command() {
    let (cfg, _buf) = make_test_config();
    assert!(
        deterministic_safe_allow_reason(&cfg, "ssh", &args(&["host01", "id; rm -rf /"])).is_none()
    );
}

#[test]
fn ssh_options_allow_list_permits_only_vetted_options() {
    // Options a read-only diagnostic may legitimately carry, in both the
    // separate-value and concatenated forms.
    for ok in [
        &["host01", "id"][..],
        &["-4", "host01", "id"][..],
        &["-6", "-C", "-q", "host01", "id"][..],
        &["-v", "host01", "id"][..],
        &["-vvv", "host01", "id"][..],
        &["-T", "-a", "-x", "-k", "host01", "id"][..],
        &["-p", "2222", "host01", "id"][..],
        &["-p2222", "host01", "id"][..],
        &["-l", "root", "host01", "id"][..],
        &["-lroot", "host01", "id"][..],
        &["-o", "ConnectTimeout=5", "host01", "id"][..],
        &["-o", "BatchMode=yes", "host01", "id"][..],
        &["-oConnectTimeout=5", "host01", "id"][..],
        &["--", "host01", "id"][..],
        &["host01", "--", "id"][..],
        // Host-key handling injected by the --hostkey mode must not
        // knock the diagnostic off the fast path.
        &[
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "UpdateHostKeys=yes",
            "host01",
            "id",
        ][..],
        // OpenSSH accepts vetted options between the destination and remote
        // command, so this form shares the same fast path as pre-destination
        // options.
        &["host01", "-o", "ConnectTimeout=5", "-oBatchMode=yes", "id"][..],
    ] {
        assert!(
            ssh_options_all_readonly_safe(&args(ok)),
            "options should be allow-listed: {ok:?}"
        );
    }

    // Every unvetted option forfeits the fast path. This covers the
    // classes an allow-list must reject: forwarding, proxy/jump, tunnel,
    // external config (-F) and PKCS#11 module (-I), identity/log/socket
    // files, and any -o directive outside the vetted keyword set.
    for bad in [
        &["-A", "host01", "id"][..],
        &["-X", "host01", "id"][..],
        &["-Y", "host01", "id"][..],
        &["-L", "8080:localhost:80", "host01", "id"][..],
        &["-R", "9000:localhost:22", "host01", "id"][..],
        &["-D", "1080", "host01", "id"][..],
        &["-W", "host:22", "host01", "id"][..],
        &["-J", "jump", "host01", "id"][..],
        &["-F", "/tmp/evil_ssh_config", "host01", "id"][..],
        &["-I", "/tmp/pkcs11.so", "host01", "id"][..],
        &["-E", "/tmp/log", "host01", "id"][..],
        &["-i", "/tmp/key", "host01", "id"][..],
        &["-S", "/tmp/ctl.sock", "host01", "id"][..],
        &["-o", "ProxyCommand=nc x 22", "host01", "id"][..],
        &["-oProxyJump=jump", "host01", "id"][..],
        &["-o", "LocalCommand=touch /tmp/x", "host01", "id"][..],
        &["-o", "RemoteCommand=cat /etc/shadow", "host01", "id"][..],
        &["-o", "PermitLocalCommand=yes", "host01", "id"][..],
        &["-o", "Include=/tmp/evil", "host01", "id"][..],
        // Combined short flags are not decomposed; forfeit conservatively.
        &["-Cq", "host01", "id"][..],
        // A value option with no following value is malformed; forfeit.
        &["-p"][..],
        &["host01", "-l"][..],
    ] {
        assert!(
            !ssh_options_all_readonly_safe(&args(bad)),
            "option should forfeit the fast path: {bad:?}"
        );
    }
}

#[test]
fn ssh_options_reject_dangerous_option_between_host_and_command() {
    // ssh honors options placed between the destination and the remote
    // command (confirmed against `ssh -G`), so the allow-list must scan
    // past the destination up to the command token. A proxy/forward/jump
    // in that position must forfeit the fast path.
    for bad in [
        &["host01", "-o", "ProxyCommand=nc x 22", "id"][..],
        &["host01", "-L", "8080:localhost:80", "id"][..],
        &["host01", "-J", "jump", "id"][..],
        &["host01", "-oProxyJump=jump", "id"][..],
        &["host01", "-F", "/tmp/evil_ssh_config", "id"][..],
    ] {
        assert!(
            !ssh_options_all_readonly_safe(&args(bad)),
            "option between host and command must forfeit: {bad:?}"
        );
    }
    // An option that appears *after* the command token is a command
    // argument, not an ssh option, and ssh does not re-parse it; it does
    // not affect the fast-path decision for the (fixed) command itself.
    assert!(ssh_options_all_readonly_safe(&args(&[
        "host01",
        "id",
        "-o",
        "ProxyCommand=nc x 22"
    ])));
}

#[test]
fn safe_allow_rejects_post_command_dash_arguments() {
    let (cfg, _buf) = make_test_config();
    for command in [&["host01", "id", "-u"][..], &["host01", "id", "--foo"][..]] {
        assert!(
            deterministic_safe_allow_reason(&cfg, "ssh", &args(command)).is_none(),
            "post-command argument must be part of the remote command: {command:?}"
        );
    }
}

#[test]
fn ssh_option_terminator_preserves_remote_command_boundary() {
    let (cfg, _buf) = make_test_config();
    assert!(deterministic_safe_allow_reason(&cfg, "ssh", &args(&["--", "host01", "id"])).is_some());
    assert!(deterministic_safe_allow_reason(&cfg, "ssh", &args(&["host01", "--", "id"])).is_some());

    // After the terminator, a dash-prefixed token is the remote command, not
    // a local option. It cannot match the fixed read-only command allow-list.
    assert!(deterministic_safe_allow_reason(
        &cfg,
        "ssh",
        &args(&["host01", "--", "-remote-tool", "--flag"])
    )
    .is_none());
}

#[test]
fn ssh_o_directive_rejects_newline_smuggled_second_directive() {
    // A single -o value carrying a second directive on a later line must
    // be rejected outright rather than inspected only up to its first
    // keyword.
    assert!(!ssh_o_directive_readonly_safe(
        "ConnectTimeout=5\nProxyCommand=nc attacker 22"
    ));
    assert!(!ssh_o_directive_readonly_safe(
        "BatchMode=yes\rLocalCommand=touch /tmp/x"
    ));
    assert!(!ssh_options_all_readonly_safe(&args(&[
        "-o",
        "ConnectTimeout=5\nProxyCommand=nc x 22",
        "host01",
        "id"
    ])));
    // The same keyword without a newline stays on the fast path.
    assert!(ssh_o_directive_readonly_safe("ConnectTimeout=5"));
}

#[test]
fn ssh_o_stricthostkeychecking_permits_only_secure_values() {
    // Security-preserving values keep the fast path (accept-new is what
    // the --hostkey mode injects).
    assert!(ssh_o_directive_readonly_safe("StrictHostKeyChecking=yes"));
    assert!(ssh_o_directive_readonly_safe(
        "StrictHostKeyChecking=accept-new"
    ));
    // Disabling or deferring host-key verification forfeits to the
    // evaluator rather than auto-allowing over an unauthenticated channel.
    for weak in [
        "StrictHostKeyChecking=no",
        "StrictHostKeyChecking=off",
        "StrictHostKeyChecking=ask",
        "stricthostkeychecking no",
    ] {
        assert!(
            !ssh_o_directive_readonly_safe(weak),
            "{weak} should forfeit the fast path"
        );
    }
    // And the whole invocation forfeits when the caller disables it.
    let (cfg, _buf) = make_test_config();
    assert!(deterministic_safe_allow_reason(
        &cfg,
        "ssh",
        &args(&["-o", "StrictHostKeyChecking=no", "host01", "id"])
    )
    .is_none());
}

#[test]
fn safe_allow_rejects_ssh_forwarding_and_proxy() {
    let (cfg, _buf) = make_test_config();
    for reject in [
        &["-L", "8080:localhost:80", "host01", "id"][..],
        &["-A", "host01", "id"][..],
        &["-o", "ProxyCommand=nc x 22", "host01", "id"][..],
        &["-oProxyJump=jump", "host01", "id"][..],
        &["-F", "/tmp/evil_ssh_config", "host01", "id"][..],
    ] {
        assert!(
            deterministic_safe_allow_reason(&cfg, "ssh", &args(reject)).is_none(),
            "ssh with {reject:?} must not take the fast path"
        );
    }
    // A benign, vetted option still allows the fixed diagnostic.
    assert!(deterministic_safe_allow_reason(
        &cfg,
        "ssh",
        &args(&["-o", "ConnectTimeout=5", "host01", "id"])
    )
    .is_some());
}

#[test]
fn is_fixed_readonly_diagnostic_is_narrow() {
    assert!(is_fixed_readonly_diagnostic("id"));
    assert!(is_fixed_readonly_diagnostic("uname -a"));
    assert!(is_fixed_readonly_diagnostic("df -h"));
    assert!(!is_fixed_readonly_diagnostic("id && rm -rf /"));
    assert!(!is_fixed_readonly_diagnostic("cat /etc/shadow"));
    assert!(!is_fixed_readonly_diagnostic("uname -a; whoami"));
    assert!(!is_fixed_readonly_diagnostic(""));
}
