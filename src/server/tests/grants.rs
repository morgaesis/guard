#[cfg(unix)]
use crate::server::execute::{
    exec_with_read_grant_retry_with_secret_authority, permission_denied_path,
};
#[cfg(unix)]
use crate::server::gate_runtime::now_unix;
#[cfg(unix)]
use crate::server::grants::{
    apply_read_grant, apply_read_grant_entries, finish_read_grant_revert,
    getfacl_user_has_traverse, handle_grant_read, plan_read_grant, revoke_read_grant_acls,
};
#[cfg(unix)]
use crate::server::wire::CallerIdentity;
#[cfg(unix)]
use crate::server::wire::{ExecOutcome, ExecuteRequest};
#[cfg(unix)]
use crate::session::SessionGrant;
#[cfg(unix)]
use guard::gating::read_grant::{ReadGrant, ReadGrantStatus};
#[cfg(unix)]
use guard::principal::PrincipalKey;
#[cfg(unix)]
use std::collections::HashMap;
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use tokio::process::Command;

#[cfg_attr(not(unix), allow(unused_imports))]
use super::make_test_config;

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(unix)]
fn acl_tools_available() -> bool {
    let ok = |bin: &str| {
        std::process::Command::new(bin)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    ok("setfacl") && ok("getfacl")
}

#[cfg(unix)]
async fn getfacl_raw(path: &Path) -> String {
    let out = Command::new("getfacl")
        .arg("-n")
        .arg("--absolute-names")
        .arg("--")
        .arg(path)
        .output()
        .await
        .unwrap();
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Whether a named `user:<uid>:` ACL entry exists on `path` (any perms).
#[cfg(unix)]
async fn getfacl_has_user(path: &Path, uid: u32) -> bool {
    let want = format!("user:{uid}:");
    getfacl_raw(path)
        .await
        .lines()
        .any(|l| l.trim().starts_with(&want))
}

#[cfg(unix)]
#[tokio::test]
async fn grant_read_deny_list_short_circuits_before_evaluator() {
    // The evaluator here is LLM-disabled with no policy, so a request that
    // reached it would be denied with "default-deny". A .vault_pass path is
    // instead denied with the deny-list reason, proving the static check
    // ran before any evaluator involvement.
    let (cfg, _buf) = make_test_config();
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join(".vault_pass");
    std::fs::write(&vault, "secret").unwrap();
    let caller = CallerIdentity::Unix {
        uid: unsafe { libc::geteuid() },
    };
    let result = handle_grant_read(&cfg, &caller, vault.display().to_string(), None).await;
    assert!(!result.policy_allowed());
    assert!(
        result.policy_reason().contains("credential material"),
        "expected deny-list reason, got: {}",
        result.policy_reason()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn grant_read_denies_kubeconfig() {
    let (cfg, _buf) = make_test_config();
    let dir = tempfile::tempdir().unwrap();
    let kube = dir.path().join(".kube");
    std::fs::create_dir_all(&kube).unwrap();
    let config_file = kube.join("config");
    std::fs::write(&config_file, "apiVersion: v1").unwrap();
    let caller = CallerIdentity::Unix {
        uid: unsafe { libc::geteuid() },
    };
    let result = handle_grant_read(&cfg, &caller, config_file.display().to_string(), None).await;
    assert!(!result.policy_allowed());
    assert!(
        result.policy_reason().contains("kube-proxy"),
        "got: {}",
        result.policy_reason()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn read_grant_revert_marks_seeded_grant_revoked() {
    // The kept revocation path operates on the active registry entry and only
    // removes access. It does not depend on a caller token or grant RPC.
    let (cfg, _buf) = make_test_config();
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("values.yaml");
    std::fs::write(&target, "k: v").unwrap();
    let key = std::fs::canonicalize(&target)
        .unwrap()
        .display()
        .to_string();

    // Empty ACL entries keep revocation free of any real setfacl call, so the
    // test does not depend on ACL tooling being installed.
    let now = now_unix();
    cfg.read_grants.write().await.insert(ReadGrant {
        handle: "hA".to_string(),
        principal: Some(PrincipalKey::from_uid(4242)),
        granting_session: Some("session-A".to_string()),
        target_path: key.clone(),
        grantee_uid: 4242,
        entries: Vec::new(),
        reason: "seeded by session A".to_string(),
        created_unix: now,
        expires_unix: now + 300,
        status: ReadGrantStatus::Active,
        revert_detail: None,
    });

    let claimed = cfg
        .read_grants
        .write()
        .await
        .begin_revert(&key)
        .expect("active grant should be claimable for revert");
    finish_read_grant_revert(&cfg, &claimed, "test").await;

    assert_eq!(
        cfg.read_grants.read().await.get(&key).unwrap().status,
        ReadGrantStatus::Revoked,
        "the active grant must be marked revoked"
    );
}

#[cfg(unix)]
#[test]
fn permission_denied_path_understands_common_error_shapes() {
    // coreutils
    assert_eq!(
        permission_denied_path("cat: /home/op/vars.yml: Permission denied").as_deref(),
        Some("/home/op/vars.yml")
    );
    // Python / ansible
    assert_eq!(
        permission_denied_path("[Errno 13] Permission denied: '/home/op/inventory.ini'").as_deref(),
        Some("/home/op/inventory.ini")
    );
    // Go tools (helm etc.)
    assert_eq!(
        permission_denied_path("Error: open /home/op/values.yaml: permission denied").as_deref(),
        Some("/home/op/values.yaml")
    );
    // A denied line with no path, and unrelated failures, yield nothing.
    assert_eq!(permission_denied_path("permission denied"), None);
    assert_eq!(
        permission_denied_path("error: /home/op/vars.yml: no such file"),
        None
    );
}

/// A permission failure naming a path the grant pipeline rejects (here:
/// unresolvable) must surface the command's own failure unchanged - no
/// retry loop, no grant row.
#[cfg(unix)]
#[tokio::test]
async fn read_grant_retry_returns_original_failure_when_grant_denied() {
    let (cfg, _buf) = make_test_config();
    let caller = CallerIdentity::Unix {
        uid: unsafe { libc::geteuid() },
    };
    let request = ExecuteRequest {
        binary: "sh".to_string(),
        args: vec![
            "-c".to_string(),
            "echo \"cat: /definitely/missing/vars.yml: Permission denied\" >&2; exit 1".to_string(),
        ],
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        secret_files: HashMap::new(),
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
    let result = exec_with_read_grant_retry_with_secret_authority(
        request,
        &cfg,
        &caller,
        "test allow".to_string(),
        0,
        false,
        &mut sink,
        None,
    )
    .await;
    match &result.exec {
        ExecOutcome::Completed { exit_code, .. } => assert_eq!(*exit_code, Some(1)),
        other => panic!("expected the original failure, got {other:?}"),
    }
    assert!(
        cfg.read_grants.read().await.list().is_empty(),
        "a denied grant must leave no grant row"
    );
}

/// The full transparent path: a command fails naming a readable-policy
/// file, the read-grant pipeline (session-allowed here) applies a TTL ACL,
/// and the command is retried and succeeds.
#[cfg(unix)]
#[tokio::test]
async fn read_grant_retry_grants_and_reruns_after_permission_denied() {
    if !acl_tools_available() {
        eprintln!("skipping: setfacl/getfacl not available");
        return;
    }
    // The grant walks up to the file owner's home directory, so the target
    // must live under the real home.
    let Some(home) = dirs::home_dir() else {
        eprintln!("skipping: no home directory");
        return;
    };
    let Ok(dir) = tempfile::tempdir_in(&home) else {
        eprintln!("skipping: home directory not writable");
        return;
    };
    let target = dir.path().join("values.yaml");
    std::fs::write(&target, "k: v").unwrap();
    let canonical = std::fs::canonicalize(&target)
        .unwrap()
        .display()
        .to_string();
    let flag = dir.path().join("ran-once");

    let (mut cfg, _buf) = make_test_config();
    // The grantee must resolve to a real account for the ACL to apply.
    cfg.daemon_uid = unsafe { libc::geteuid() };
    // A session allow rule authorizes the grant deterministically, so the
    // test never reaches the (unconfigured) evaluator.
    cfg.sessions.write().await.grant(
        "sess-retry".to_string(),
        SessionGrant {
            allow: vec!["grant-read*".to_string()],
            deny: Vec::new(),
            allow_exact: Vec::new(),
            deny_exact: Vec::new(),
            activated_verbs: Vec::new(),
            override_markers: Vec::new(),
            scope: Default::default(),
            expires_at: None,
            prompt_append: None,
            generated_notes: Vec::new(),
            granted_at: 0,
            static_only: false,
            auto_amend: false,
        },
    );

    let script = format!(
            "if [ -e '{}' ]; then exit 0; else echo \"cat: {}: Permission denied\" >&2; touch '{}'; exit 1; fi",
            flag.display(),
            canonical,
            flag.display()
        );
    let request = ExecuteRequest {
        binary: "sh".to_string(),
        args: vec!["-c".to_string(), script],
        auth_token: None,
        env: HashMap::new(),
        secrets: HashMap::new(),
        secret_files: HashMap::new(),
        stream: false,
        session_token: Some("sess-retry".to_string()),
        revert: None,
        confirm_within_secs: None,
        reevaluate: false,
        ssh_hostkey: None,
        cwd: None,
        require_approval: None,
        wait_approval_secs: None,
        verb: None,
    };
    let caller = CallerIdentity::Unix {
        uid: unsafe { libc::geteuid() },
    };
    let mut sink = tokio::io::sink();
    let result = exec_with_read_grant_retry_with_secret_authority(
        request,
        &cfg,
        &caller,
        "test allow".to_string(),
        0,
        false,
        &mut sink,
        None,
    )
    .await;
    match &result.exec {
        ExecOutcome::Completed { exit_code, .. } => assert_eq!(
            *exit_code,
            Some(0),
            "the retried command must succeed after the grant"
        ),
        other => panic!("expected a completed retry, got {other:?}"),
    }
    let grant = cfg
        .read_grants
        .read()
        .await
        .get(&canonical)
        .cloned()
        .expect("the transparent grant must be recorded");
    assert_eq!(grant.status, ReadGrantStatus::Active);
    assert_eq!(grant.granting_session.as_deref(), Some("sess-retry"));

    // Cleanup: revoke so no ACL outlives the test.
    let cleanup = cfg
        .read_grants
        .write()
        .await
        .begin_revert(&canonical)
        .expect("transparent grant should be claimable for cleanup");
    finish_read_grant_revert(&cfg, &cleanup, "test").await;
}

/// Build a home/pub_dir(0755)/priv_dir(0700)/values.yaml tree and return the
/// paths, so ACL tests can exercise "add traverse only where missing".
#[cfg(unix)]
fn build_grant_tree(home: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let pub_dir = home.join("pub_dir");
    std::fs::create_dir(&pub_dir).unwrap();
    set_mode(&pub_dir, 0o755);
    let priv_dir = pub_dir.join("priv_dir");
    std::fs::create_dir(&priv_dir).unwrap();
    set_mode(&priv_dir, 0o700);
    let target = priv_dir.join("values.yaml");
    std::fs::write(&target, "k: v").unwrap();
    set_mode(&target, 0o600);
    (pub_dir, priv_dir, target)
}

// A uid distinct from the test runner's own, so owner permission bits never
// grant it traverse and the "where missing" logic must add an entry.
#[cfg(unix)]
const TEST_GRANTEE_UID: u32 = 987654;
#[cfg(unix)]
const TEST_GRANTEE_GID: u32 = 987654;

#[cfg(unix)]
#[tokio::test]
async fn apply_read_grant_adds_traverse_only_where_missing_and_only_x() {
    if !acl_tools_available() {
        eprintln!("skipping: setfacl/getfacl not available");
        return;
    }
    let home = tempfile::tempdir().unwrap();
    set_mode(home.path(), 0o755); // world-traversable home: no traverse grant needed here
    let (pub_dir, priv_dir, target) = build_grant_tree(home.path());
    let pub_before = getfacl_raw(&pub_dir).await;

    let entries = apply_read_grant(&target, TEST_GRANTEE_UID, TEST_GRANTEE_GID, home.path())
        .await
        .expect("apply grant");

    // The private dir was 0700, so a traverse grant was added; the
    // world-traversable pub dir and home were skipped. The leaf got read.
    let priv_str = priv_dir.display().to_string();
    let target_str = target.display().to_string();
    let pub_str = pub_dir.display().to_string();
    let home_str = home.path().display().to_string();
    assert!(
        entries.iter().any(|e| e.path == priv_str && e.perms == "x"),
        "priv dir should get an x-only traverse grant: {entries:?}"
    );
    assert!(
        entries
            .iter()
            .any(|e| e.path == target_str && e.perms == "r"),
        "leaf should get an r grant: {entries:?}"
    );
    assert!(
        !entries.iter().any(|e| e.path == pub_str),
        "world-traversable pub dir must NOT get a grant: {entries:?}"
    );
    assert!(
        !entries.iter().any(|e| e.path == home_str),
        "world-traversable home must NOT get a grant: {entries:?}"
    );
    // Every ancestor grant is x-only (never r or w).
    for e in &entries {
        if e.path != target_str {
            assert_eq!(e.perms, "x", "ancestor grant must be x-only: {e:?}");
        }
    }
    // The untouched pub dir's ACL is byte-identical to before.
    assert_eq!(pub_before, getfacl_raw(&pub_dir).await);
    assert!(getfacl_user_has_traverse(&priv_dir, TEST_GRANTEE_UID).await);
}

/// The apply is pinned to the inodes vetted at plan time: swapping the
/// target for a different file between evaluation and apply must abort the
/// grant and roll back any ancestor entries already applied.
#[cfg(unix)]
#[tokio::test]
async fn read_grant_apply_aborts_when_target_swapped_after_plan() {
    if !acl_tools_available() {
        eprintln!("skipping: setfacl/getfacl not available");
        return;
    }
    let home = tempfile::tempdir().unwrap();
    set_mode(home.path(), 0o755);
    let (_pub_dir, priv_dir, target) = build_grant_tree(home.path());

    let planned = plan_read_grant(&target, TEST_GRANTEE_UID, TEST_GRANTEE_GID, home.path())
        .await
        .expect("plan grant");

    // Swap the vetted target for a symlink to a different file: the
    // original inode stays alive under another name so the filesystem
    // cannot recycle its number, and the path now resolves to the "secret".
    let secret = home.path().join("id_rsa");
    std::fs::write(&secret, "PRIVATE KEY").unwrap();
    std::fs::rename(&target, priv_dir.join("orig.yaml")).unwrap();
    std::os::unix::fs::symlink(&secret, &target).unwrap();

    let err = apply_read_grant_entries(TEST_GRANTEE_UID, &planned)
        .await
        .expect_err("apply must refuse the swapped inode");
    assert!(
        err.to_string()
            .contains("changed between policy evaluation"),
        "got: {err:#}"
    );
    assert!(
        !getfacl_user_has_traverse(&priv_dir, TEST_GRANTEE_UID).await,
        "the ancestor traverse entry applied before the abort must be rolled back"
    );
}

/// A multi-hardlink target is refused at plan time: the ACL binds to the
/// inode, which is reachable under every other link name.
#[cfg(unix)]
#[tokio::test]
async fn read_grant_denies_multi_hardlink_target() {
    let home = tempfile::tempdir().unwrap();
    set_mode(home.path(), 0o755);
    let (_pub_dir, priv_dir, target) = build_grant_tree(home.path());
    std::fs::hard_link(&target, priv_dir.join("alias.yaml")).unwrap();

    let err = plan_read_grant(&target, TEST_GRANTEE_UID, TEST_GRANTEE_GID, home.path())
        .await
        .expect_err("multi-hardlink target must be refused");
    assert!(err.to_string().contains("hard links"), "got: {err:#}");
}

#[cfg(unix)]
#[tokio::test]
async fn revoke_removes_exactly_added_entries_and_nothing_else() {
    if !acl_tools_available() {
        eprintln!("skipping: setfacl/getfacl not available");
        return;
    }
    let home = tempfile::tempdir().unwrap();
    set_mode(home.path(), 0o755);
    let (pub_dir, priv_dir, target) = build_grant_tree(home.path());

    // Seed an unrelated pre-existing ACL entry on the private dir; revocation
    // must leave it untouched (proving "removes exactly the added entries and
    // nothing else", which a blanket ACL wipe would violate).
    const OTHER_UID: u32 = 111222;
    let seed = Command::new("setfacl")
        .arg("-m")
        .arg(format!("u:{OTHER_UID}:rx"))
        .arg("--")
        .arg(&priv_dir)
        .output()
        .await
        .unwrap();
    assert!(seed.status.success());
    assert!(getfacl_has_user(&priv_dir, OTHER_UID).await);
    let pub_before = getfacl_raw(&pub_dir).await;

    let entries = apply_read_grant(&target, TEST_GRANTEE_UID, TEST_GRANTEE_GID, home.path())
        .await
        .expect("apply grant");
    assert!(getfacl_has_user(&priv_dir, TEST_GRANTEE_UID).await);

    let grant = ReadGrant {
        handle: "h".to_string(),
        principal: None,
        granting_session: None,
        target_path: target.display().to_string(),
        grantee_uid: TEST_GRANTEE_UID,
        entries,
        reason: "test".to_string(),
        created_unix: 0,
        expires_unix: 0,
        status: ReadGrantStatus::Reverting,
        revert_detail: None,
    };
    revoke_read_grant_acls(&grant).await.expect("revoke");

    // Exactly the granted entry is gone; the pre-existing unrelated entry
    // survives, and the never-touched pub dir is byte-identical.
    assert!(
        !getfacl_has_user(&priv_dir, TEST_GRANTEE_UID).await,
        "granted entry must be removed"
    );
    assert!(
        getfacl_has_user(&priv_dir, OTHER_UID).await,
        "pre-existing unrelated ACL entry must survive revocation"
    );
    assert!(!getfacl_has_user(&target, TEST_GRANTEE_UID).await);
    assert_eq!(pub_before, getfacl_raw(&pub_dir).await);
}

#[cfg(unix)]
#[tokio::test]
async fn expired_read_grant_is_auto_revoked() {
    if !acl_tools_available() {
        eprintln!("skipping: setfacl/getfacl not available");
        return;
    }
    let (cfg, _buf) = make_test_config();
    let home = tempfile::tempdir().unwrap();
    set_mode(home.path(), 0o755);
    let (_pub_dir, priv_dir, target) = build_grant_tree(home.path());

    let entries = apply_read_grant(&target, TEST_GRANTEE_UID, TEST_GRANTEE_GID, home.path())
        .await
        .expect("apply grant");
    assert!(getfacl_user_has_traverse(&priv_dir, TEST_GRANTEE_UID).await);

    let now = now_unix();
    let grant = ReadGrant {
        handle: "h".to_string(),
        principal: None,
        granting_session: None,
        target_path: target.display().to_string(),
        grantee_uid: TEST_GRANTEE_UID,
        entries,
        reason: "test".to_string(),
        created_unix: now,
        expires_unix: now.saturating_sub(1), // already past its TTL
        status: ReadGrantStatus::Active,
        revert_detail: None,
    };
    cfg.read_grants.write().await.insert(grant.clone());

    // The sweeper's due-claim drives the timer: an expired Active grant is
    // taken and then reverted.
    let due = cfg.read_grants.write().await.take_due(now_unix());
    assert_eq!(due.len(), 1);
    finish_read_grant_revert(&cfg, &due[0], "expiry").await;

    assert!(!getfacl_user_has_traverse(&priv_dir, TEST_GRANTEE_UID).await);
    assert_eq!(
        cfg.read_grants
            .read()
            .await
            .get(&grant.target_path)
            .unwrap()
            .status,
        ReadGrantStatus::Revoked
    );
}
