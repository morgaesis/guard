#[cfg(unix)]
use crate::session::SessionDecision;
#[cfg(unix)]
use anyhow::{bail, Context, Result};
use guard::gating::read_grant::ReadGrant;
#[cfg(unix)]
use guard::gating::read_grant::{
    ancestor_dirs_within, clamp_ttl, credential_path_deny_reason, AclEntry, ReadGrantStatus,
};
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use tokio::process::Command;

#[cfg(unix)]
use super::execute::{resolve_exec_caller_context, AUTO_READ_GRANT_TTL_SECS};
#[cfg(unix)]
use super::gate_runtime::{new_handle, now_unix};
#[cfg(unix)]
use super::wire::{CallerIdentity, ExecuteResult};
use super::ServerContext;

/// Label used for the binary field of a read-grant request's audit records, so
/// `[AUDIT] ALLOWED`/`DENIED` grep patterns and session allow/deny globs match a
/// read grant under a stable name. Kept as `grant-read` so an operator session
/// grant that allow-lists this shape keeps matching the transparent path.
#[cfg(unix)]
const AUTO_READ_GRANT_LABEL: &str = "grant-read";

#[cfg(unix)]
fn grant_read_audit_args(path: &str, ttl: u64) -> Vec<String> {
    vec![path.to_string(), "--ttl".to_string(), ttl.to_string()]
}

/// Issue a scoped, time-boxed POSIX ACL read grant, routed through the same
/// policy pipeline as any brokered command: a hard credential deny-list first
/// (before the evaluator ever sees it), then session allow/deny globs, then the
/// LLM evaluator. On allow, the ACL entries are applied and an expiry is armed.
#[cfg(unix)]
pub(super) async fn handle_grant_read(
    server: &ServerContext,
    caller: &CallerIdentity,
    path: String,
    session_token: Option<String>,
) -> ExecuteResult {
    let ttl = clamp_ttl(AUTO_READ_GRANT_TTL_SECS);

    // A read grant applies an ACL for a kernel-verified local uid; only a local
    // Unix peer carries one.
    let caller_uid = match caller {
        CallerIdentity::Unix { uid } => *uid,
        _ => {
            let reason = "read grants require a local Unix socket caller".to_string();
            server.audit_deny(
                caller,
                session_token.as_deref(),
                AUTO_READ_GRANT_LABEL,
                &grant_read_audit_args(&path, ttl),
                &reason,
            );
            return ExecuteResult::denied(reason);
        }
    };

    // Canonicalize first: resolve symlinks and `..` so the deny-list and the
    // home-boundary check reason about the real target, not a path that only
    // textually sits under a home directory.
    let canonical = match std::fs::canonicalize(&path) {
        Ok(p) => p,
        Err(e) => {
            let reason = format!("read-grant denied: cannot resolve '{path}': {e}");
            server.audit_deny(
                caller,
                session_token.as_deref(),
                AUTO_READ_GRANT_LABEL,
                &grant_read_audit_args(&path, ttl),
                &reason,
            );
            return ExecuteResult::denied(reason);
        }
    };
    let canonical_str = canonical.display().to_string();
    let audit_args = grant_read_audit_args(&canonical_str, ttl);

    // 1. Hard static credential deny-list, BEFORE the evaluator.
    if let Some(reason) = credential_path_deny_reason(&canonical_str) {
        server.audit_deny(
            caller,
            session_token.as_deref(),
            AUTO_READ_GRANT_LABEL,
            &audit_args,
            &reason,
        );
        return ExecuteResult::denied(reason);
    }

    // 2. Session allow/deny globs short-circuit, exactly as for a command: a
    // deny wins before the evaluator; an allow skips it.
    let mut allow_reason: Option<String> = None;
    if let Some(ref token) = session_token {
        let (decision, exists, static_only) = {
            let reg = server.state.sessions.read().await;
            (
                reg.check(token, AUTO_READ_GRANT_LABEL, &audit_args, None),
                reg.has(token),
                reg.static_only_for(token),
            )
        };
        if !exists {
            let reason =
                format!("unknown session token: '{token}' is revoked, expired, or never existed");
            server.audit_deny(
                caller,
                session_token.as_deref(),
                AUTO_READ_GRANT_LABEL,
                &audit_args,
                &reason,
            );
            return ExecuteResult::denied(reason);
        }
        match decision {
            Some((SessionDecision::Deny, reason)) => {
                server.audit_deny(
                    caller,
                    session_token.as_deref(),
                    AUTO_READ_GRANT_LABEL,
                    &audit_args,
                    &reason,
                );
                return ExecuteResult::denied(reason);
            }
            Some((SessionDecision::Allow, reason)) => allow_reason = Some(reason),
            None if static_only => {
                let reason =
                    "session policy-only mode: read is outside active verb coverage".to_string();
                server.audit_deny(
                    caller,
                    session_token.as_deref(),
                    AUTO_READ_GRANT_LABEL,
                    &audit_args,
                    &reason,
                );
                return ExecuteResult::denied(reason);
            }
            None => {}
        }
    }

    // 3. LLM evaluator, when no session allow already settled it. Same
    // `evaluate_with_reevaluate` call the command pipeline uses; the request is
    // phrased naturally and given assessment context so the model has real
    // signal about what reading this path means.
    if allow_reason.is_none() {
        let session_prompt = match session_token.as_deref() {
            Some(token) => server.state.sessions.read().await.prompt_append_for(token),
            None => None,
        };
        let command_line = format!(
            "grant guard's brokering service account scoped read access to the file {canonical_str} for {ttl} seconds"
        );
        let context = format!(
            "READ-GRANT ASSESSMENT. A brokered caller is asking guard to add a scoped, \
             time-boxed POSIX ACL read grant for its own low-privilege service account on \
             the single file below, so a brokered ansible/helm command can read an operator \
             config/vars/values file. The grant auto-revokes after the TTL; it is not a \
             command execution and touches no other path.\n\
             Target file: {canonical_str}\n\
             TTL: {ttl} seconds\n\
             APPROVE if this is an ordinary configuration/vars/values file the operator would \
             let a brokered tool read. DENY if the path looks like it exposes credentials, \
             private keys, tokens, or other secrets."
        );
        let prompt_append = match session_prompt {
            Some(sp) if !sp.trim().is_empty() => format!("{context}\n\n{sp}"),
            _ => context,
        };
        match server
            .state
            .evaluator
            .evaluate_with_reevaluate(&command_line, Some(&prompt_append), false)
            .await
        {
            guard::evaluate::EvalResult::Allow { reason, .. } => allow_reason = Some(reason),
            guard::evaluate::EvalResult::Deny { reason, .. } => {
                server.audit_deny(
                    caller,
                    session_token.as_deref(),
                    AUTO_READ_GRANT_LABEL,
                    &audit_args,
                    &reason,
                );
                return ExecuteResult::denied(reason);
            }
            guard::evaluate::EvalResult::Error(e) => {
                let reason = format!("evaluation error: {e}");
                server.audit_deny(
                    caller,
                    session_token.as_deref(),
                    AUTO_READ_GRANT_LABEL,
                    &audit_args,
                    &reason,
                );
                return ExecuteResult::denied(reason);
            }
        }
    }
    let reason = allow_reason.unwrap_or_default();

    // One ALLOWED record for the whole grant flow, emitted BEFORE anything
    // acts on the decision. If it cannot be made durable, fail closed.
    if !server.audit_allow(
        caller,
        session_token.as_deref(),
        AUTO_READ_GRANT_LABEL,
        &audit_args,
        &reason,
    ) {
        return ExecuteResult::denied(super::AUDIT_UNAVAILABLE_REASON);
    }

    if server.config.dry_run {
        return ExecuteResult::completed(
            reason,
            Some(0),
            Some(format!(
                "[DRY-RUN] would grant read on {canonical_str} for {ttl}s\n"
            )),
            None,
        );
    }

    // 4. Determine the grantee: guard's own service account by default, or the
    // caller's uid under --exec-as-caller (where brokered children run as the
    // caller, not the daemon).
    let grantee_uid = if server.config.exec_as_caller {
        caller_uid
    } else {
        server.config.daemon_uid
    };
    let grantee_gid = match resolve_exec_caller_context(grantee_uid) {
        Ok(ctx) => ctx.gid,
        Err(e) => {
            let reason = format!("grantee uid {grantee_uid} could not be resolved: {e}");
            return ExecuteResult::exec_failed(reason.clone(), reason);
        }
    };

    // The traverse boundary is the home directory of the file's owner: walk no
    // higher than it so a grant can never add traverse ACLs into shared system
    // paths above a home. Fail closed if the target is not under it.
    let home_boundary = match owner_home_boundary(&canonical) {
        Ok(home) => home,
        Err(e) => {
            let reason = format!("read-grant denied: {e}");
            server.audit_deny(
                caller,
                session_token.as_deref(),
                AUTO_READ_GRANT_LABEL,
                &audit_args,
                &reason,
            );
            return ExecuteResult::denied(reason);
        }
    };

    // Plan the entries, commit the grant row, THEN apply the ACLs, so a crash
    // mid-apply leaves a recoverable row the reconciler can revoke rather than a
    // permanently-open grant with no record.
    let planned = match plan_read_grant(&canonical, grantee_uid, grantee_gid, &home_boundary).await
    {
        Ok(planned) => planned,
        Err(e) => {
            let reason = format!("read-grant denied: {e}");
            server.audit_deny(
                caller,
                session_token.as_deref(),
                AUTO_READ_GRANT_LABEL,
                &audit_args,
                &reason,
            );
            return ExecuteResult::denied(reason);
        }
    };

    let now = now_unix();
    let grant = ReadGrant {
        handle: new_handle(),
        principal: caller.principal(),
        granting_session: session_token.clone(),
        target_path: canonical_str.clone(),
        grantee_uid,
        entries: planned.iter().map(|p| p.entry.clone()).collect(),
        reason: reason.clone(),
        created_unix: now,
        expires_unix: now.saturating_add(ttl),
        status: ReadGrantStatus::Active,
        revert_detail: None,
    };
    persist_read_grant(server, &grant).await;

    if let Err(e) = apply_read_grant_entries(grantee_uid, &planned).await {
        // Nothing survived the in-apply rollback, so drop the committed row too.
        delete_read_grant_row(server, &grant.target_path).await;
        let exec_reason = format!("failed to apply read grant: {e}");
        server.log_audit_exec_failed(
            caller,
            session_token.as_deref(),
            AUTO_READ_GRANT_LABEL,
            &audit_args,
            &exec_reason,
        );
        return ExecuteResult::exec_failed(reason, exec_reason);
    }

    let traverse_count = grant.entries.len().saturating_sub(1);
    server.state.read_grants.write().await.insert(grant.clone());

    server.emit_audit_ungated(
        guard::audit::AuditEvent::new(guard::audit::AuditKind::ReadGrantIssued)
            .handle(&grant.handle)
            .caller(caller)
            .session_fingerprint(super::execute::audit_session_fingerprint(
                session_token.as_deref(),
            ))
            .field("path", &grant.target_path)
            .field("grantee_uid", grantee_uid)
            .field("ttl", ttl)
            .field("traverse_grants", traverse_count),
    );

    let stdout = format!(
        "granted read on {} to uid {} for {}s (handle {}); {} ancestor traverse grant(s); auto-revokes at unix {}\n",
        grant.target_path,
        grantee_uid,
        ttl,
        grant.handle,
        traverse_count,
        grant.expires_unix,
    );
    ExecuteResult::completed(reason, Some(0), Some(stdout), None)
}

/// The home directory of the file at `target`'s owner, used as the ceiling for
/// ancestor traverse grants. Canonicalized so a symlinked home compares equal.
#[cfg(unix)]
fn owner_home_boundary(target: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(target).with_context(|| format!("stat {}", target.display()))?;
    let owner_uid = meta.uid();
    let ctx = resolve_exec_caller_context(owner_uid)
        .with_context(|| format!("resolve owner uid {owner_uid}"))?;
    let home = std::fs::canonicalize(&ctx.home_dir).unwrap_or(ctx.home_dir);
    if !target.starts_with(&home) || target == home.as_path() {
        bail!(
            "target {} is not under the owning home directory {}",
            target.display(),
            home.display()
        );
    }
    Ok(home)
}

/// Compute the ACL entries a read grant needs WITHOUT applying them: a `--x`
/// traverse grant on each ancestor directory the grantee cannot already cross,
/// then the `r` read grant on the leaf. Separated from application so the grant
/// row can be committed to the state store before any ACL is touched (mirroring
/// the provisional "commit before the forward command runs" pattern), so a crash
/// mid-apply always leaves a recoverable row rather than a leaked grant.
#[cfg(unix)]
pub(super) async fn plan_read_grant(
    target: &Path,
    grantee_uid: u32,
    grantee_gid: u32,
    home_boundary: &Path,
) -> Result<Vec<PlannedAclEntry>> {
    use std::os::unix::fs::MetadataExt;
    let ancestors = ancestor_dirs_within(target, home_boundary).ok_or_else(|| {
        anyhow::anyhow!(
            "target {} is not under the owning home directory {}",
            target.display(),
            home_boundary.display()
        )
    })?;
    // A regular file open requires `--x` (traverse) on every ancestor directory,
    // so plan it only where the grantee cannot already cross, from the leaf's
    // parent up to the home boundary.
    let mut entries = Vec::new();
    for dir in &ancestors {
        let meta = std::fs::metadata(dir).with_context(|| format!("stat {}", dir.display()))?;
        if dir_allows_traverse(&meta, dir, grantee_uid, grantee_gid).await {
            continue;
        }
        entries.push(PlannedAclEntry {
            entry: AclEntry {
                path: dir.display().to_string(),
                perms: "x".to_string(),
            },
            dev: meta.dev(),
            ino: meta.ino(),
        });
    }
    let target_meta =
        std::fs::metadata(target).with_context(|| format!("stat {}", target.display()))?;
    // An ACL binds to the inode, and every hard link is another name for it: a
    // grant vetted under one benign name must not open a credential file
    // linked to the same inode elsewhere.
    if target_meta.is_file() && target_meta.nlink() > 1 {
        anyhow::bail!(
            "target {} has {} hard links; the same inode is reachable under other names",
            target.display(),
            target_meta.nlink()
        );
    }
    entries.push(PlannedAclEntry {
        entry: AclEntry {
            path: target.display().to_string(),
            perms: "r".to_string(),
        },
        dev: target_meta.dev(),
        ino: target_meta.ino(),
    });
    Ok(entries)
}

/// A planned ACL entry pinned to the inode that was vetted. `dev`/`ino` are
/// captured in the same pass as the policy checks and re-verified at apply
/// time, so a path component swapped for a symlink between evaluation and
/// apply cannot redirect the setfacl to a different file. On Linux the apply
/// addresses the pinned descriptor through `/proc/self/fd` for a fully
/// TOCTOU-closed apply; other unix (where the POSIX-ACL `setfacl`/`getfacl`
/// tools are not present anyway) re-verify the inode by `fstat` and apply by
/// path.
#[cfg(unix)]
#[derive(Debug)]
pub(super) struct PlannedAclEntry {
    entry: AclEntry,
    dev: u64,
    ino: u64,
}

/// Open `path` and verify it is still the exact inode that was vetted, using
/// `O_NOFOLLOW` so a final-component symlink swap is rejected outright.
/// Returns the open handle (which pins the inode) on a match.
#[cfg(unix)]
fn open_verified_inode(planned: &PlannedAclEntry, flags: libc::c_int) -> Result<std::fs::File> {
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::MetadataExt;
    let cpath = std::ffi::CString::new(planned.entry.path.as_bytes())
        .context("planned path contains a NUL byte")?;
    let fd = unsafe { libc::open(cpath.as_ptr(), flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("open {}", planned.entry.path));
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let meta = file
        .metadata()
        .with_context(|| format!("fstat {}", planned.entry.path))?;
    if meta.dev() != planned.dev || meta.ino() != planned.ino {
        anyhow::bail!(
            "{} changed between policy evaluation and apply (vetted inode {}:{}, found {}:{}); grant aborted",
            planned.entry.path,
            planned.dev,
            planned.ino,
            meta.dev(),
            meta.ino()
        );
    }
    Ok(file)
}

/// The daemon-side procfs path naming an open descriptor. Spawned setfacl
/// children resolve it through the daemon's fd table (same uid), reaching the
/// pinned inode regardless of what the original path now points at.
#[cfg(target_os = "linux")]
fn proc_fd_path(file: &std::fs::File) -> PathBuf {
    use std::os::fd::AsRawFd;
    PathBuf::from(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        file.as_raw_fd()
    ))
}

/// Apply a planned set of ACL entries on Linux, each addressed through a
/// verified `/proc/self/fd` descriptor so the setfacl lands on exactly the
/// vetted inode. Rolls back everything it applied on a partial failure so a
/// failed grant never leaves stray ACL entries behind.
#[cfg(target_os = "linux")]
pub(super) async fn apply_read_grant_entries(
    grantee_uid: u32,
    entries: &[PlannedAclEntry],
) -> Result<()> {
    // O_PATH is a Linux extension: a handle that pins the inode without needing
    // read permission on it. Applied descriptors stay open for the whole apply
    // so a rollback removes the entries from the same inodes they were added to.
    let mut applied: Vec<std::fs::File> = Vec::new();
    for planned in entries {
        let pinned = match open_verified_inode(planned, libc::O_PATH) {
            Ok(f) => f,
            Err(e) => {
                for done in &applied {
                    let _ = setfacl_remove(grantee_uid, &proc_fd_path(done)).await;
                }
                return Err(e);
            }
        };
        let spec = format!("u:{grantee_uid}:{}", planned.entry.perms);
        if let Err(e) = setfacl_modify(&spec, &proc_fd_path(&pinned)).await {
            for done in &applied {
                let _ = setfacl_remove(grantee_uid, &proc_fd_path(done)).await;
            }
            return Err(e).with_context(|| {
                format!("grant {} on {}", planned.entry.perms, planned.entry.path)
            });
        }
        applied.push(pinned);
    }
    Ok(())
}

/// Apply a planned set of ACL entries on non-Linux unix. There is no `O_PATH`
/// or `/proc/self/fd` here, so the inode is re-verified by `fstat` (with
/// `O_NOFOLLOW` rejecting a final-component symlink) and setfacl is then
/// applied by path. This is best-effort: the POSIX-ACL tools this relies on
/// are not present on macOS/BSD, so the runtime path fails there regardless;
/// the verification still refuses a swapped inode before spawning anything.
#[cfg(all(unix, not(target_os = "linux")))]
pub(super) async fn apply_read_grant_entries(
    grantee_uid: u32,
    entries: &[PlannedAclEntry],
) -> Result<()> {
    let mut applied: Vec<&PlannedAclEntry> = Vec::new();
    for planned in entries {
        if let Err(e) = open_verified_inode(planned, libc::O_RDONLY) {
            for done in &applied {
                let _ = setfacl_remove(grantee_uid, Path::new(&done.entry.path)).await;
            }
            return Err(e);
        }
        let spec = format!("u:{grantee_uid}:{}", planned.entry.perms);
        if let Err(e) = setfacl_modify(&spec, Path::new(&planned.entry.path)).await {
            for done in &applied {
                let _ = setfacl_remove(grantee_uid, Path::new(&done.entry.path)).await;
            }
            return Err(e).with_context(|| {
                format!("grant {} on {}", planned.entry.perms, planned.entry.path)
            });
        }
        applied.push(planned);
    }
    Ok(())
}

/// Test/convenience wrapper: plan then apply, returning the applied entries.
#[cfg(all(unix, test))]
pub(super) async fn apply_read_grant(
    target: &Path,
    grantee_uid: u32,
    grantee_gid: u32,
    home_boundary: &Path,
) -> Result<Vec<AclEntry>> {
    let planned = plan_read_grant(target, grantee_uid, grantee_gid, home_boundary).await?;
    apply_read_grant_entries(grantee_uid, &planned).await?;
    Ok(planned.into_iter().map(|p| p.entry).collect())
}

/// Whether `uid` (primary group `gid`) can already traverse `dir` without a new
/// ACL entry: via the base `other`/owner/group execute bits, or an existing
/// `user:<uid>:` ACL entry that grants execute. Conservative toward adding: an
/// undetected named-group ACL grant only causes a redundant `--x` entry that is
/// removed on revoke, never a stripped pre-existing permission.
#[cfg(unix)]
async fn dir_allows_traverse(meta: &std::fs::Metadata, dir: &Path, uid: u32, gid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode();
    if mode & 0o001 != 0 {
        return true;
    }
    if meta.uid() == uid && mode & 0o100 != 0 {
        return true;
    }
    if meta.gid() == gid && mode & 0o010 != 0 {
        return true;
    }
    getfacl_user_has_traverse(dir, uid).await
}

/// Parse `getfacl -n` for a `user:<uid>:` entry whose permission triad grants
/// execute. Numeric output (`-n`) avoids name resolution; the owner entry
/// (`user::`) is skipped because the base owner bits are checked separately.
#[cfg(unix)]
pub(super) async fn getfacl_user_has_traverse(dir: &Path, uid: u32) -> bool {
    let output = Command::new("getfacl")
        .arg("-n")
        .arg("--absolute-names")
        .arg("--")
        .arg(dir)
        .output()
        .await;
    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let want = uid.to_string();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(3, ':');
        let (Some(kind), Some(qualifier), Some(perms)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if kind == "user" && qualifier == want {
            // perms triad is r,w,x; execute is the third position.
            if perms.as_bytes().get(2) == Some(&b'x') {
                return true;
            }
        }
    }
    false
}

#[cfg(unix)]
async fn setfacl_modify(spec: &str, path: &Path) -> Result<()> {
    let output = Command::new("setfacl")
        .arg("-m")
        .arg(spec)
        .arg("--")
        .arg(path)
        .output()
        .await
        .context("spawn setfacl")?;
    if !output.status.success() {
        bail!(
            "setfacl -m {} {}: {}",
            spec,
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(unix)]
async fn setfacl_remove(uid: u32, path: &Path) -> Result<()> {
    // A deleted target has no ACL left to remove; treat that as done.
    if !path.exists() {
        return Ok(());
    }
    let output = Command::new("setfacl")
        .arg("-x")
        .arg(format!("u:{uid}"))
        .arg("--")
        .arg(path)
        .output()
        .await
        .context("spawn setfacl")?;
    if !output.status.success() {
        bail!(
            "setfacl -x u:{} {}: {}",
            uid,
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Remove exactly the ACL entries a grant recorded, in reverse order (leaf
/// first, then ancestors) so a directory's traverse grant outlives the leaf read
/// grant during teardown. A per-path failure is collected rather than aborting,
/// so one stuck path does not strand the rest.
#[cfg(unix)]
pub(super) async fn revoke_read_grant_acls(grant: &ReadGrant) -> Result<()> {
    let mut errors = Vec::new();
    for entry in grant.entries.iter().rev() {
        if let Err(e) = setfacl_remove(grant.grantee_uid, Path::new(&entry.path)).await {
            errors.push(format!("{}: {}", entry.path, e));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!("{}", errors.join("; "))
    }
}

/// Run a read grant's revocation and record the outcome. On non-Unix this is a
/// no-op (read grants can only be created on Unix).
pub(super) async fn finish_read_grant_revert(
    server: &ServerContext,
    grant: &ReadGrant,
    source: &str,
) {
    #[cfg(unix)]
    {
        match revoke_read_grant_acls(grant).await {
            Ok(()) => {
                server
                    .state
                    .read_grants
                    .write()
                    .await
                    .set_revoked(&grant.target_path);
                if let Some(updated) = server
                    .state
                    .read_grants
                    .read()
                    .await
                    .get(&grant.target_path)
                {
                    persist_read_grant(server, updated).await;
                }
                server.emit_audit_ungated(
                    guard::audit::AuditEvent::new(guard::audit::AuditKind::ReadGrantRevoked)
                        .handle(&grant.handle)
                        .field("path", &grant.target_path)
                        .field("source", source),
                );
            }
            Err(e) => {
                server
                    .state
                    .read_grants
                    .write()
                    .await
                    .set_revert_failed(&grant.target_path, e.to_string());
                if let Some(updated) = server
                    .state
                    .read_grants
                    .read()
                    .await
                    .get(&grant.target_path)
                {
                    persist_read_grant(server, updated).await;
                }
                server.emit_audit_ungated(
                    guard::audit::AuditEvent::new(guard::audit::AuditKind::ReadGrantRevokeFailed)
                        .handle(&grant.handle)
                        .field("path", &grant.target_path)
                        .field("source", source)
                        .field("detail", e),
                );
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (server, grant, source);
    }
}

pub(super) async fn persist_read_grant(server: &ServerContext, g: &ReadGrant) {
    if let Some(store) = &server.state.session_store {
        if let Err(e) = store.save_read_grant(g.clone()).await {
            tracing::warn!("failed to persist read grant {}: {}", g.target_path, e);
        }
    }
}

pub(super) async fn delete_read_grant_row(server: &ServerContext, target_path: &str) {
    if let Some(store) = &server.state.session_store {
        if let Err(e) = store.delete_read_grant(target_path.to_string()).await {
            tracing::warn!("failed to delete read grant {}: {}", target_path, e);
        }
    }
}
