//! Time-boxed POSIX ACL read grants.
//!
//! Commands guard brokers (ansible, helm) routinely read config/vars/values
//! files owned by the operator under the operator's home. guard's dedicated
//! service account (or, under `--exec-as-caller`, the identity that runs a
//! brokered child) cannot read them. A blanket ACL over the whole ops tree would
//! also expose credential files; this primitive instead grants a scoped,
//! auto-expiring read grant on one operator-named file and reverts it on
//! expiry.
//!
//! This module is the pure part: the record, the in-memory registry, the static
//! credential deny-list, TTL bounds, and the ancestor-directory plan. It owns no
//! clock and performs no ACL syscalls; the daemon supplies `now`, runs
//! setfacl/getfacl, and feeds outcomes back. It lives alongside `provisional`
//! and `approval` because it reuses the same deadline-sweep + state-store
//! persistence shape.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use crate::principal::PrincipalKey;

/// Hard ceiling on a read grant's TTL, mirroring the containment envelope's
/// `MAX_CONFIRM_WITHIN_SECS`. A grant is a standing privilege, so it is always
/// bounded even if a caller asks for longer.
pub const MAX_READ_GRANT_TTL_SECS: u64 = 24 * 60 * 60;

/// Lifecycle of a read grant. Unlike a provisional, an expired read grant is
/// always safe to revoke unattended (revocation only removes access), so there
/// is no "needs operator decision" recovery state: startup reconciliation
/// revokes any past-deadline grant outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadGrantStatus {
    /// The ACL entries are in place and the expiry timer is counting down.
    Active,
    /// The sweeper (or an explicit revoke) has claimed this and the ACL removal
    /// is in flight.
    Reverting,
    /// The ACL entries were removed successfully.
    Revoked,
    /// Revocation was attempted but a setfacl call failed; the grant may still
    /// be partly in place, so this stays queryable.
    RevertFailed,
}

impl ReadGrantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reverting => "reverting",
            Self::Revoked => "revoked",
            Self::RevertFailed => "revert_failed",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Revoked)
    }
}

/// One ACL entry guard added, recorded so revocation removes exactly what was
/// added and never strips a pre-existing entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclEntry {
    /// Absolute path the entry was added to.
    pub path: String,
    /// The permission letters granted: `r` for the leaf read grant, `x` for an
    /// ancestor traverse grant.
    pub perms: String,
}

/// One active (or terminal) read grant and the exact ACL entries it added.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadGrant {
    /// Unguessable handle for audit correlation.
    pub handle: String,
    /// Principal of the caller that requested the grant, for audit and scoping.
    #[serde(default)]
    pub principal: Option<PrincipalKey>,
    /// Session token the grant was requested under, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granting_session: Option<String>,
    /// The single caller-named file the grant is for (absolute).
    pub target_path: String,
    /// setfacl user qualifier the grant was issued to: the numeric uid of the
    /// identity that runs brokered children (guard's own uid, or the caller's
    /// uid under `--exec-as-caller`).
    pub grantee_uid: u32,
    /// Every ACL entry added: the leaf read grant plus each ancestor traverse
    /// grant. Revocation removes exactly these.
    pub entries: Vec<AclEntry>,
    /// Short caller-facing rationale for the grant (the policy allow reason).
    pub reason: String,
    pub created_unix: u64,
    /// Auto-revert fires at or after this wall-clock unix-seconds value.
    pub expires_unix: u64,
    pub status: ReadGrantStatus,
    /// Human-readable detail for a failed revocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert_detail: Option<String>,
}

/// In-memory registry of read grants, keyed by target path (a path has at most
/// one active grant; re-granting replaces). Pure: no clock, no I/O.
#[derive(Debug, Default, Clone)]
pub struct GrantReadRegistry {
    items: HashMap<String, ReadGrant>,
}

impl GrantReadRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild from persisted rows at daemon startup. Any row still `Reverting`
    /// (a revocation interrupted by restart) is returned to `Active` so the
    /// sweeper/reconciler will retry its removal; nothing is lost because
    /// re-running setfacl removal is idempotent.
    pub fn from_rows(rows: Vec<ReadGrant>) -> Self {
        let mut items = HashMap::new();
        for mut row in rows {
            if row.status == ReadGrantStatus::Reverting {
                row.status = ReadGrantStatus::Active;
            }
            items.insert(row.target_path.clone(), row);
        }
        Self { items }
    }

    pub fn insert(&mut self, grant: ReadGrant) {
        self.items.insert(grant.target_path.clone(), grant);
    }

    pub fn get(&self, target_path: &str) -> Option<&ReadGrant> {
        self.items.get(target_path)
    }

    pub fn remove(&mut self, target_path: &str) -> Option<ReadGrant> {
        self.items.remove(target_path)
    }

    /// All grants, newest first.
    pub fn list(&self) -> Vec<ReadGrant> {
        let mut v: Vec<_> = self.items.values().cloned().collect();
        v.sort_by(|a, b| {
            b.created_unix
                .cmp(&a.created_unix)
                .then(a.target_path.cmp(&b.target_path))
        });
        v
    }

    /// Claim the path for an explicit early revoke, transitioning `Active` to
    /// `Reverting` and returning the row so the daemon can remove the ACLs.
    pub fn begin_revert(&mut self, target_path: &str) -> Option<ReadGrant> {
        let g = self.items.get_mut(target_path)?;
        if g.status == ReadGrantStatus::Active {
            g.status = ReadGrantStatus::Reverting;
            Some(g.clone())
        } else {
            None
        }
    }

    /// Sweeper tick: claim every `Active` grant whose deadline has passed,
    /// transitioning each to `Reverting`, and return them so the daemon can
    /// remove their ACLs.
    pub fn take_due(&mut self, now: u64) -> Vec<ReadGrant> {
        let due: Vec<String> = self
            .items
            .values()
            .filter(|g| g.status == ReadGrantStatus::Active && now >= g.expires_unix)
            .map(|g| g.target_path.clone())
            .collect();
        let mut taken = Vec::new();
        for path in due {
            if let Some(g) = self.items.get_mut(&path) {
                g.status = ReadGrantStatus::Reverting;
                taken.push(g.clone());
            }
        }
        taken.sort_by(|a, b| a.target_path.cmp(&b.target_path));
        taken
    }

    /// Record a successful revocation.
    pub fn set_revoked(&mut self, target_path: &str) {
        if let Some(g) = self.items.get_mut(target_path) {
            g.status = ReadGrantStatus::Revoked;
            g.revert_detail = None;
        }
    }

    /// Record a failed revocation; the ACL may still be in place, so this stays
    /// queryable rather than being dropped.
    pub fn set_revert_failed(&mut self, target_path: &str, detail: String) {
        if let Some(g) = self.items.get_mut(target_path) {
            g.status = ReadGrantStatus::RevertFailed;
            g.revert_detail = Some(detail);
        }
    }

    /// Drop terminal rows older than `retention_secs` so the table stays
    /// bounded. Non-terminal rows are never pruned.
    pub fn prune_terminal(&mut self, now: u64, retention_secs: u64) -> Vec<String> {
        let drop: Vec<String> = self
            .items
            .values()
            .filter(|g| {
                g.status.is_terminal() && now.saturating_sub(g.created_unix) > retention_secs
            })
            .map(|g| g.target_path.clone())
            .collect();
        for path in &drop {
            self.items.remove(path);
        }
        drop
    }
}

/// Clamp a requested TTL into the always-bounded range `[1, MAX]`.
pub fn clamp_ttl(requested: u64) -> u64 {
    requested.clamp(1, MAX_READ_GRANT_TTL_SECS)
}

/// Static credential deny-list, checked before the evaluator ever sees a grant
/// request. Returns a caller-facing denial reason for a credential-shaped path,
/// or `None` if the path is not obviously sensitive (and so still gets an
/// evaluator look). Classification is by filename and path components so a match
/// fires regardless of directory depth. Fails closed: a non-absolute path, or
/// one whose leaf classification is unknown but sits under a private-key
/// directory, is denied rather than guessed safe.
///
/// Extend this by adding to `DENY_BASENAMES` / `DENY_EXTENSIONS` or the
/// component checks below; it is intentionally a flat list, not a plugin system.
pub fn credential_path_deny_reason(path: &str) -> Option<String> {
    // Exact basenames that are always credential material.
    const DENY_BASENAMES: &[&str] = &[
        ".vault_pass",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        ".netrc",
        ".git-credentials",
        ".npmrc",
        ".pypirc",
        // GCP service-account key / application default credentials: each
        // carries a full private key.
        "credentials.json",
        "application_default_credentials.json",
        // PostgreSQL / MySQL client credential files.
        ".pgpass",
        ".my.cnf",
        // direnv files routinely `export SECRET=...`.
        ".envrc",
    ];
    // Extensions that denote a private key or certificate key material.
    const DENY_EXTENSIONS: &[&str] = &[".pem", ".key"];

    // POSIX-absolute check (leading `/`) rather than `Path::is_absolute`, whose
    // result is platform-dependent; read grants are a POSIX-ACL, Unix-only
    // feature, so the classifier reasons about POSIX paths on any host.
    if !path.starts_with('/') {
        return Some(format!(
            "read-grant denied: '{path}' is not an absolute path (fail-closed)"
        ));
    }

    let components: Vec<String> = Path::new(path)
        .components()
        .filter_map(|c| match c {
            Component::Normal(os) => os.to_str().map(|s| s.to_string()),
            _ => None,
        })
        .collect();
    let Some(basename) = components.last() else {
        return Some(format!("read-grant denied: '{path}' has no file component"));
    };
    let base_lower = basename.to_ascii_lowercase();
    let has_component = |name: &str| components.iter().any(|c| c.eq_ignore_ascii_case(name));

    // guard's kube-proxy manages kubeconfig credential injection on its own,
    // correct path; a read grant on anything under `.kube` is never the right
    // tool and would be a bypass around that path. An embedded-token kubeconfig
    // can live under any filename (`config`, `admin.yaml`, `other-cluster.yaml`),
    // so deny every file directly under `.kube` and fall closed; only the
    // clearly-non-credential discovery/HTTP response caches (`.kube/cache/...`,
    // `.kube/http-cache/...`) are allowed through.
    if let Some(kube_idx) = components
        .iter()
        .position(|c| c.eq_ignore_ascii_case(".kube"))
    {
        let next = components.get(kube_idx + 1).map(|s| s.to_ascii_lowercase());
        let is_safe_cache = matches!(next.as_deref(), Some("cache") | Some("http-cache"));
        if !is_safe_cache {
            return Some(format!(
                "read-grant denied: '{path}' is under .kube (managed by guard's kube-proxy credential path, not by read grants; fail-closed)"
            ));
        }
    }

    // Terraform state commonly embeds plaintext secrets and sensitive outputs.
    if base_lower.ends_with(".tfstate") || base_lower.ends_with(".tfstate.backup") {
        return Some(format!(
            "read-grant denied: '{basename}' is Terraform state (may contain plaintext secrets)"
        ));
    }

    if DENY_BASENAMES
        .iter()
        .any(|d| base_lower == d.to_ascii_lowercase())
    {
        return Some(format!(
            "read-grant denied: '{basename}' is credential material"
        ));
    }

    // .env / .env.<env> hold environment secrets.
    if base_lower == ".env" || base_lower.starts_with(".env.") {
        return Some(format!(
            "read-grant denied: '{basename}' is a dotenv secrets file"
        ));
    }

    // A public key sibling is fine; only the private-key/cert-key forms are
    // denied by extension.
    if !base_lower.ends_with(".pub") && DENY_EXTENSIONS.iter().any(|e| base_lower.ends_with(e)) {
        return Some(format!(
            "read-grant denied: '{basename}' is a private key or cert-key file"
        ));
    }

    // Anything under a GnuPG home is key material.
    if has_component(".gnupg") {
        return Some("read-grant denied: paths under .gnupg are key material".to_string());
    }

    // .aws/credentials, .docker/config.json.
    if has_component(".aws") && base_lower == "credentials" {
        return Some("read-grant denied: .aws/credentials holds cloud credentials".to_string());
    }
    if has_component(".docker") && base_lower == "config.json" {
        return Some(
            "read-grant denied: .docker/config.json holds registry credentials".to_string(),
        );
    }

    // Under an .ssh directory, deny anything that is not one of the known
    // non-secret files. This fails closed: an unrecognized file under .ssh is
    // assumed to be a private key rather than guessed safe.
    if has_component(".ssh") {
        const SSH_PUBLIC_OK: &[&str] =
            &["known_hosts", "known_hosts2", "authorized_keys", "config"];
        let ok = base_lower.ends_with(".pub") || SSH_PUBLIC_OK.iter().any(|f| base_lower == *f);
        if !ok {
            return Some(format!(
                "read-grant denied: '{basename}' under .ssh has a private-key shape (fail-closed)"
            ));
        }
    }

    None
}

/// The ordered list of ancestor directories to consider for traverse grants:
/// from the target's immediate parent up to and including `home_boundary`,
/// nearest-first. Returns `None` (deny, fail-closed) if the target is not
/// strictly under the boundary, so a grant can never add traverse ACLs above a
/// home directory into shared system paths.
pub fn ancestor_dirs_within(target: &Path, home_boundary: &Path) -> Option<Vec<PathBuf>> {
    if !target.starts_with(home_boundary) || target == home_boundary {
        return None;
    }
    let mut dirs = Vec::new();
    let mut cur = target.parent();
    while let Some(dir) = cur {
        dirs.push(dir.to_path_buf());
        if dir == home_boundary {
            break;
        }
        cur = dir.parent();
    }
    // The loop always reaches the boundary because target.starts_with(boundary)
    // and we walk parents; guard against a malformed input regardless.
    if dirs.last().map(|d| d.as_path()) != Some(home_boundary) {
        return None;
    }
    Some(dirs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_list_blocks_vault_pass_anywhere() {
        assert!(credential_path_deny_reason("/home/op/ops/ansible/.vault_pass").is_some());
        assert!(credential_path_deny_reason("/home/op/.vault_pass").is_some());
    }

    #[test]
    fn deny_list_blocks_private_keys_but_allows_pub_siblings() {
        assert!(credential_path_deny_reason("/home/op/.ssh/id_ed25519").is_some());
        assert!(credential_path_deny_reason("/home/op/.ssh/id_rsa").is_some());
        assert!(credential_path_deny_reason("/home/op/certs/server.key").is_some());
        assert!(credential_path_deny_reason("/home/op/certs/server.pem").is_some());
        // Public key siblings are readable.
        assert!(credential_path_deny_reason("/home/op/.ssh/id_ed25519.pub").is_none());
    }

    #[test]
    fn deny_list_blocks_kubeconfig() {
        // The literal `.kube/config`, and any other filename directly under
        // `.kube` (embedded-token kubeconfigs can be named anything).
        assert!(credential_path_deny_reason("/home/op/.kube/config").is_some());
        assert!(credential_path_deny_reason("/home/op/.kube/admin.yaml").is_some());
        assert!(credential_path_deny_reason("/home/op/.kube/other-cluster.yaml").is_some());
        // The non-credential discovery / HTTP response caches are allowed.
        assert!(credential_path_deny_reason(
            "/home/op/.kube/cache/discovery/api.example_6443/v1/serverresources.json"
        )
        .is_none());
        assert!(credential_path_deny_reason("/home/op/.kube/http-cache/abc123def456").is_none());
    }

    #[test]
    fn deny_list_blocks_cloud_and_db_credential_files() {
        // GCP service-account key / application default credentials.
        assert!(credential_path_deny_reason("/home/op/gcp/credentials.json").is_some());
        assert!(credential_path_deny_reason(
            "/home/op/.config/gcloud/application_default_credentials.json"
        )
        .is_some());
        // Database client credential files.
        assert!(credential_path_deny_reason("/home/op/.pgpass").is_some());
        assert!(credential_path_deny_reason("/home/op/.my.cnf").is_some());
        // direnv files export secrets.
        assert!(credential_path_deny_reason("/home/op/project/.envrc").is_some());
    }

    #[test]
    fn deny_list_blocks_terraform_state() {
        assert!(credential_path_deny_reason("/home/op/infra/terraform.tfstate").is_some());
        assert!(credential_path_deny_reason("/home/op/infra/prod.tfstate").is_some());
        assert!(credential_path_deny_reason("/home/op/infra/terraform.tfstate.backup").is_some());
    }

    #[test]
    fn deny_list_blocks_dotenv_and_variants() {
        assert!(credential_path_deny_reason("/home/op/app/.env").is_some());
        assert!(credential_path_deny_reason("/home/op/app/.env.production").is_some());
    }

    #[test]
    fn deny_list_blocks_credential_dirs_and_files() {
        assert!(credential_path_deny_reason("/home/op/.gnupg/secring.gpg").is_some());
        assert!(credential_path_deny_reason("/home/op/.aws/credentials").is_some());
        assert!(credential_path_deny_reason("/home/op/.docker/config.json").is_some());
        assert!(credential_path_deny_reason("/home/op/.git-credentials").is_some());
        assert!(credential_path_deny_reason("/home/op/.netrc").is_some());
    }

    #[test]
    fn deny_list_blocks_unknown_ssh_files_fail_closed() {
        // Not a known-public .ssh file, and no .pub extension: fail closed.
        assert!(credential_path_deny_reason("/home/op/.ssh/deploy_token").is_some());
        // Known non-secret .ssh files are allowed.
        assert!(credential_path_deny_reason("/home/op/.ssh/known_hosts").is_none());
        assert!(credential_path_deny_reason("/home/op/.ssh/config").is_none());
    }

    #[test]
    fn deny_list_rejects_relative_paths() {
        assert!(credential_path_deny_reason("ops/values.yaml").is_some());
        assert!(credential_path_deny_reason("../values.yaml").is_some());
    }

    #[test]
    fn ordinary_config_files_pass_the_deny_list() {
        assert!(credential_path_deny_reason("/home/op/ops/group_vars/all.yaml").is_none());
        assert!(credential_path_deny_reason("/home/op/charts/values.yaml").is_none());
        assert!(credential_path_deny_reason("/home/op/ansible/hosts.ini").is_none());
    }

    #[test]
    fn ancestor_dirs_walk_up_to_boundary_inclusive() {
        let target = Path::new("/home/op/ops/group_vars/all.yaml");
        let boundary = Path::new("/home/op");
        let dirs = ancestor_dirs_within(target, boundary).unwrap();
        assert_eq!(
            dirs,
            vec![
                PathBuf::from("/home/op/ops/group_vars"),
                PathBuf::from("/home/op/ops"),
                PathBuf::from("/home/op"),
            ]
        );
    }

    #[test]
    fn ancestor_dirs_reject_target_outside_boundary() {
        let target = Path::new("/etc/shadow");
        let boundary = Path::new("/home/op");
        assert!(ancestor_dirs_within(target, boundary).is_none());
    }

    #[test]
    fn clamp_ttl_bounds_range() {
        assert_eq!(clamp_ttl(0), 1);
        assert_eq!(clamp_ttl(300), 300);
        assert_eq!(clamp_ttl(u64::MAX), MAX_READ_GRANT_TTL_SECS);
    }

    #[test]
    fn take_due_claims_only_expired_active_grants() {
        let mut reg = GrantReadRegistry::new();
        reg.insert(sample_grant("/a", 100));
        reg.insert(sample_grant("/b", 300));
        let due = reg.take_due(150);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].target_path, "/a");
        assert_eq!(reg.get("/a").unwrap().status, ReadGrantStatus::Reverting);
        assert_eq!(reg.get("/b").unwrap().status, ReadGrantStatus::Active);
    }

    #[test]
    fn from_rows_returns_interrupted_reverts_to_active() {
        let mut g = sample_grant("/a", 100);
        g.status = ReadGrantStatus::Reverting;
        let reg = GrantReadRegistry::from_rows(vec![g]);
        assert_eq!(reg.get("/a").unwrap().status, ReadGrantStatus::Active);
    }

    fn sample_grant(path: &str, expires: u64) -> ReadGrant {
        ReadGrant {
            handle: "h".to_string(),
            principal: None,
            granting_session: None,
            target_path: path.to_string(),
            grantee_uid: 1001,
            entries: vec![AclEntry {
                path: path.to_string(),
                perms: "r".to_string(),
            }],
            reason: "test".to_string(),
            created_unix: 0,
            expires_unix: expires,
            status: ReadGrantStatus::Active,
            revert_detail: None,
        }
    }
}
