//! Candidate detection for repeated low-risk LLM approvals.
//!
//! This module tracks commands the LLM evaluator has approved more than once
//! at low risk and, once a pattern crosses `min_approvals`, returns a
//! `LearningOutcome` the caller (`server::learning::learning_notice`) turns into an
//! operator-facing notice.
//!
//! It deliberately does NOT grant a bypass itself. An agent's own repeated
//! behavior is not a trustworthy signal to grant that same agent a
//! permanent, LLM-skipping allow -- that would let an agent promote itself
//! past the evaluator by simply repeating a borderline-but-approved command,
//! via a second glob matcher with the same "can't parse shell quoting"
//! weakness `PolicyEngine` documents for its own deny-only fast path. Every
//! other deterministic-allow mechanism in this codebase (`guard verb`) is
//! operator-authored or operator-invoked; this one is too. The candidate
//! becomes a real, LLM-skipping rule only when the operator runs `guard verb
//! create --prompt` (the notice text gives the exact command), which goes
//! through the same synthesis safety gate as any other verb.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

use crate::env::now_unix;
use crate::redact::{
    command_contains_sensitive_literals, flattened_command_contains_sensitive_literals,
    redact_output_text,
};

/// Outcome of an atomic learning-file replacement.
///
/// A warning means the destination contains the returned snapshot, but a later
/// durability or cleanup operation failed or the platform cannot independently
/// confirm directory-entry durability. Callers adopt this snapshot before
/// surfacing the warning so memory does not diverge from committed authority.
#[derive(Debug)]
#[cfg_attr(windows, allow(dead_code))]
pub(crate) struct LearningWriteOutcome {
    snapshot: LearningFileSnapshot,
    warning: Option<anyhow::Error>,
}

impl LearningWriteOutcome {
    #[cfg(test)]
    pub(crate) fn committed_snapshot(&self) -> &LearningFileSnapshot {
        &self.snapshot
    }

    #[cfg(test)]
    pub(crate) fn warning(&self) -> Option<&anyhow::Error> {
        self.warning.as_ref()
    }

    pub(crate) fn into_parts(self) -> (LearningFileSnapshot, Option<anyhow::Error>) {
        #[cfg(test)]
        let hook = {
            let mut hooks = post_commit_adoption_hooks()
                .lock()
                .expect("post-commit hook lock");
            let matching = self.snapshot.content().and_then(|content| {
                std::str::from_utf8(content).ok().and_then(|content| {
                    hooks
                        .keys()
                        .find(|needle| content.contains(needle.as_str()))
                        .cloned()
                })
            });
            matching.and_then(|needle| hooks.remove(&needle))
        };
        #[cfg(test)]
        if let Some((committed, release)) = hook {
            committed.wait();
            release.wait();
        }
        (self.snapshot, self.warning)
    }

    #[cfg(test)]
    pub(crate) fn committed_with_warning_for_test(
        snapshot: LearningFileSnapshot,
        warning: anyhow::Error,
    ) -> Self {
        Self {
            snapshot,
            warning: Some(warning),
        }
    }
}

#[cfg(test)]
type PostCommitAdoptionHook = (
    std::sync::Arc<std::sync::Barrier>,
    std::sync::Arc<std::sync::Barrier>,
);

#[cfg(test)]
fn post_commit_adoption_hooks(
) -> &'static std::sync::Mutex<BTreeMap<String, PostCommitAdoptionHook>> {
    static HOOKS: std::sync::OnceLock<std::sync::Mutex<BTreeMap<String, PostCommitAdoptionHook>>> =
        std::sync::OnceLock::new();
    HOOKS.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
pub(crate) fn pause_post_commit_adoption_for_test(
    needle: &str,
) -> (
    std::sync::Arc<std::sync::Barrier>,
    std::sync::Arc<std::sync::Barrier>,
) {
    let committed = std::sync::Arc::new(std::sync::Barrier::new(2));
    let release = std::sync::Arc::new(std::sync::Barrier::new(2));
    post_commit_adoption_hooks()
        .lock()
        .expect("post-commit hook lock")
        .insert(needle.to_string(), (committed.clone(), release.clone()));
    (committed, release)
}

#[cfg(test)]
type ImmutableLockPreopenHook = Box<dyn FnOnce(&Path) + Send>;

#[cfg(test)]
fn immutable_lock_preopen_hooks() -> &'static Mutex<BTreeMap<PathBuf, ImmutableLockPreopenHook>> {
    static HOOKS: OnceLock<Mutex<BTreeMap<PathBuf, ImmutableLockPreopenHook>>> = OnceLock::new();
    HOOKS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
pub(crate) fn replace_immutable_lock_before_write_open_for_test(
    path: &Path,
    hook: impl FnOnce(&Path) + Send + 'static,
) {
    let path = canonical_destination(path).unwrap_or_else(|_| path.to_path_buf());
    immutable_lock_preopen_hooks()
        .lock()
        .expect("immutable-lock pre-open hook lock")
        .insert(path, Box::new(hook));
}

#[cfg(test)]
fn run_immutable_lock_preopen_hook_for_test(path: &Path) {
    let hook = immutable_lock_preopen_hooks()
        .lock()
        .expect("immutable-lock pre-open hook lock")
        .remove(path);
    if let Some(hook) = hook {
        hook(path);
    }
}

#[derive(Debug)]
struct LearningSnapshotConflict;

impl std::fmt::Display for LearningSnapshotConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("destination generation changed before the atomic rewrite")
    }
}

impl std::error::Error for LearningSnapshotConflict {}

pub(crate) fn is_learning_snapshot_conflict(error: &anyhow::Error) -> bool {
    error.downcast_ref::<LearningSnapshotConflict>().is_some()
}

fn snapshot_conflict() -> anyhow::Error {
    anyhow::Error::new(LearningSnapshotConflict)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DirectoryIdentity {
    #[cfg(unix)]
    Unix { device: u64, inode: u64 },
    #[cfg(windows)]
    Windows { volume: u32, index: u64 },
}

/// Exact authority bytes and filesystem identity observed through a pinned
/// parent, with a destination lock for mutable authority.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct LearningFileSnapshot {
    content: Option<Vec<u8>>,
    generation: Option<String>,
    parent_identity: DirectoryIdentity,
    modified: Option<SystemTime>,
}

impl LearningFileSnapshot {
    pub(crate) fn content(&self) -> Option<&[u8]> {
        self.content.as_deref()
    }

    pub(crate) fn modified(&self) -> Option<SystemTime> {
        self.modified
    }

    pub(crate) fn same_authority(&self, other: &Self) -> bool {
        self.generation == other.generation && self.parent_identity == other.parent_identity
    }
}

/// A file-backed authority store that can be updated on a blocking worker and
/// conditionally adopted without replacing a newer in-memory epoch.
#[doc(hidden)]
pub trait AsyncDurableStore: Clone + Send + Sync + 'static {
    fn authority_name(&self) -> &'static str;
    fn durable_path(&self) -> Option<&Path>;
    fn same_durable_snapshot(&self, snapshot: &LearningFileSnapshot) -> bool;
    fn same_in_memory_epoch(&self, other: &Self) -> bool;
    fn adopt_async_result(&mut self, baseline: &Self, result: Self) -> Result<()> {
        if self.same_in_memory_epoch(baseline) {
            *self = result;
            return Ok(());
        }
        if self.same_in_memory_epoch(&result) {
            return Ok(());
        }
        anyhow::bail!(
            "{} authority changed during asynchronous file I/O",
            self.authority_name()
        )
    }
}

#[derive(Debug)]
struct AuthorityLockTimeout {
    boundary: &'static str,
}

impl std::fmt::Display for AuthorityLockTimeout {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "timed out acquiring {} authority coordination",
            self.boundary
        )
    }
}

impl std::error::Error for AuthorityLockTimeout {}

fn authority_lock_timeout(boundary: &'static str) -> anyhow::Error {
    anyhow::Error::new(AuthorityLockTimeout { boundary })
}

#[cfg(test)]
fn is_authority_lock_timeout(error: &anyhow::Error) -> bool {
    error.downcast_ref::<AuthorityLockTimeout>().is_some()
}

const AUTHORITY_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const AUTHORITY_LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

fn durable_store_coordinator(path: &Path) -> Result<Arc<RwLock<()>>> {
    static COORDINATORS: OnceLock<Mutex<BTreeMap<PathBuf, Weak<RwLock<()>>>>> = OnceLock::new();
    let key = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut coordinators = COORDINATORS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| anyhow::anyhow!("durable-store coordinator is unavailable"))?;
    if let Some(coordinator) = coordinators.get(&key).and_then(Weak::upgrade) {
        return Ok(coordinator);
    }
    let coordinator = Arc::new(RwLock::new(()));
    coordinators.insert(key, Arc::downgrade(&coordinator));
    Ok(coordinator)
}

async fn acquire_durable_store_write_permit(path: &Path) -> Result<OwnedRwLockWriteGuard<()>> {
    acquire_durable_store_write_permit_with_timeout(path, AUTHORITY_LOCK_TIMEOUT).await
}

async fn acquire_durable_store_write_permit_with_timeout(
    path: &Path,
    timeout: Duration,
) -> Result<OwnedRwLockWriteGuard<()>> {
    #[cfg(test)]
    signal_durable_store_write_attempt(path);
    let permit = tokio::time::timeout(timeout, durable_store_coordinator(path)?.write_owned())
        .await
        .map_err(|_| authority_lock_timeout("in-process"))?;
    Ok(permit)
}

#[cfg(test)]
fn durable_store_write_attempt_hooks(
) -> &'static std::sync::Mutex<BTreeMap<PathBuf, Arc<tokio::sync::Semaphore>>> {
    static HOOKS: OnceLock<std::sync::Mutex<BTreeMap<PathBuf, Arc<tokio::sync::Semaphore>>>> =
        OnceLock::new();
    HOOKS.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
fn observe_durable_store_write_attempt(path: &Path) -> Arc<tokio::sync::Semaphore> {
    let signal = Arc::new(tokio::sync::Semaphore::new(0));
    durable_store_write_attempt_hooks()
        .lock()
        .expect("durable-store attempt hook lock")
        .insert(path.to_path_buf(), signal.clone());
    signal
}

#[cfg(test)]
fn signal_durable_store_write_attempt(path: &Path) {
    if let Some(signal) = durable_store_write_attempt_hooks()
        .lock()
        .expect("durable-store attempt hook lock")
        .remove(path)
    {
        signal.add_permits(1);
    }
}

async fn acquire_durable_store_read_permit(path: &Path) -> Result<OwnedRwLockReadGuard<()>> {
    tokio::time::timeout(
        AUTHORITY_LOCK_TIMEOUT,
        durable_store_coordinator(path)?.read_owned(),
    )
    .await
    .map_err(|_| authority_lock_timeout("in-process"))
}

/// An immutable generation-bound authority snapshot. Acquisition validates the
/// durable bytes and live epoch under coordination, then retains the exact
/// read coordination until the caller's finite side-effect handoff returns.
/// This prevents an allow removal or deny insertion from landing between the
/// authority decision and upstream initiation. The proxy releases the lease
/// before it streams the response body.
#[doc(hidden)]
pub struct AuthorityUseLease<S> {
    snapshot: S,
    _store_guard: OwnedRwLockReadGuard<S>,
    _destination_lock: Option<DestinationLock>,
    _permit: Option<OwnedRwLockReadGuard<()>>,
}

impl<S> std::ops::Deref for AuthorityUseLease<S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.snapshot
    }
}

fn acquire_locked_authority_snapshot(
    path: PathBuf,
) -> Result<(DestinationLock, LearningFileSnapshot)> {
    #[cfg(test)]
    signal_authority_snapshot_attempt_for_test(&path);
    let mut lock = DestinationLock::acquire_shared(&path)?;
    lock.verify_parent_binding()?;
    if !transaction_artifacts(lock.destination())?.is_empty() {
        drop(lock);
        let recovery_lock = DestinationLock::acquire(&path)?;
        recovery_lock.verify_parent_binding()?;
        recover_learning_file_transaction_locked(recovery_lock.destination())?;
        recovery_lock.verify_parent_binding()?;
        drop(recovery_lock);
        lock = DestinationLock::acquire_shared(&path)?;
        lock.verify_parent_binding()?;
    }
    if !transaction_artifacts(lock.destination())?.is_empty() {
        anyhow::bail!("authority transaction requires exclusive recovery before use")
    }
    let snapshot = read_learning_file_snapshot_locked(&lock)?;
    Ok((lock, snapshot))
}

#[cfg(test)]
fn authority_snapshot_attempt_hooks(
) -> &'static std::sync::Mutex<std::collections::BTreeMap<PathBuf, std::sync::mpsc::SyncSender<()>>>
{
    static HOOKS: OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<PathBuf, std::sync::mpsc::SyncSender<()>>>,
    > = OnceLock::new();
    HOOKS.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()))
}

#[cfg(test)]
fn signal_authority_snapshot_attempt_for_test(path: &Path) {
    if let Some(sender) = authority_snapshot_attempt_hooks()
        .lock()
        .unwrap()
        .remove(path)
    {
        let _ = sender.try_send(());
    }
}

#[cfg(test)]
pub(crate) fn observe_authority_snapshot_attempt_for_test(
    path: PathBuf,
) -> std::sync::mpsc::Receiver<()> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    authority_snapshot_attempt_hooks()
        .lock()
        .unwrap()
        .insert(path, sender);
    receiver
}

/// Acquire a bounded read lease for a previously refreshed store. A durable
/// generation change between refresh and lease acquisition is rejected. The
/// owned task keeps path coordination alive if its async caller is cancelled
/// while blocking filesystem work is in progress.
#[doc(hidden)]
pub async fn acquire_async_authority_use_lease<S>(
    store: &Arc<RwLock<S>>,
    task: &'static str,
) -> Result<AuthorityUseLease<S>>
where
    S: AsyncDurableStore,
{
    let store = Arc::clone(store);
    tokio::spawn(async move {
        let baseline = store.read().await.clone();
        let path = baseline.durable_path().map(Path::to_path_buf);
        let permit = match path.as_deref() {
            Some(path) => Some(acquire_durable_store_read_permit(path).await?),
            None => None,
        };
        let (destination_lock, snapshot) = match path {
            Some(path) => {
                let pair =
                    tokio::task::spawn_blocking(move || acquire_locked_authority_snapshot(path))
                        .await
                        .map_err(|error| anyhow::anyhow!("{task} task failed: {error}"))??;
                (Some(pair.0), Some(pair.1))
            }
            None => (None, None),
        };
        let guard = Arc::clone(&store).read_owned().await;
        if !guard.same_in_memory_epoch(&baseline)
            || snapshot
                .as_ref()
                .is_some_and(|snapshot| !guard.same_durable_snapshot(snapshot))
        {
            anyhow::bail!("{task} authority changed before its use boundary")
        }
        let snapshot = guard.clone();
        Ok(AuthorityUseLease {
            snapshot,
            _store_guard: guard,
            _destination_lock: destination_lock,
            _permit: permit,
        })
    })
    .await
    .map_err(|error| anyhow::anyhow!("{task} coordination task failed: {error}"))?
}

/// Run one synchronous file transaction on Tokio's blocking pool. The
/// destination-scoped single-flight permit remains held until the exact
/// returned snapshot is either adopted or rejected against a newer in-memory
/// epoch.
#[doc(hidden)]
pub async fn run_async_durable_store_operation<S, T, F>(
    store: &Arc<RwLock<S>>,
    task: &'static str,
    operation: F,
) -> Result<T>
where
    S: AsyncDurableStore,
    T: Send + 'static,
    F: FnOnce(&mut S) -> Result<T> + Send + 'static,
{
    let store = Arc::clone(store);
    tokio::spawn(async move {
        let path = store.read().await.durable_path().map(Path::to_path_buf);
        let _permit = match path {
            Some(path) => Some(acquire_durable_store_write_permit(&path).await?),
            None => None,
        };
        let baseline = store.read().await.clone();
        let mut worker = baseline.clone();
        let (result, value) = tokio::task::spawn_blocking(move || {
            let value = operation(&mut worker)?;
            Ok::<_, anyhow::Error>((worker, value))
        })
        .await
        .map_err(|error| anyhow::anyhow!("{task} task failed: {error}"))??;
        store.write().await.adopt_async_result(&baseline, result)?;
        Ok(value)
    })
    .await
    .map_err(|error| anyhow::anyhow!("{task} coordination task failed: {error}"))?
}

const MAX_SNAPSHOT_RETRIES: usize = 8;

pub(crate) fn retry_learning_snapshot_conflicts<T, F>(mut operation: F) -> Result<T>
where
    F: FnMut() -> Result<T>,
{
    for _ in 0..MAX_SNAPSHOT_RETRIES {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if is_learning_snapshot_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(snapshot_conflict()).context("bounded learning-file mutation exhausted its CAS retries")
}

/// Reapply a commutative mutation to fresh locked snapshots until its CAS
/// succeeds. The callback returns the canonical replacement and an adoption
/// value derived from the same snapshot.
pub(crate) fn rewrite_learning_file_bounded<T, F>(
    path: &Path,
    mut reapply: F,
) -> Result<(T, LearningFileSnapshot, Option<anyhow::Error>)>
where
    F: FnMut(&LearningFileSnapshot) -> Result<(Option<String>, T)>,
{
    for _ in 0..MAX_SNAPSHOT_RETRIES {
        let snapshot = load_learning_file_snapshot(path)?;
        let (content, adoption) = reapply(&snapshot)?;
        let Some(content) = content else {
            return Ok((adoption, snapshot, None));
        };
        match write_learning_file_atomically_for_locked_snapshot(path, &snapshot, &content) {
            Ok(outcome) => {
                let (committed, warning) = outcome.into_parts();
                return Ok((adoption, committed, warning));
            }
            Err(error) if is_learning_snapshot_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(snapshot_conflict()).context("bounded learning-file rewrite exhausted its CAS retries")
}

/// Create one durable authority file only when its destination is absent.
/// Parent hardening, restrictive file creation, replacement journaling, and
/// generation comparison use the same path as subsequent learning writes.
pub fn create_hardened_file_if_absent(path: &Path, content: &str) -> Result<()> {
    let (_, _, warning) = rewrite_learning_file_bounded(path, |snapshot| {
        if let Some(existing) = snapshot.content() {
            if existing != content.as_bytes() {
                return Err(snapshot_conflict())
                    .context("authority-file destination already contains different bytes");
            }
            return Ok((None, ()));
        }
        Ok((Some(content.to_string()), ()))
    })?;
    if let Some(error) = warning {
        tracing::warn!("authority-file creation committed with a durability warning: {error}");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn authority_tempdir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("create authority test directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("harden authority test directory");
    }
    directory
}

#[cfg(test)]
pub(crate) fn write_authority_file(
    path: impl AsRef<Path>,
    content: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    let path = path.as_ref();
    std::fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    apply_owner_only_windows_dacl(path)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    Ok(())
}

#[cfg(all(test, unix))]
pub(crate) fn create_authority_directory(path: impl AsRef<Path>) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let path = path.as_ref();
    std::fs::create_dir(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(test)]
pub(crate) fn hold_learning_file_lock_for_test(
    path: &Path,
    acquired: &std::sync::Barrier,
    release: &std::sync::Barrier,
) {
    let lock = DestinationLock::acquire(path).expect("acquire authority test lock");
    acquired.wait();
    release.wait();
    drop(lock);
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LearningTransactionMarker {
    version: u32,
    transaction_id: String,
    phase: LearningTransactionPhase,
    candidate_generation: String,
    expected_generation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_security_generation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_unix_mode: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LearningTransactionPhase {
    Preparing,
    Ready,
    Replacing,
    ReplacementDurable,
    BackupRemoved,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LearningTransactionMarkerV2 {
    version: u32,
    transaction_id: String,
    content_sha256: String,
    original_sha256: Option<String>,
    had_destination: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LearningTransactionMarkerV1 {
    version: u32,
    destination: String,
    source: String,
    backup: String,
    content_sha256: String,
    original_sha256: Option<String>,
    had_destination: bool,
}

enum DecodedLearningTransactionMarker {
    Current(LearningTransactionMarker),
    Legacy {
        transaction_id: String,
        candidate_generation: String,
        expected_generation: Option<String>,
        had_destination: bool,
    },
}

#[derive(Debug)]
struct LearningTransactionPaths {
    marker: PathBuf,
    marker_staging: PathBuf,
    source: PathBuf,
    backup_staging: PathBuf,
    backup: PathBuf,
}

const LEARNING_TRANSACTION_VERSION: u32 = 3;
const MAX_TRANSACTION_MARKER_BYTES: u64 = 4 * 1024;
const MAX_CORRUPT_RECOVERY_BYTES: usize = 16 * 1024 * 1024;
const MAX_CORRUPT_RECOVERY_FILES: usize = 8;

fn learning_sibling(path: &Path, role: &str, identity: Option<u128>) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("learning");
    match identity {
        Some(identity) => parent.join(format!(".{name}.learning-{role}-{identity:032x}")),
        None => parent.join(format!(".{name}.learning-{role}")),
    }
}

fn content_digest(content: &[u8]) -> String {
    Sha256::digest(content)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_transaction_id(identity: &str) -> Result<()> {
    if identity.len() != 32
        || !identity
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        anyhow::bail!("invalid learning transaction identity")
    }
    Ok(())
}

fn validate_generation_digest(digest: &str) -> Result<()> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        anyhow::bail!("invalid learning transaction generation digest")
    }
    Ok(())
}

#[cfg(unix)]
fn validate_recoverable_unix_mode(mode: u32) -> Result<()> {
    if mode & 0o600 != 0o600 || mode & 0o7111 != 0 || mode & 0o022 != 0 || mode > 0o7777 {
        anyhow::bail!("transaction marker records an unsafe authority-file mode")
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_recoverable_unix_mode(_mode: u32) -> Result<()> {
    anyhow::bail!("Unix authority-file modes are invalid on this platform")
}

fn transaction_paths(path: &Path, identity: &str) -> Result<LearningTransactionPaths> {
    validate_transaction_id(identity)?;
    let marker = learning_sibling(path, "transaction", None);
    let marker_staging =
        learning_sibling(path, "marker", Some(u128::from_str_radix(identity, 16)?));
    let source = learning_sibling(path, "new", Some(u128::from_str_radix(identity, 16)?));
    let backup_staging =
        learning_sibling(path, "old-stage", Some(u128::from_str_radix(identity, 16)?));
    let backup = learning_sibling(path, "old", Some(u128::from_str_radix(identity, 16)?));
    let paths = [
        &marker,
        &marker_staging,
        &source,
        &backup_staging,
        &backup,
        path,
    ];
    for (index, left) in paths.iter().enumerate() {
        if paths[index + 1..].iter().any(|right| left == right) {
            anyhow::bail!("learning transaction paths are not distinct")
        }
        if left.parent().unwrap_or_else(|| Path::new("."))
            != path.parent().unwrap_or_else(|| Path::new("."))
        {
            anyhow::bail!("learning transaction path escapes its destination directory")
        }
    }
    Ok(LearningTransactionPaths {
        marker,
        marker_staging,
        source,
        backup_staging,
        backup,
    })
}

fn canonical_destination(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = parent.canonicalize().with_context(|| {
        format!(
            "failed to resolve destination directory {}",
            parent.display()
        )
    })?;
    let name = path
        .file_name()
        .context("learning destination has no file name")?;
    Ok(parent.join(name))
}

#[cfg(windows)]
fn destination_lock_path(path: &Path) -> Result<PathBuf> {
    Ok(learning_sibling(
        &canonical_destination(path)?,
        "lock",
        None,
    ))
}

struct DestinationLock {
    file: File,
    parent: File,
    canonical_parent: PathBuf,
    destination: PathBuf,
    canonical_lock_path: PathBuf,
}

struct ImmutableAuthorityLock {
    file: File,
    parent: File,
    canonical_parent: PathBuf,
    canonical_lock_path: PathBuf,
}

impl ImmutableAuthorityLock {
    fn acquire(path: &Path, immutable_authority: &File) -> Result<Self> {
        ensure_destination_parent(path)?;
        let canonical_lock_path = canonical_destination(path)?;
        let canonical_parent = canonical_lock_path
            .parent()
            .context("immutable authority lock has no canonical parent")?
            .to_path_buf();
        let parent = open_parent_directory(&canonical_parent)?;
        validate_trusted_parent(&parent, &canonical_parent)?;
        let bound_lock_path = bind_destination_to_parent(&parent, &canonical_lock_path)?;
        let file = open_owner_only_new_or_existing_distinct(
            &bound_lock_path,
            &canonical_lock_path,
            immutable_authority,
        )
        .with_context(|| format!("failed to open immutable authority lock {}", path.display()))?;
        ensure_regular_file(&bound_lock_path)?;
        lock_file(&file, Instant::now() + AUTHORITY_LOCK_TIMEOUT, true)
            .with_context(|| format!("failed to lock immutable authority {}", path.display()))?;
        let lock = Self {
            file,
            parent,
            canonical_parent,
            canonical_lock_path,
        };
        lock.verify_parent_binding()?;
        Ok(lock)
    }

    fn verify_parent_binding(&self) -> Result<()> {
        let current = self.canonical_parent.canonicalize().with_context(|| {
            format!(
                "failed to verify immutable authority lock directory {}",
                self.canonical_parent.display()
            )
        })?;
        if current != self.canonical_parent {
            anyhow::bail!("immutable authority lock directory binding changed")
        }
        parent_identity_matches(&self.parent, &self.canonical_parent)?;
        validate_trusted_parent(&self.parent, &self.canonical_parent)?;
        validate_lock_file(&self.file, &self.canonical_lock_path)
    }
}
impl DestinationLock {
    fn acquire(path: &Path) -> Result<Self> {
        Self::acquire_with_mode(path, true)
    }

    fn acquire_shared(path: &Path) -> Result<Self> {
        Self::acquire_with_mode(path, false)
    }

    fn acquire_with_mode(path: &Path, exclusive: bool) -> Result<Self> {
        Self::acquire_with_mode_and_timeout(path, exclusive, AUTHORITY_LOCK_TIMEOUT)
    }

    fn acquire_with_mode_and_timeout(
        path: &Path,
        exclusive: bool,
        timeout: Duration,
    ) -> Result<Self> {
        #[cfg(test)]
        signal_authority_snapshot_attempt_for_test(path);
        ensure_destination_parent(path)?;
        let destination = canonical_destination(path)?;
        let canonical_parent = destination
            .parent()
            .context("learning destination has no canonical parent")?
            .to_path_buf();
        let parent = open_parent_directory(&canonical_parent)?;
        validate_trusted_parent(&parent, &canonical_parent)?;
        let destination = bind_destination_to_parent(&parent, &destination)?;
        let lock_path = learning_sibling(&destination, "lock", None);
        let canonical_lock_path = learning_sibling(
            &canonical_parent.join(
                destination
                    .file_name()
                    .context("learning destination has no file name")?,
            ),
            "lock",
            None,
        );
        let file = open_owner_only_new_or_existing(&lock_path).with_context(|| {
            format!("failed to open learning-file lock {}", lock_path.display())
        })?;
        ensure_regular_file(&lock_path)?;
        lock_file(&file, Instant::now() + timeout, exclusive)
            .with_context(|| format!("failed to lock learning destination {}", path.display()))?;
        validate_lock_file(&file, &canonical_lock_path)?;
        let lock = Self {
            file,
            parent,
            canonical_parent,
            destination,
            canonical_lock_path,
        };
        lock.verify_parent_binding()?;
        Ok(lock)
    }

    fn destination(&self) -> &Path {
        &self.destination
    }

    fn verify_parent_binding(&self) -> Result<()> {
        let current = self.canonical_parent.canonicalize().with_context(|| {
            format!(
                "failed to verify destination directory {}",
                self.canonical_parent.display()
            )
        })?;
        if current != self.canonical_parent {
            anyhow::bail!("destination directory binding changed during the transaction")
        }
        parent_identity_matches(&self.parent, &self.canonical_parent)?;
        validate_trusted_parent(&self.parent, &self.canonical_parent)?;
        validate_lock_file(&self.file, &self.canonical_lock_path)
    }

    fn parent_identity(&self) -> Result<DirectoryIdentity> {
        directory_identity(&self.parent)
    }
}

#[cfg(unix)]
fn directory_identity(file: &File) -> Result<DirectoryIdentity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok(DirectoryIdentity::Unix {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
fn directory_identity(file: &File) -> Result<DirectoryIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect a pinned Windows directory");
    }
    Ok(DirectoryIdentity::Windows {
        volume: information.dwVolumeSerialNumber,
        index: (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
    })
}

#[cfg(not(any(unix, windows)))]
fn directory_identity(_file: &File) -> Result<DirectoryIdentity> {
    anyhow::bail!("destination directory identity checks are unsupported on this platform")
}

#[cfg(unix)]
fn validate_trusted_parent(parent: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = parent.metadata()?;
    let effective_user = unsafe { libc::geteuid() };
    if metadata.uid() != effective_user && metadata.uid() != 0 {
        anyhow::bail!("destination directory is not owned by a trusted principal")
    }
    if metadata.mode() & 0o022 != 0 {
        anyhow::bail!("destination directory permits untrusted entry replacement")
    }
    if !metadata.is_dir() {
        anyhow::bail!("destination parent is not a directory")
    }
    parent_identity_matches(parent, path)
}

#[cfg(unix)]
fn validate_authority_file(file: &File) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    let effective_user = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || (metadata.uid() != effective_user && metadata.uid() != 0)
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        anyhow::bail!("authority file ownership, permissions, or link count are unsafe")
    }
    Ok(())
}

#[cfg(windows)]
fn validate_trusted_parent(parent: &File, path: &Path) -> Result<()> {
    validate_windows_authority_handle(parent, true)?;
    parent_identity_matches(parent, path)
}

#[cfg(windows)]
fn validate_authority_file(file: &File) -> Result<()> {
    validate_windows_authority_handle(file, false)
}

#[cfg(unix)]
fn executable_search_file_is_candidate(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.is_file() && metadata.mode() & 0o111 != 0
}

#[cfg(windows)]
fn executable_search_file_is_candidate(metadata: &std::fs::Metadata) -> bool {
    metadata.is_file()
}

#[cfg(unix)]
fn validate_executable_search_file(file: &File, untrusted_unix_user_id: Option<u32>) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    if !executable_search_file_is_candidate(&metadata)
        || untrusted_unix_user_id.is_some_and(|user_id| metadata.uid() == user_id)
        || metadata.mode() & 0o022 != 0
    {
        anyhow::bail!("executable search file ownership or permissions are unsafe")
    }
    Ok(())
}

#[cfg(windows)]
fn validate_executable_search_file(
    file: &File,
    _untrusted_unix_user_id: Option<u32>,
) -> Result<()> {
    validate_windows_operator_authority_handle(file, false)
}

#[cfg(windows)]
fn windows_authority_mutation_mask(directory: bool) -> u32 {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA, FILE_DELETE_CHILD,
        FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
    };
    let object_specific = if directory {
        FILE_ADD_FILE
            | FILE_ADD_SUBDIRECTORY
            | FILE_DELETE_CHILD
            | FILE_WRITE_ATTRIBUTES
            | FILE_WRITE_EA
    } else {
        FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA
    };
    object_specific
        | 0x0001_0000 // DELETE
        | 0x0004_0000 // WRITE_DAC
        | 0x0008_0000 // WRITE_OWNER
        | 0x1000_0000 // GENERIC_ALL
        | 0x4000_0000 // GENERIC_WRITE
}

#[cfg(windows)]
fn validate_windows_authority_handle(file: &File, directory: bool) -> Result<()> {
    validate_windows_authority_handle_with_current_user(file, directory, true)
}

#[cfg(windows)]
fn validate_windows_operator_authority_handle(file: &File, directory: bool) -> Result<()> {
    validate_windows_authority_handle_with_current_user(file, directory, false)
}

#[cfg(windows)]
fn validate_windows_authority_handle_with_current_user(
    file: &File,
    directory: bool,
    allow_current_user: bool,
) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, GetSecurityInfo, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, EqualSid, GetAce, GetTokenInformation, IsValidAcl, IsValidSid,
        TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACE_HEADER,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSID, SECURITY_MAX_SID_SIZE,
        TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect the Windows authority object type");
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        anyhow::bail!("authority object is a Windows reparse point");
    }
    let is_directory = information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if is_directory != directory {
        anyhow::bail!("authority object type does not match its expected role");
    }

    fn well_known_sid(kind: i32) -> Result<Vec<u8>> {
        let mut sid = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = sid.len() as u32;
        if unsafe {
            CreateWellKnownSid(
                kind,
                std::ptr::null_mut(),
                sid.as_mut_ptr().cast(),
                &mut size,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error())
                .context("failed to construct a trusted Windows SID");
        }
        sid.truncate(size as usize);
        Ok(sid)
    }

    fn current_user_sid() -> Result<Vec<u8>> {
        let mut token = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to open the current Windows process token");
        }
        let mut needed = 0;
        unsafe {
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        }
        if needed == 0 {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(token) };
            return Err(std::io::Error::last_os_error())
                .context("failed to size the current Windows user SID");
        }
        let mut token_user = vec![0u8; needed as usize];
        let loaded = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                token_user.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        };
        unsafe { windows_sys::Win32::Foundation::CloseHandle(token) };
        if loaded == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to read the current Windows user SID");
        }
        let user = unsafe { &*(token_user.as_ptr().cast::<TOKEN_USER>()) };
        let sid_length = unsafe { windows_sys::Win32::Security::GetLengthSid(user.User.Sid) };
        if sid_length == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to measure the current Windows user SID");
        }
        let mut sid = vec![0u8; sid_length as usize];
        if unsafe {
            windows_sys::Win32::Security::CopySid(
                sid_length,
                sid.as_mut_ptr().cast(),
                user.User.Sid,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error())
                .context("failed to copy the current Windows user SID");
        }
        Ok(sid)
    }

    fn string_sid(value: &str, label: &str) -> Result<Vec<u8>> {
        let value = format!("{value}\0").encode_utf16().collect::<Vec<_>>();
        let mut allocated: PSID = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(value.as_ptr(), &mut allocated) } == 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to construct the Windows {label} SID"));
        }
        let length = unsafe { windows_sys::Win32::Security::GetLengthSid(allocated) };
        if length == 0 {
            unsafe { LocalFree(allocated) };
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to measure the Windows {label} SID"));
        }
        let mut sid = vec![0u8; length as usize];
        let copied = unsafe {
            windows_sys::Win32::Security::CopySid(length, sid.as_mut_ptr().cast(), allocated)
        };
        unsafe { LocalFree(allocated) };
        if copied == 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to copy the Windows {label} SID"));
        }
        Ok(sid)
    }

    let system = well_known_sid(WinLocalSystemSid)?;
    let administrators = well_known_sid(WinBuiltinAdministratorsSid)?;
    let current_user = current_user_sid()?;
    let owner_rights = string_sid("S-1-3-4", "Owner Rights")?;
    let trusted_installer = string_sid(
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
        "TrustedInstaller",
    )?;
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() || owner.is_null() || dacl.is_null() {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor) };
        }
        anyhow::bail!("authority object has no inspectable owner-only Windows DACL");
    }

    let trusted_owner = (allow_current_user
        && unsafe { EqualSid(owner, current_user.as_ptr().cast_mut().cast()) } != 0)
        || unsafe { EqualSid(owner, system.as_ptr().cast_mut().cast()) } != 0
        || unsafe { EqualSid(owner, administrators.as_ptr().cast_mut().cast()) } != 0
        || unsafe { EqualSid(owner, trusted_installer.as_ptr().cast_mut().cast()) } != 0;
    if !trusted_owner {
        unsafe { LocalFree(descriptor) };
        anyhow::bail!("authority object is not owned by a trusted Windows principal");
    }

    let dangerous = windows_authority_mutation_mask(directory);
    let result = (|| -> Result<()> {
        const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
        const ACCESS_DENIED_ACE_TYPE: u8 = 1;

        if unsafe { IsValidAcl(dacl) } == 0 {
            anyhow::bail!("authority object has an invalid Windows DACL");
        }
        for index in 0..unsafe { (*dacl).AceCount } {
            let mut ace = std::ptr::null_mut();
            if unsafe { GetAce(dacl, u32::from(index), &mut ace) } == 0 || ace.is_null() {
                anyhow::bail!("failed to enumerate the Windows authority DACL");
            }
            let header = ace.cast::<ACE_HEADER>();
            // An inherit-only ACE does not grant rights on this object. Each
            // descendant authority object is opened and validated separately,
            // so inherited grants become enforceable when they reach the
            // descendant rather than making a trusted ancestor unusable.
            const INHERIT_ONLY_ACE: u8 = 0x08;
            if unsafe { (*header).AceFlags } & INHERIT_ONLY_ACE != 0 {
                continue;
            }
            match unsafe { (*header).AceType } {
                ACCESS_DENIED_ACE_TYPE => continue,
                ACCESS_ALLOWED_ACE_TYPE => {}
                // Object and callback ACEs have variable trustee layouts and
                // may evaluate code or object-type conditions. Authority
                // storage accepts only unconditional, directly inspectable
                // grants and fails closed on every other ACE form.
                _ => anyhow::bail!("authority DACL contains an unsupported ACE type"),
            }
            let ace_size = usize::from(unsafe { (*header).AceSize });
            if ace_size < std::mem::size_of::<ACCESS_ALLOWED_ACE>() {
                anyhow::bail!("authority DACL contains a truncated access-allowed ACE");
            }
            let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
            if unsafe { (*allowed).Mask } & dangerous == 0 {
                continue;
            }
            let trustee: PSID =
                unsafe { std::ptr::addr_of!((*allowed).SidStart).cast_mut().cast() };
            let sid_offset = trustee as usize - ace as usize;
            const SID_HEADER_SIZE: usize = 8;
            if sid_offset + SID_HEADER_SIZE > ace_size {
                anyhow::bail!("authority DACL contains a truncated trustee SID");
            }
            let sub_authority_count = usize::from(unsafe { *trustee.cast::<u8>().add(1) });
            let sid_size = SID_HEADER_SIZE + sub_authority_count * std::mem::size_of::<u32>();
            if sid_offset + sid_size > ace_size {
                anyhow::bail!("authority DACL contains a truncated trustee SID");
            }
            if unsafe { IsValidSid(trustee) } == 0 {
                anyhow::bail!("authority DACL grants mutation rights to an invalid trustee SID");
            }
            let trusted = unsafe { EqualSid(trustee, owner) } != 0
                || (allow_current_user
                    && unsafe { EqualSid(trustee, current_user.as_ptr().cast_mut().cast()) } != 0)
                || unsafe { EqualSid(trustee, system.as_ptr().cast_mut().cast()) } != 0
                || unsafe { EqualSid(trustee, administrators.as_ptr().cast_mut().cast()) } != 0
                || unsafe { EqualSid(trustee, trusted_installer.as_ptr().cast_mut().cast()) } != 0
                // Owner Rights represents the already validated object owner.
                // Accept it only after the owner check above succeeds.
                || unsafe { EqualSid(trustee, owner_rights.as_ptr().cast_mut().cast()) } != 0;
            if !trusted {
                anyhow::bail!("authority DACL grants mutation rights to an untrusted principal");
            }
        }
        Ok(())
    })();
    unsafe { LocalFree(descriptor) };
    result
}

#[cfg(not(any(unix, windows)))]
fn validate_authority_file(_file: &File) -> Result<()> {
    anyhow::bail!("authority-file validation is unsupported on this platform")
}

#[cfg(not(any(unix, windows)))]
fn validate_trusted_parent(_parent: &File, _path: &Path) -> Result<()> {
    anyhow::bail!("trusted destination directories are unsupported on this platform")
}

#[cfg(unix)]
fn validate_lock_file(file: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let held = file.metadata()?;
    let current = std::fs::symlink_metadata(path)?;
    if !held.is_file()
        || held.uid() != unsafe { libc::geteuid() }
        || held.mode() & 0o077 != 0
        || held.nlink() != 1
        || held.dev() != current.dev()
        || held.ino() != current.ino()
    {
        anyhow::bail!("learning-file lock identity or permissions are unsafe")
    }
    Ok(())
}

#[cfg(windows)]
fn validate_lock_file(file: &File, path: &Path) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    fn identity(file: &File) -> Result<(u32, u64)> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(std::io::Error::last_os_error()).context("failed to inspect lock handle");
        }
        Ok((
            info.dwVolumeSerialNumber,
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        ))
    }
    validate_windows_authority_handle(file, false)?;
    let current = owner_only_options().read(true).write(true).open(path)?;
    validate_windows_authority_handle(&current, false)?;
    if identity(file)? != identity(&current)? {
        anyhow::bail!("learning-file lock identity changed while held")
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn validate_lock_file(_file: &File, _path: &Path) -> Result<()> {
    anyhow::bail!("learning-file lock validation is unsupported on this platform")
}

#[cfg(unix)]
fn open_parent_directory(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("failed to pin destination directory {}", path.display()))
}

#[cfg(windows)]
fn open_parent_directory(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    OpenOptions::new()
        .read(true)
        // Excluding FILE_SHARE_DELETE prevents the directory entry from being
        // renamed or removed while transaction paths are in use. Read and
        // write sharing keep ordinary non-elevated file access compatible.
        .share_mode(0x00000001 | 0x00000002)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("failed to pin destination directory {}", path.display()))
}

/// Open a pinned directory handle with the minimum rights needed to replace
/// its DACL. Ordinary parent pinning deliberately remains read-only.
#[cfg(windows)]
fn open_windows_directory_for_dacl_update(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;

    OpenOptions::new()
        // `access_mode` replaces the generic read/write flags. `WRITE_DAC`
        // is required by SetSecurityInfo, while read attributes and control
        // data let the retained handle undergo the existing authority checks.
        .access_mode(FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| {
            format!(
                "failed to open private directory for DACL update {}",
                path.display()
            )
        })
}

#[cfg(target_os = "linux")]
fn bind_destination_to_parent(parent: &File, destination: &Path) -> Result<PathBuf> {
    use std::os::fd::AsRawFd;
    let name = destination
        .file_name()
        .context("learning destination has no file name")?;
    let bound_parent = PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd()));
    if !bound_parent.is_dir() {
        anyhow::bail!("held destination directory is not available through its file descriptor")
    }
    Ok(bound_parent.join(name))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn bind_destination_to_parent(parent: &File, destination: &Path) -> Result<PathBuf> {
    use std::os::fd::AsRawFd;
    let name = destination
        .file_name()
        .context("learning destination has no file name")?;
    let bound_parent = PathBuf::from(format!("/dev/fd/{}", parent.as_raw_fd()));
    if !bound_parent.is_dir() {
        anyhow::bail!("held destination directory is not available through its file descriptor")
    }
    Ok(bound_parent.join(name))
}

#[cfg(not(unix))]
fn bind_destination_to_parent(_parent: &File, destination: &Path) -> Result<PathBuf> {
    Ok(destination.to_path_buf())
}

#[cfg(not(any(unix, windows)))]
fn open_parent_directory(_path: &Path) -> Result<File> {
    anyhow::bail!("destination directory pinning is unsupported on this platform")
}

#[cfg(unix)]
fn parent_identity_matches(parent: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let pinned = parent.metadata()?;
    let current = std::fs::metadata(path)?;
    if pinned.dev() != current.dev() || pinned.ino() != current.ino() {
        anyhow::bail!("destination directory identity changed during the transaction")
    }
    Ok(())
}

#[cfg(windows)]
fn parent_identity_matches(parent: &File, path: &Path) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    fn identity(file: &File) -> Result<(u32, u64)> {
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to inspect a pinned Windows directory");
        }
        Ok((
            information.dwVolumeSerialNumber,
            (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
        ))
    }

    let current = open_parent_directory(path)?;
    if identity(parent)? != identity(&current)? {
        anyhow::bail!("destination directory identity changed during the transaction")
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn parent_identity_matches(_parent: &File, _path: &Path) -> Result<()> {
    anyhow::bail!("destination directory identity checks are unsupported on this platform")
}

#[cfg(unix)]
fn ensure_destination_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_durable_directory(parent, &mut sync_parent_directory)
}

#[cfg(windows)]
fn ensure_destination_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if parent.is_dir() {
        return Ok(());
    }
    let mut missing = Vec::new();
    let mut cursor = parent;
    while !cursor.as_os_str().is_empty() && !cursor.is_dir() {
        missing.push(cursor.to_path_buf());
        cursor = cursor.parent().unwrap_or_else(|| Path::new("."));
    }
    for directory in missing.into_iter().rev() {
        create_owner_only_directory_windows(&directory).with_context(|| {
            format!(
                "failed to create restricted destination directory {}",
                directory.display()
            )
        })?;
    }
    Ok(())
}

#[cfg(windows)]
fn create_owner_only_directory_windows(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    let sddl = "D:P(A;OICI;FA;;;OW)\0".encode_utf16().collect::<Vec<_>>();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to create an owner-only Windows directory descriptor");
    }
    let security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let created = unsafe { CreateDirectoryW(wide.as_ptr(), &security) };
    unsafe { LocalFree(descriptor.cast()) };
    if created == 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error.into());
        }
    }
    if !path.is_dir() {
        anyhow::bail!("restricted destination parent is not a directory")
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_destination_parent(_path: &Path) -> Result<()> {
    anyhow::bail!("learning-file locking is unsupported on this platform")
}

impl Drop for DestinationLock {
    fn drop(&mut self) {
        let _ = unlock_file(&self.file);
    }
}

#[cfg(unix)]
fn lock_file(file: &File, deadline: Instant, exclusive: bool) -> Result<()> {
    use std::os::fd::AsRawFd;
    let mode = if exclusive {
        libc::LOCK_EX
    } else {
        libc::LOCK_SH
    };
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), mode | libc::LOCK_NB) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::WouldBlock {
            return Err(error.into());
        }
        if Instant::now() >= deadline {
            return Err(authority_lock_timeout("cross-process"));
        }
        std::thread::sleep(AUTHORITY_LOCK_RETRY_INTERVAL);
    }
}

#[cfg(unix)]
fn unlock_file(file: &File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn lock_file(file: &File, deadline: Instant, exclusive: bool) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{
        LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };
    loop {
        let mut overlapped = unsafe { std::mem::zeroed() };
        let flags = LOCKFILE_FAIL_IMMEDIATELY
            | if exclusive {
                LOCKFILE_EXCLUSIVE_LOCK
            } else {
                0
            };
        if unsafe { LockFileEx(file.as_raw_handle(), flags, 0, 1, 0, &mut overlapped) } != 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_LOCK_VIOLATION as i32) {
            return Err(error.into());
        }
        if Instant::now() >= deadline {
            return Err(authority_lock_timeout("cross-process"));
        }
        std::thread::sleep(AUTHORITY_LOCK_RETRY_INTERVAL);
    }
}

#[cfg(windows)]
fn unlock_file(file: &File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
    let mut overlapped = unsafe { std::mem::zeroed() };
    if unsafe { UnlockFileEx(file.as_raw_handle(), 0, 1, 0, &mut overlapped) } == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
fn lock_file(_file: &File, _deadline: Instant, _exclusive: bool) -> Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "file locking is unsupported",
    )
    .into())
}

#[cfg(not(any(unix, windows)))]
fn unlock_file(_file: &File) -> std::io::Result<()> {
    Ok(())
}

fn preserve_recovery_metadata(source: &Path, recovery: &Path) -> Result<()> {
    #[cfg(unix)]
    if let Ok(metadata) = std::fs::metadata(source) {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o600;
        std::fs::set_permissions(recovery, std::fs::Permissions::from_mode(mode)).with_context(
            || {
                format!(
                    "failed to preserve recovery metadata for {}",
                    source.display()
                )
            },
        )?;
    }
    #[cfg(windows)]
    let recovery_file = open_windows_recovery_file(recovery)?;
    #[cfg(not(windows))]
    let recovery_file = std::fs::File::open(recovery)?;
    recovery_file
        .sync_all()
        .with_context(|| format!("failed to sync recovery metadata for {}", source.display()))
}

#[cfg(unix)]
fn owner_only_options() -> OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
}

#[cfg(windows)]
fn owner_only_options() -> OpenOptions {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let mut options = OpenOptions::new();
    options
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options
}

#[cfg(not(any(unix, windows)))]
fn owner_only_options() -> OpenOptions {
    OpenOptions::new()
}

#[cfg(windows)]
fn apply_owner_only_windows_dacl(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    let sddl = "D:P(A;;FA;;;OW)"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor = std::ptr::null_mut();
    let mut descriptor_size = 0;
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            &mut descriptor_size,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to create an owner-only Windows DACL");
    }
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        SetFileSecurityW(
            wide.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.cast(),
        )
    };
    unsafe { LocalFree(descriptor.cast()) };
    if result == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to apply an owner-only Windows DACL");
    }
    Ok(())
}

#[cfg(windows)]
fn apply_security_descriptor_to_handle(
    file: &File,
    descriptor: &[u8],
    information: u32,
) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::Security::Authorization::{SetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::GetSecurityDescriptorDacl;

    let mut descriptor = descriptor.to_vec();
    let mut dacl_present = 0;
    let mut dacl = std::ptr::null_mut();
    let mut dacl_defaulted = 0;
    let dacl_result = unsafe {
        GetSecurityDescriptorDacl(
            descriptor.as_mut_ptr().cast(),
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    };
    if dacl_result == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to read the replacement Windows DACL");
    }
    if dacl_present == 0 {
        anyhow::bail!("replacement Windows security descriptor does not contain a DACL");
    }
    if dacl.is_null() {
        anyhow::bail!("replacement Windows security descriptor contains a null DACL");
    }
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            information,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .context("failed to apply a DACL through the pinned file-system handle");
    }
    Ok(())
}

#[cfg(windows)]
fn apply_owner_only_windows_dacl_to_handle(file: &File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetSecurityInfo, SDDL_REVISION_1,
        SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    let sddl = "D:P(A;;FA;;;OW)"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to create an owner-only Windows DACL");
    }
    let mut dacl_present = 0;
    let mut dacl = std::ptr::null_mut();
    let mut dacl_defaulted = 0;
    let dacl_result = unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    };
    if dacl_result == 0 {
        let error = std::io::Error::last_os_error();
        unsafe { LocalFree(descriptor.cast()) };
        return Err(error).context("failed to read the owner-only Windows DACL");
    }
    if dacl_present == 0 {
        unsafe { LocalFree(descriptor.cast()) };
        anyhow::bail!("owner-only Windows security descriptor does not contain a DACL");
    }
    if dacl.is_null() {
        unsafe { LocalFree(descriptor.cast()) };
        anyhow::bail!("owner-only Windows security descriptor contains a null DACL");
    }
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        )
    };
    unsafe { LocalFree(descriptor.cast()) };
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .context("failed to apply an owner-only DACL through the pinned file-system handle");
    }
    Ok(())
}

#[cfg(windows)]
#[doc(hidden)]
pub fn protect_current_user_directory(path: &Path) -> Result<()> {
    let directory = open_windows_directory_for_dacl_update(path)
        .with_context(|| format!("cannot open private directory {}", path.display()))?;
    apply_owner_only_windows_dacl_to_handle(&directory)
        .with_context(|| format!("cannot protect private directory {}", path.display()))?;
    validate_windows_authority_handle(&directory, true)
        .with_context(|| format!("private directory {} is not trusted", path.display()))
}

#[cfg(windows)]
fn ensure_windows_owner_group_compatible(destination: &[u8], writer: &[u8]) -> Result<()> {
    use windows_sys::Win32::Security::{
        EqualSid, GetSecurityDescriptorGroup, GetSecurityDescriptorOwner, PSID,
    };

    fn identities(descriptor: &[u8]) -> Result<(PSID, PSID)> {
        let mut owner = std::ptr::null_mut();
        let mut group = std::ptr::null_mut();
        let mut owner_defaulted = 0;
        let mut group_defaulted = 0;
        if unsafe {
            GetSecurityDescriptorOwner(
                descriptor.as_ptr().cast_mut().cast(),
                &mut owner,
                &mut owner_defaulted,
            )
        } == 0
            || unsafe {
                GetSecurityDescriptorGroup(
                    descriptor.as_ptr().cast_mut().cast(),
                    &mut group,
                    &mut group_defaulted,
                )
            } == 0
            || owner.is_null()
            || group.is_null()
        {
            return Err(std::io::Error::last_os_error())
                .context("failed to extract Windows owner and group identities");
        }
        Ok((owner, group))
    }

    let (destination_owner, destination_group) = identities(destination)?;
    let (writer_owner, writer_group) = identities(writer)?;
    if unsafe { EqualSid(destination_owner, writer_owner) } == 0
        || unsafe { EqualSid(destination_group, writer_group) } == 0
    {
        anyhow::bail!(
            "cannot replace a Windows learning file whose owner or group differs from the non-elevated writer"
        );
    }
    Ok(())
}

#[cfg(not(windows))]
fn open_owner_only_new(path: &Path) -> Result<File> {
    let mut options = owner_only_options();
    let file = options.write(true).read(true).create_new(true).open(path)?;
    #[cfg(windows)]
    apply_owner_only_windows_dacl(path)?;
    Ok(file)
}

#[cfg(windows)]
fn open_windows_recovery_file(path: &Path) -> Result<File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | 0x0004_0000,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to open recovery file {}", path.display()));
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(windows)]
fn open_owner_only_new(path: &Path) -> Result<File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{
        LocalFree, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let sddl = "D:P(A;;FA;;;OW)\0".encode_utf16().collect::<Vec<_>>();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to create an owner-only Windows security descriptor");
    }
    let security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            // WRITE_DAC is the standard access right 0x0004_0000.
            GENERIC_READ | GENERIC_WRITE | 0x0004_0000,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &security,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    unsafe { LocalFree(descriptor.cast()) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to create restricted file {}", path.display()));
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn open_owner_only_new_or_existing(path: &Path) -> Result<File> {
    let mut options = owner_only_options();
    let file = options.write(true).read(true).create(true).open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    apply_owner_only_windows_dacl(path)?;
    Ok(file)
}

/// Open a lock file without ever normalizing the permissions of an authority
/// file. An existing lock is inspected through its directory entry before it
/// is opened for write, then the pinned handle is compared again before any
/// permission or ACL change. A newly created file cannot alias the already
/// opened immutable authority because creation is exclusive.
fn open_owner_only_new_or_existing_distinct(
    path: &Path,
    _canonical_path: &Path,
    immutable_authority: &File,
) -> Result<File> {
    match open_owner_only_new(path) {
        Ok(file) => {
            ensure_regular_file(path)?;
            verify_open_file_binding(&file, path)?;
            return Ok(file);
        }
        Err(error) if anyhow_error_has_io_kind(&error, std::io::ErrorKind::AlreadyExists) => {}
        Err(error) => return Err(error),
    }

    reject_immutable_lock_path_alias(path, immutable_authority)?;
    #[cfg(test)]
    run_immutable_lock_preopen_hook_for_test(_canonical_path);
    let mut options = owner_only_options();
    let file = options.read(true).write(true).open(path)?;
    ensure_regular_file(path)?;
    verify_open_file_binding(&file, path)?;
    if same_file_identity(&file, immutable_authority)? {
        anyhow::bail!("immutable authority lock aliases the immutable authority file")
    }
    set_owner_only_permissions(&file)?;
    Ok(file)
}

fn anyhow_error_has_io_kind(error: &anyhow::Error, kind: std::io::ErrorKind) -> bool {
    error.chain().any(|source| {
        source
            .downcast_ref::<std::io::Error>()
            .is_some_and(|source| source.kind() == kind)
    })
}

fn set_owner_only_permissions(file: &File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    apply_owner_only_windows_dacl_to_handle(file)?;
    Ok(())
}

/// Reject a direct path, hard link, symlink, or Windows reparse point before
/// any write-capable lock handle is opened. The repeated handle check above
/// closes the path-to-open race. The lock parent remains pinned and trusted,
/// and the immutable authority remains pinned by its read-only file handle.
fn reject_immutable_lock_path_alias(path: &Path, immutable_authority: &File) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect immutable authority lock {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("immutable authority lock must not be a symbolic link")
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            anyhow::bail!("immutable authority lock must not be a Windows reparse point")
        }
    }
    if !metadata.is_file() {
        anyhow::bail!("immutable authority lock is not a regular file")
    }
    if same_path_and_file_identity(path, immutable_authority)? {
        anyhow::bail!("immutable authority lock aliases the immutable authority file")
    }
    Ok(())
}

#[cfg(unix)]
fn same_file_identity(left: &File, right: &File) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(windows)]
fn same_file_identity(left: &File, right: &File) -> Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    fn identity(file: &File) -> Result<(u32, u64)> {
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to inspect immutable authority identity");
        }
        Ok((
            information.dwVolumeSerialNumber,
            (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
        ))
    }

    Ok(identity(left)? == identity(right)?)
}

#[cfg(not(any(unix, windows)))]
fn same_file_identity(_left: &File, _right: &File) -> Result<bool> {
    anyhow::bail!("immutable authority lock identity checks are unsupported on this platform")
}

#[cfg(unix)]
fn same_path_and_file_identity(path: &Path, immutable_authority: &File) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let candidate = std::fs::metadata(path)?;
    let authority = immutable_authority.metadata()?;
    Ok(candidate.dev() == authority.dev() && candidate.ino() == authority.ino())
}

#[cfg(windows)]
fn same_path_and_file_identity(path: &Path, immutable_authority: &File) -> Result<bool> {
    let mut options = owner_only_options();
    let candidate = options.read(true).open(path)?;
    same_file_identity(&candidate, immutable_authority)
}

#[cfg(not(any(unix, windows)))]
fn same_path_and_file_identity(_path: &Path, _immutable_authority: &File) -> Result<bool> {
    anyhow::bail!("immutable authority lock identity checks are unsupported on this platform")
}

fn ensure_regular_file(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        anyhow::bail!("learning transaction path is not a regular file")
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            anyhow::bail!("learning transaction path is a Windows reparse point")
        }
    }
    Ok(())
}

fn path_present(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn digest_file(path: &Path) -> Result<String> {
    ensure_regular_file(path)?;
    let mut file = OpenOptions::new().read(true).open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn write_transaction_marker(
    paths: &LearningTransactionPaths,
    marker: &LearningTransactionMarker,
) -> Result<()> {
    let bytes = serde_json::to_vec(marker)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_TRANSACTION_MARKER_BYTES {
        anyhow::bail!("learning transaction marker exceeds its size bound")
    }
    let publish = (|| -> Result<()> {
        let mut file = open_owner_only_new(&paths.marker_staging).with_context(|| {
            format!(
                "failed to create transaction marker {}",
                paths.marker_staging.display()
            )
        })?;
        file.write_all(&bytes).with_context(|| {
            format!(
                "failed to write transaction marker {}",
                paths.marker_staging.display()
            )
        })?;
        file.sync_all().with_context(|| {
            format!(
                "failed to sync transaction marker {}",
                paths.marker_staging.display()
            )
        })?;
        drop(file);
        rename_write_through(&paths.marker_staging, &paths.marker).with_context(|| {
            format!(
                "failed to publish transaction marker {}",
                paths.marker.display()
            )
        })?;
        Ok(())
    })();
    if let Err(error) = publish {
        if !path_present(&paths.marker)? {
            remove_if_present(&paths.marker_staging).with_context(|| {
                format!("failed to clean unpublished transaction marker after: {error}")
            })?;
            sync_learning_parent(paths.marker.parent().unwrap_or_else(|| Path::new(".")))?;
        }
        return Err(error);
    }
    Ok(())
}

fn read_transaction_marker(
    path: &Path,
    destination: &Path,
) -> Result<DecodedLearningTransactionMarker> {
    ensure_regular_file(path)?;
    let metadata = std::fs::metadata(path)?;
    if metadata.len() == 0 || metadata.len() > MAX_TRANSACTION_MARKER_BYTES {
        anyhow::bail!("transaction marker has an invalid bounded size")
    }
    let file = OpenOptions::new().read(true).open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_TRANSACTION_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > MAX_TRANSACTION_MARKER_BYTES {
        anyhow::bail!("transaction marker changed while being read")
    }
    let envelope: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid transaction marker {}", path.display()))?;
    let version = envelope
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .context("transaction marker has no bounded integer version")?;
    match version {
        3 => {
            let marker: LearningTransactionMarker = serde_json::from_value(envelope)
                .with_context(|| format!("invalid transaction marker {}", path.display()))?;
            validate_transaction_id(&marker.transaction_id)?;
            validate_generation_digest(&marker.candidate_generation)?;
            if let Some(expected) = &marker.expected_generation {
                validate_generation_digest(expected)?;
            }
            if let Some(expected) = &marker.expected_security_generation {
                validate_generation_digest(expected)?;
            }
            if let Some(mode) = marker.expected_unix_mode {
                validate_recoverable_unix_mode(mode)?;
            }
            Ok(DecodedLearningTransactionMarker::Current(marker))
        }
        2 => {
            let marker: LearningTransactionMarkerV2 = serde_json::from_value(envelope)
                .with_context(|| format!("invalid version 2 marker {}", path.display()))?;
            if marker.version != 2 || marker.had_destination != marker.original_sha256.is_some() {
                anyhow::bail!("version 2 transaction marker has inconsistent generations")
            }
            validate_transaction_id(&marker.transaction_id)?;
            validate_generation_digest(&marker.content_sha256)?;
            if let Some(expected) = &marker.original_sha256 {
                validate_generation_digest(expected)?;
            }
            Ok(DecodedLearningTransactionMarker::Legacy {
                transaction_id: marker.transaction_id,
                candidate_generation: marker.content_sha256,
                expected_generation: marker.original_sha256,
                had_destination: marker.had_destination,
            })
        }
        1 => decode_v1_transaction_marker(envelope, destination),
        _ => anyhow::bail!("unsupported learning transaction marker version"),
    }
}

fn decode_v1_transaction_marker(
    envelope: serde_json::Value,
    destination: &Path,
) -> Result<DecodedLearningTransactionMarker> {
    let marker: LearningTransactionMarkerV1 =
        serde_json::from_value(envelope).context("invalid version 1 transaction marker")?;
    if marker.version != 1 || marker.had_destination != marker.original_sha256.is_some() {
        anyhow::bail!("version 1 transaction marker has inconsistent generations")
    }
    validate_generation_digest(&marker.content_sha256)?;
    if let Some(expected) = &marker.original_sha256 {
        validate_generation_digest(expected)?;
    }
    let destination_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .context("learning destination name is not portable")?;
    if marker.destination != destination_name {
        anyhow::bail!("version 1 marker targets a different destination")
    }
    let source_prefix = format!(".{destination_name}.learning-new-");
    let backup_prefix = format!(".{destination_name}.learning-old-");
    let source_id = marker
        .source
        .strip_prefix(&source_prefix)
        .context("version 1 source is not a derived transaction path")?;
    let backup_id = marker
        .backup
        .strip_prefix(&backup_prefix)
        .context("version 1 backup is not a derived transaction path")?;
    if source_id != backup_id
        || Path::new(&marker.source).components().count() != 1
        || Path::new(&marker.backup).components().count() != 1
    {
        anyhow::bail!("version 1 transaction paths are inconsistent")
    }
    validate_transaction_id(source_id)?;
    let paths = transaction_paths(destination, source_id)?;
    if paths.source.file_name().and_then(|name| name.to_str()) != Some(marker.source.as_str())
        || paths.backup.file_name().and_then(|name| name.to_str()) != Some(marker.backup.as_str())
    {
        anyhow::bail!("version 1 transaction paths are not canonical")
    }
    Ok(DecodedLearningTransactionMarker::Legacy {
        transaction_id: source_id.to_string(),
        candidate_generation: marker.content_sha256,
        expected_generation: marker.original_sha256,
        had_destination: marker.had_destination,
    })
}

fn transaction_artifacts(path: &Path) -> Result<Vec<PathBuf>> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("learning destination name is not portable")?;
    let prefixes = [
        format!(".{name}.learning-marker-"),
        format!(".{name}.learning-new-"),
        format!(".{name}.learning-old-"),
        format!(".{name}.learning-old-stage-"),
    ];
    let mut found = Vec::new();
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let candidate = entry.file_name();
        let candidate = candidate.to_string_lossy();
        if prefixes.iter().any(|prefix| candidate.starts_with(prefix)) {
            found.push(entry.path());
        }
    }
    Ok(found)
}

/// Recover a destination-bound learning transaction before loading authority.
/// A malformed or ambiguous state fails closed instead of guessing which copy
/// is authoritative.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn recover_learning_file_transaction(path: &Path) -> Result<()> {
    let lock = DestinationLock::acquire(path)?;
    lock.verify_parent_binding()?;
    recover_learning_file_transaction_locked(lock.destination())?;
    lock.verify_parent_binding()
}

/// Recover and read a destination while one lock and pinned parent remain
/// held. The returned bytes and generation refer to the same opened file.
pub(crate) fn load_learning_file_snapshot(path: &Path) -> Result<LearningFileSnapshot> {
    let lock = DestinationLock::acquire(path)?;
    lock.verify_parent_binding()?;
    recover_learning_file_transaction_locked(lock.destination())?;
    read_learning_file_snapshot_locked(&lock)
}

/// Pinned filesystem authority held from the final policy recheck for the
/// child lifetime. Ancestor handles prevent Windows rename/delete races; Unix
/// ownership and mode checks make every retained path immutable to untrusted
/// principals while the daemon holds the lease.
#[derive(Debug)]
pub struct OperatorAuthorityArtifactLease {
    _handles: Vec<File>,
}

#[cfg(unix)]
fn validate_operator_authority_parent(
    parent: &File,
    path: &Path,
    untrusted_unix_user_id: Option<u32>,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    validate_trusted_parent(parent, path)?;
    let metadata = parent.metadata()?;
    if untrusted_unix_user_id.is_some_and(|user_id| user_id == 0 || metadata.uid() == user_id) {
        anyhow::bail!("authority directory can be mutated by the child identity")
    }
    Ok(())
}

#[cfg(windows)]
fn validate_operator_authority_parent(
    parent: &File,
    path: &Path,
    _untrusted_unix_user_id: Option<u32>,
) -> Result<()> {
    // A Windows volume root has no replaceable parent entry. Retaining its
    // no-share-delete handle is sufficient while stricter DACL checks remain
    // required for every descendant directory.
    if path.parent().is_none() {
        return parent_identity_matches(parent, path);
    }
    validate_windows_operator_authority_handle(parent, true)?;
    parent_identity_matches(parent, path)
}

#[cfg(not(any(unix, windows)))]
fn validate_operator_authority_parent(
    parent: &File,
    path: &Path,
    _untrusted_unix_user_id: Option<u32>,
) -> Result<()> {
    validate_trusted_parent(parent, path)
}

#[cfg(unix)]
fn validate_operator_authority_file(
    file: &File,
    untrusted_unix_user_id: Option<u32>,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    validate_authority_file(file)?;
    let metadata = file.metadata()?;
    if untrusted_unix_user_id.is_some_and(|user_id| user_id == 0 || metadata.uid() == user_id) {
        anyhow::bail!("authority file can be mutated by the child identity")
    }
    Ok(())
}

#[cfg(windows)]
fn validate_operator_authority_file(
    file: &File,
    _untrusted_unix_user_id: Option<u32>,
) -> Result<()> {
    validate_windows_operator_authority_handle(file, false)
}

#[cfg(not(any(unix, windows)))]
fn validate_operator_authority_file(
    file: &File,
    _untrusted_unix_user_id: Option<u32>,
) -> Result<()> {
    validate_authority_file(file)
}

fn open_operator_authority_file(path: &Path, untrusted_unix_user_id: Option<u32>) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let handle = options
        .open(path)
        .with_context(|| format!("cannot pin operator authority file {}", path.display()))?;
    validate_operator_authority_file(&handle, untrusted_unix_user_id)
        .with_context(|| format!("operator authority file {} is not trusted", path.display()))?;
    verify_open_file_binding(&handle, path).with_context(|| {
        format!(
            "operator authority file {} changed while it was pinned",
            path.display()
        )
    })?;
    Ok(handle)
}

fn pin_operator_authority_directory_tree(
    root: &Path,
    handles: &mut Vec<File>,
    untrusted_unix_user_id: Option<u32>,
) -> Result<()> {
    const MAX_PINNED_AUTHORITY_ENTRIES: usize = 4_096;

    let mut pending = vec![root.to_path_buf()];
    let mut inspected = 0usize;
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).with_context(|| {
            format!(
                "cannot enumerate operator authority directory {}",
                directory.display()
            )
        })? {
            let path = entry?.path();
            inspected = inspected.saturating_add(1);
            if inspected > MAX_PINNED_AUTHORITY_ENTRIES {
                anyhow::bail!(
                    "operator authority directory exceeds {MAX_PINNED_AUTHORITY_ENTRIES} pinned entries"
                )
            }
            let metadata = std::fs::symlink_metadata(&path).with_context(|| {
                format!("cannot inspect operator authority child {}", path.display())
            })?;
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "operator authority directory contains symlink {}",
                    path.display()
                )
            }
            if metadata.is_dir() {
                let handle = open_parent_directory(&path).with_context(|| {
                    format!("cannot pin operator authority directory {}", path.display())
                })?;
                validate_operator_authority_parent(&handle, &path, untrusted_unix_user_id)
                    .with_context(|| {
                        format!(
                            "operator authority directory {} is not trusted",
                            path.display()
                        )
                    })?;
                handles.push(handle);
                pending.push(path);
            } else if metadata.is_file() {
                // Keep every file handle for the lease lifetime. On Windows a
                // no-share-write handle is the mutation boundary for a child
                // that otherwise has the daemon token; retaining only parent
                // directory handles does not prevent in-place file writes.
                handles.push(open_operator_authority_file(&path, untrusted_unix_user_id)?);
            } else {
                anyhow::bail!(
                    "operator authority directory contains unsupported file type {}",
                    path.display()
                )
            }
        }
    }
    Ok(())
}

/// Pin one executable or credential-bearing operator artifact. Every path
/// component must be a real directory owned by the daemon user or root and
/// must deny mutation by group/other principals. The final object may be a
/// regular file or directory and is opened without following a final symlink.
pub fn lease_operator_authority_artifact(
    path: &Path,
    untrusted_unix_user_id: Option<u32>,
) -> Result<OperatorAuthorityArtifactLease> {
    if !path.is_absolute() {
        anyhow::bail!("operator authority artifact path is not absolute")
    }

    let metadata = std::fs::symlink_metadata(path).with_context(|| {
        format!(
            "cannot inspect operator authority artifact {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !(metadata.is_file() || metadata.is_dir()) {
        anyhow::bail!("operator authority artifact is a symlink or unsupported file type")
    }

    #[cfg(unix)]
    if path.canonicalize().with_context(|| {
        format!(
            "cannot canonicalize operator authority artifact {}",
            path.display()
        )
    })? != path
    {
        anyhow::bail!("operator authority artifact path is not canonical")
    }

    let mut handles = Vec::new();
    let mut ancestors = path.ancestors().skip(1).collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        let handle = open_parent_directory(ancestor).with_context(|| {
            format!(
                "cannot pin operator authority ancestor {}",
                ancestor.display()
            )
        })?;
        validate_operator_authority_parent(&handle, ancestor, untrusted_unix_user_id)
            .with_context(|| {
                format!(
                    "operator authority ancestor {} is not trusted",
                    ancestor.display()
                )
            })?;
        handles.push(handle);
    }

    if metadata.is_dir() {
        let handle = open_parent_directory(path).with_context(|| {
            format!("cannot pin operator authority directory {}", path.display())
        })?;
        validate_operator_authority_parent(&handle, path, untrusted_unix_user_id).with_context(
            || {
                format!(
                    "operator authority directory {} is not trusted",
                    path.display()
                )
            },
        )?;
        handles.push(handle);
        pin_operator_authority_directory_tree(path, &mut handles, untrusted_unix_user_id)?;
    } else {
        handles.push(open_operator_authority_file(path, untrusted_unix_user_id)?);
    }

    Ok(OperatorAuthorityArtifactLease { _handles: handles })
}

fn open_executable_search_file(path: &Path, untrusted_unix_user_id: Option<u32>) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let handle = options
        .open(path)
        .with_context(|| format!("cannot pin executable search entry {}", path.display()))?;
    validate_executable_search_file(&handle, untrusted_unix_user_id)
        .with_context(|| format!("executable search entry {} is not trusted", path.display()))?;
    verify_open_file_binding(&handle, path).with_context(|| {
        format!(
            "executable search entry {} changed while it was pinned",
            path.display()
        )
    })?;
    Ok(handle)
}

#[cfg(unix)]
fn executable_search_entry_is_link(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(unix)]
fn system_executable_directory(path: &Path) -> bool {
    ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]
        .into_iter()
        .filter_map(|directory| Path::new(directory).canonicalize().ok())
        .any(|directory| path == directory)
}

#[cfg(windows)]
fn system_executable_directory(path: &Path) -> bool {
    std::env::var_os("SystemRoot")
        .and_then(|root| PathBuf::from(root).canonicalize().ok())
        .is_some_and(|root| path.starts_with(root))
}

#[cfg(windows)]
fn executable_search_entry_is_link(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn retain_executable_search_link_target(
    path: &Path,
    handles: &mut Vec<File>,
    retained_paths: &mut BTreeSet<PathBuf>,
    untrusted_unix_user_id: Option<u32>,
) -> Result<()> {
    let target = path.canonicalize().with_context(|| {
        format!(
            "cannot resolve executable search link target {}",
            path.display()
        )
    })?;
    let metadata = std::fs::metadata(&target)?;
    if !executable_search_file_is_candidate(&metadata) {
        return Ok(());
    }
    if !system_executable_directory(target.parent().unwrap_or_else(|| Path::new(""))) {
        let lease = lease_operator_authority_artifact(&target, untrusted_unix_user_id)?;
        handles.extend(lease._handles);
        retained_paths.insert(target);
        return Ok(());
    }
    let mut ancestors = target.ancestors().skip(1).collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        if retained_paths.insert(ancestor.to_path_buf()) {
            let handle = open_parent_directory(ancestor).with_context(|| {
                format!(
                    "cannot pin executable search target ancestor {}",
                    ancestor.display()
                )
            })?;
            validate_trusted_parent(&handle, ancestor).with_context(|| {
                format!(
                    "executable search target ancestor {} is not trusted",
                    ancestor.display()
                )
            })?;
            handles.push(handle);
        }
    }
    if retained_paths.insert(target.clone()) {
        handles.push(open_executable_search_file(
            &target,
            untrusted_unix_user_id,
        )?);
    }
    Ok(())
}

/// Pin one directory used for direct executable lookup. Unlike a configuration
/// or plugin tree, PATH lookup examines only immediate entries. This lease
/// validates the directory and retains every immediate executable link target
/// without traversing unrelated entries or descendants. Direct entries cannot
/// be replaced beneath the retained directory; the primary executable has its
/// own exact artifact lease. Link targets and their ancestors remain pinned for
/// the child lifetime. System-directory executables owned by the originating
/// Unix caller are rejected because that caller can rewrite them in place.
pub fn lease_operator_executable_search_directory(
    path: &Path,
    untrusted_unix_user_id: Option<u32>,
) -> Result<OperatorAuthorityArtifactLease> {
    if !path.is_absolute() {
        anyhow::bail!("operator executable search directory is not absolute")
    }
    let metadata = std::fs::symlink_metadata(path).with_context(|| {
        format!(
            "cannot inspect operator executable search directory {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("operator executable search directory is not a real directory")
    }

    let mut handles = Vec::new();
    let mut retained_paths = BTreeSet::new();
    let mut components = path.ancestors().collect::<Vec<_>>();
    components.reverse();
    for directory in components {
        let handle = open_parent_directory(directory).with_context(|| {
            format!(
                "cannot pin operator executable search directory {}",
                directory.display()
            )
        })?;
        validate_trusted_parent(&handle, directory).with_context(|| {
            format!(
                "operator executable search directory {} is not trusted",
                directory.display()
            )
        })?;
        handles.push(handle);
        retained_paths.insert(directory.to_path_buf());
    }

    const MAX_SEARCH_ENTRIES: usize = 100_000;
    let system_directory = system_executable_directory(path);
    for (index, entry) in std::fs::read_dir(path)?.enumerate() {
        if index >= MAX_SEARCH_ENTRIES {
            anyhow::bail!(
                "operator executable search directory exceeds {MAX_SEARCH_ENTRIES} entries"
            )
        }
        let entry = entry?;
        let entry_path = entry.path();
        let metadata = std::fs::symlink_metadata(&entry_path)?;
        if executable_search_entry_is_link(&metadata) {
            retain_executable_search_link_target(
                &entry_path,
                &mut handles,
                &mut retained_paths,
                untrusted_unix_user_id,
            )?;
        } else if metadata.is_file() {
            if system_directory {
                if executable_search_file_is_candidate(&metadata) {
                    // System directory membership is root-controlled, but an
                    // entry's owner can still rewrite its contents in place.
                    // Validate each executable even though retaining thousands
                    // of system binary handles would exhaust process limits.
                    drop(open_executable_search_file(
                        &entry_path,
                        untrusted_unix_user_id,
                    )?);
                }
            } else {
                let lease = lease_operator_authority_artifact(&entry_path, untrusted_unix_user_id)?;
                handles.extend(lease._handles);
            }
        } else if !metadata.is_dir() && !metadata.is_file() {
            anyhow::bail!(
                "operator executable search directory contains unsupported entry {}",
                entry_path.display()
            )
        }
    }

    Ok(OperatorAuthorityArtifactLease { _handles: handles })
}

/// Read one operator-owned authority file without creating writable sibling
/// state. The returned bytes are immutable process input: callers must not
/// retain the path as live, reloadable authority. This is for packaged
/// configuration trees that deliberately grant the daemon read access only.
pub(crate) fn load_immutable_learning_file_snapshot(path: &Path) -> Result<LearningFileSnapshot> {
    let destination = canonical_destination(path)?;
    let canonical_parent = destination
        .parent()
        .context("immutable authority file has no canonical parent")?
        .to_path_buf();
    let parent = open_parent_directory(&canonical_parent)?;
    validate_trusted_parent(&parent, &canonical_parent)?;
    let parent_identity = directory_identity(&parent)?;
    let destination = bind_destination_to_parent(&parent, &destination)?;
    if !transaction_artifacts(&destination)?.is_empty() {
        anyhow::bail!("immutable authority file has pending transaction artifacts");
    }
    ensure_regular_file(&destination)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options
        .open(&destination)
        .with_context(|| format!("failed to open immutable authority {}", path.display()))?;
    validate_authority_file(&file)?;
    let modified = file
        .metadata()
        .ok()
        .and_then(|metadata| metadata.modified().ok());
    let mut content = Vec::new();
    file.read_to_end(&mut content)
        .with_context(|| format!("failed to read immutable authority {}", path.display()))?;
    verify_open_file_binding(&file, &destination)?;
    validate_trusted_parent(&parent, &canonical_parent)?;
    if directory_identity(&parent)? != parent_identity {
        anyhow::bail!("immutable authority directory changed while it was read");
    }
    if !transaction_artifacts(&destination)?.is_empty() {
        anyhow::bail!("immutable authority transaction appeared while it was read");
    }
    Ok(LearningFileSnapshot {
        generation: Some(content_digest(&content)),
        content: Some(content),
        parent_identity,
        modified,
    })
}

/// Pin the immutable authority only long enough to compare its stable identity
/// with a proposed writable lock. This intentionally does not apply the full
/// authority-file policy: a hard-link alias must be rejected as an alias
/// before the normal immutable read reports its independently unsafe link
/// count.
fn pin_immutable_authority_for_lock_identity(path: &Path) -> Result<File> {
    let destination = canonical_destination(path)?;
    let canonical_parent = destination
        .parent()
        .context("immutable authority file has no canonical parent")?
        .to_path_buf();
    let parent = open_parent_directory(&canonical_parent)?;
    validate_trusted_parent(&parent, &canonical_parent)?;
    let destination = bind_destination_to_parent(&parent, &destination)?;
    ensure_regular_file(&destination)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(&destination)
        .with_context(|| format!("failed to pin immutable authority {}", path.display()))?;
    verify_open_file_binding(&file, &destination)?;
    Ok(file)
}

/// Read immutable authority while an independently located writable lock is
/// held. The authority path remains immutable process input; the lock only
/// coordinates startup readers and never grants a write path beside it.
pub(crate) fn load_immutable_learning_file_snapshot_with_lock(
    path: &Path,
    lock_path: &Path,
) -> Result<LearningFileSnapshot> {
    let immutable_authority = pin_immutable_authority_for_lock_identity(path)?;
    let lock = ImmutableAuthorityLock::acquire(lock_path, &immutable_authority)?;
    let snapshot = load_immutable_learning_file_snapshot(path)?;
    lock.verify_parent_binding()?;
    Ok(snapshot)
}
fn read_learning_file_snapshot_locked(lock: &DestinationLock) -> Result<LearningFileSnapshot> {
    let path = lock.destination();
    let parent_identity = lock.parent_identity()?;
    let (content, modified) = if !path_present(path)? {
        (None, None)
    } else {
        ensure_regular_file(path)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            };
            options
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let mut file = options
            .open(path)
            .with_context(|| format!("failed to open locked snapshot {}", path.display()))?;
        validate_authority_file(&file)?;
        let modified = file
            .metadata()
            .ok()
            .and_then(|metadata| metadata.modified().ok());
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .with_context(|| format!("failed to read locked snapshot {}", path.display()))?;
        verify_open_file_binding(&file, path)?;
        (Some(bytes), modified)
    };
    lock.verify_parent_binding()?;
    Ok(LearningFileSnapshot {
        generation: content.as_deref().map(content_digest),
        content,
        parent_identity,
        modified,
    })
}

fn committed_write_outcome(
    lock: &DestinationLock,
    expected_content: &[u8],
    mut warning: Option<anyhow::Error>,
) -> Result<LearningWriteOutcome> {
    let snapshot = match read_learning_file_snapshot_locked(lock) {
        Ok(snapshot) if snapshot.content() == Some(expected_content) => snapshot,
        Ok(_) => anyhow::bail!("committed authority bytes do not match the replacement candidate"),
        Err(capture_error) => {
            warning = Some(match warning {
                Some(error) => anyhow::anyhow!(
                    "{error}; the committed snapshot could not be reopened through the pinned authority namespace: {capture_error}"
                ),
                None => anyhow::anyhow!(
                    "the committed snapshot could not be reopened through the pinned authority namespace: {capture_error}"
                ),
            });
            LearningFileSnapshot {
                content: Some(expected_content.to_vec()),
                generation: Some(content_digest(expected_content)),
                parent_identity: lock.parent_identity()?,
                modified: None,
            }
        }
    };
    Ok(LearningWriteOutcome { snapshot, warning })
}

#[cfg(unix)]
fn verify_open_file_binding(file: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let held = file.metadata()?;
    let current = std::fs::symlink_metadata(path)?;
    if held.dev() != current.dev() || held.ino() != current.ino() || !current.is_file() {
        anyhow::bail!("learning destination changed during its locked read")
    }
    Ok(())
}

#[cfg(windows)]
fn verify_open_file_binding(file: &File, path: &Path) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    fn identity(file: &File) -> Result<(u32, u64)> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to inspect locked snapshot handle");
        }
        Ok((
            info.dwVolumeSerialNumber,
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        ))
    }
    let current = owner_only_options().read(true).open(path)?;
    if identity(file)? != identity(&current)? {
        anyhow::bail!("learning destination changed during its locked read")
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn verify_open_file_binding(_file: &File, _path: &Path) -> Result<()> {
    anyhow::bail!("locked snapshot identity checks are unsupported on this platform")
}

fn recover_learning_file_transaction_locked(path: &Path) -> Result<()> {
    let marker_path = learning_sibling(path, "transaction", None);
    if !path_present(&marker_path)? {
        let artifacts = transaction_artifacts(path)?;
        if artifacts.len() == 1 && is_marker_staging_artifact(path, &artifacts[0])? {
            remove_owned_precommit_artifact(&artifacts[0])?;
            sync_learning_parent(path.parent().unwrap_or_else(|| Path::new(".")))?;
            return Ok(());
        }
        if !artifacts.is_empty() {
            anyhow::bail!("untracked learning transaction artifacts require operator repair")
        }
        return Ok(());
    }
    let decoded = read_transaction_marker(&marker_path, path)?;
    let (transaction_id, candidate_generation, expected_generation) = match &decoded {
        DecodedLearningTransactionMarker::Current(marker) => (
            marker.transaction_id.clone(),
            marker.candidate_generation.clone(),
            marker.expected_generation.clone(),
        ),
        DecodedLearningTransactionMarker::Legacy {
            transaction_id,
            candidate_generation,
            expected_generation,
            ..
        } => (
            transaction_id.clone(),
            candidate_generation.clone(),
            expected_generation.clone(),
        ),
    };
    let paths = transaction_paths(path, &transaction_id)?;
    if paths.marker != marker_path {
        anyhow::bail!("transaction marker does not belong to the learning file")
    }
    let expected = [
        &paths.marker_staging,
        &paths.source,
        &paths.backup_staging,
        &paths.backup,
    ];
    for artifact in transaction_artifacts(path)? {
        if !expected.contains(&&artifact) {
            anyhow::bail!("learning transaction has an unexpected sibling artifact")
        }
        ensure_regular_file(&artifact)?;
    }
    let destination_digest = path_present(path)?.then(|| digest_file(path)).transpose()?;
    match decoded {
        DecodedLearningTransactionMarker::Legacy {
            had_destination, ..
        } => recover_legacy_transaction(
            path,
            &paths,
            destination_digest.as_deref(),
            &candidate_generation,
            expected_generation.as_deref(),
            had_destination,
        ),
        DecodedLearningTransactionMarker::Current(mut marker) => {
            recover_current_transaction(path, &paths, &mut marker, destination_digest.as_deref())
        }
    }
}

fn is_marker_staging_artifact(destination: &Path, artifact: &Path) -> Result<bool> {
    ensure_regular_file(artifact)?;
    let destination_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .context("learning destination name is not portable")?;
    let file_name = artifact
        .file_name()
        .and_then(|name| name.to_str())
        .context("learning transaction artifact name is not portable")?;
    let prefix = format!(".{destination_name}.learning-marker-");
    let Some(identity) = file_name.strip_prefix(&prefix) else {
        return Ok(false);
    };
    validate_transaction_id(identity)?;
    let paths = transaction_paths(destination, identity)?;
    if paths.marker_staging != artifact {
        anyhow::bail!("marker staging artifact is not transaction-owned")
    }
    validate_owner_only_artifact(destination, artifact)?;
    Ok(true)
}

#[cfg(unix)]
fn validate_owner_only_artifact(_destination: &Path, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        anyhow::bail!("transaction artifact permissions are unsafe")
    }
    Ok(())
}

#[cfg(windows)]
fn validate_owner_only_artifact(destination: &Path, path: &Path) -> Result<()> {
    if windows_dacl_digest(path)? != windows_dacl_digest(&destination_lock_path(destination)?)? {
        anyhow::bail!("transaction artifact DACL is not owner-only")
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn validate_owner_only_artifact(_destination: &Path, _path: &Path) -> Result<()> {
    anyhow::bail!("transaction artifact validation is unsupported on this platform")
}

fn destination_matches_expected(actual: Option<&str>, expected: Option<&str>) -> bool {
    actual == expected
}

fn remove_owned_precommit_artifact(path: &Path) -> Result<()> {
    if path_present(path)? {
        ensure_regular_file(path)?;
        remove_if_present(path)?;
    }
    Ok(())
}

fn cleanup_precommit_transaction(paths: &LearningTransactionPaths, parent: &Path) -> Result<()> {
    remove_owned_precommit_artifact(&paths.marker_staging)?;
    remove_owned_precommit_artifact(&paths.source)?;
    remove_owned_precommit_artifact(&paths.backup_staging)?;
    remove_owned_precommit_artifact(&paths.backup)?;
    sync_learning_parent(parent)?;
    remove_if_present(&paths.marker)?;
    sync_learning_parent(parent)
}

fn recover_legacy_transaction(
    path: &Path,
    paths: &LearningTransactionPaths,
    destination_generation: Option<&str>,
    candidate_generation: &str,
    expected_generation: Option<&str>,
    had_destination: bool,
) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if had_destination != expected_generation.is_some() {
        anyhow::bail!("legacy transaction has inconsistent destination state")
    }
    if destination_matches_expected(destination_generation, expected_generation) {
        return cleanup_precommit_transaction(paths, parent);
    }
    if destination_generation == Some(candidate_generation) {
        sync_replacement(path, parent)?;
        let identity = paths
            .source
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.rsplit_once('-'))
            .map(|(_, identity)| identity.to_string())
            .context("legacy transaction identity is unavailable")?;
        let mut marker = LearningTransactionMarker {
            version: LEARNING_TRANSACTION_VERSION,
            transaction_id: identity,
            phase: LearningTransactionPhase::ReplacementDurable,
            candidate_generation: candidate_generation.to_string(),
            expected_generation: expected_generation.map(str::to_string),
            expected_security_generation: None,
            expected_unix_mode: None,
        };
        persist_transaction_phase(paths, &marker)?;
        return recover_current_transaction(path, paths, &mut marker, Some(candidate_generation));
    }
    if destination_generation.is_none() && had_destination {
        restore_verified_backup(path, paths, expected_generation, None)?;
        return cleanup_precommit_transaction(paths, parent);
    }
    anyhow::bail!("legacy transaction state is ambiguous")
}

fn recover_current_transaction(
    path: &Path,
    paths: &LearningTransactionPaths,
    marker: &mut LearningTransactionMarker,
    destination_generation: Option<&str>,
) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    match marker.phase {
        LearningTransactionPhase::Preparing | LearningTransactionPhase::Ready => {
            if !destination_matches_expected(
                destination_generation,
                marker.expected_generation.as_deref(),
            ) {
                anyhow::bail!("pre-commit transaction destination generation changed")
            }
            cleanup_precommit_transaction(paths, parent)
        }
        LearningTransactionPhase::Replacing => {
            if destination_generation == Some(marker.candidate_generation.as_str()) {
                restore_replacement_metadata(path, paths, marker)?;
                sync_replacement(path, parent)?;
                marker.phase = LearningTransactionPhase::ReplacementDurable;
                persist_transaction_phase(paths, marker)?;
                recover_current_transaction(path, paths, marker, destination_generation)
            } else if destination_matches_expected(
                destination_generation,
                marker.expected_generation.as_deref(),
            ) {
                cleanup_precommit_transaction(paths, parent)
            } else if destination_generation.is_none() && marker.expected_generation.is_some() {
                restore_verified_backup(
                    path,
                    paths,
                    marker.expected_generation.as_deref(),
                    marker.expected_security_generation.as_deref(),
                )?;
                cleanup_precommit_transaction(paths, parent)
            } else {
                anyhow::bail!("replacement transaction destination generation is ambiguous")
            }
        }
        LearningTransactionPhase::ReplacementDurable => {
            if destination_generation != Some(marker.candidate_generation.as_str()) {
                anyhow::bail!("durable replacement generation is missing or changed")
            }
            restore_replacement_metadata(path, paths, marker)?;
            sync_replacement(path, parent)?;
            remove_owned_precommit_artifact(&paths.marker_staging)?;
            remove_verified_artifact(&paths.source, Some(&marker.candidate_generation))?;
            remove_owned_precommit_artifact(&paths.backup_staging)?;
            remove_verified_artifact(&paths.backup, marker.expected_generation.as_deref())?;
            sync_learning_parent(parent)?;
            marker.phase = LearningTransactionPhase::BackupRemoved;
            persist_transaction_phase(paths, marker)?;
            recover_current_transaction(path, paths, marker, destination_generation)
        }
        LearningTransactionPhase::BackupRemoved => {
            if destination_generation != Some(marker.candidate_generation.as_str()) {
                anyhow::bail!("cleanup transaction lost its durable replacement")
            }
            sync_replacement(path, parent)?;
            if path_present(&paths.backup)? {
                anyhow::bail!("cleanup phase retained an unexpected rollback backup")
            }
            remove_owned_precommit_artifact(&paths.marker_staging)?;
            remove_owned_precommit_artifact(&paths.backup_staging)?;
            remove_if_present(&paths.marker)?;
            sync_learning_parent(parent)
        }
    }
}

fn persist_transaction_phase(
    paths: &LearningTransactionPaths,
    marker: &LearningTransactionMarker,
) -> Result<()> {
    write_transaction_marker(paths, marker)?;
    sync_learning_parent(paths.marker.parent().unwrap_or_else(|| Path::new(".")))
}

#[cfg(unix)]
fn restore_replacement_metadata(
    destination: &Path,
    _paths: &LearningTransactionPaths,
    marker: &LearningTransactionMarker,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let expected = marker.expected_unix_mode.unwrap_or(0o600);
    validate_recoverable_unix_mode(expected)?;
    let actual = std::fs::metadata(destination)?.permissions().mode() & 0o7777;
    if actual != expected {
        std::fs::set_permissions(destination, std::fs::Permissions::from_mode(expected))?;
    }
    let restored = std::fs::metadata(destination)?.permissions().mode() & 0o7777;
    if restored != expected {
        anyhow::bail!("replacement file mode does not match its transaction metadata")
    }
    Ok(())
}

#[cfg(windows)]
fn restore_replacement_metadata(
    destination: &Path,
    paths: &LearningTransactionPaths,
    marker: &LearningTransactionMarker,
) -> Result<()> {
    let Some(expected_generation) = marker.expected_security_generation.as_deref() else {
        return Ok(());
    };
    if windows_dacl_generation_matches(destination, expected_generation)? {
        return Ok(());
    }
    if !path_present(&paths.backup)? {
        anyhow::bail!("replacement metadata backup is unavailable")
    }
    let (descriptor, information) = windows_security_descriptor(&paths.backup)?;
    let destination_file = open_windows_recovery_file(destination)?;
    apply_security_descriptor_to_handle(&destination_file, &descriptor, information)?;
    destination_file.sync_all()?;
    if !windows_dacl_generation_matches(destination, expected_generation)? {
        let expected = windows_dacl_generation(&paths.backup)?;
        let actual = windows_dacl_generation(destination)?;
        let expected_count = u16::from_le_bytes([expected[1], expected[2]]);
        let actual_count = u16::from_le_bytes([actual[1], actual[2]]);
        let first_difference = expected
            .iter()
            .zip(&actual)
            .position(|(left, right)| left != right)
            .map_or_else(
                || expected.len().min(actual.len()).to_string(),
                |offset| offset.to_string(),
            );
        anyhow::bail!(
            "replacement DACL does not match its transaction metadata \
             (expected {expected_count} ACEs/{expected_length} semantic bytes, \
             observed {actual_count} ACEs/{actual_length}; first difference at byte \
             {first_difference})",
            expected_length = expected.len(),
            actual_length = actual.len(),
        )
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn restore_replacement_metadata(
    _destination: &Path,
    _paths: &LearningTransactionPaths,
    _marker: &LearningTransactionMarker,
) -> Result<()> {
    anyhow::bail!("replacement metadata recovery is unsupported on this platform")
}

fn sync_replacement(path: &Path, parent: &Path) -> Result<()> {
    #[cfg(windows)]
    open_windows_recovery_file(path)?.sync_all()?;
    #[cfg(not(windows))]
    File::open(path)?.sync_all()?;
    sync_learning_parent(parent)
}

fn restore_verified_backup(
    destination: &Path,
    paths: &LearningTransactionPaths,
    expected_generation: Option<&str>,
    expected_security_generation: Option<&str>,
) -> Result<()> {
    let expected = expected_generation.context("rollback generation is missing")?;
    if !path_present(&paths.backup)? || digest_file(&paths.backup)? != expected {
        anyhow::bail!("rollback backup does not match its expected generation")
    }
    verify_windows_security_generation(&paths.backup, expected_security_generation)?;
    rename_write_through(&paths.backup, destination)?;
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    sync_replacement(destination, parent)?;
    if digest_file(destination)? != expected {
        anyhow::bail!("restored destination does not match its expected generation")
    }
    verify_windows_security_generation(destination, expected_security_generation)?;
    Ok(())
}

#[cfg(windows)]
fn verify_windows_security_generation(path: &Path, expected: Option<&str>) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if !windows_dacl_generation_matches(path, expected)? {
        anyhow::bail!("Windows rollback DACL does not match its transaction generation")
    }
    Ok(())
}

#[cfg(not(windows))]
fn verify_windows_security_generation(_path: &Path, _expected: Option<&str>) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn read_windows_dacl_descriptor(path: &Path) -> Result<Vec<u8>> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::{GetFileSecurityW, DACL_SECURITY_INFORMATION};

    let path = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut needed = 0;
    unsafe {
        GetFileSecurityW(
            path.as_ptr(),
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed == 0 {
        return Err(std::io::Error::last_os_error()).context("failed to read the Windows DACL");
    }
    let mut descriptor = vec![0u8; needed as usize];
    if unsafe {
        GetFileSecurityW(
            path.as_ptr(),
            DACL_SECURITY_INFORMATION,
            descriptor.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("failed to read the Windows DACL");
    }
    Ok(descriptor)
}

#[cfg(windows)]
fn windows_dacl_digest(path: &Path) -> Result<String> {
    Ok(content_digest(&windows_dacl_generation(path)?))
}

#[cfg(windows)]
fn windows_dacl_generation(path: &Path) -> Result<Vec<u8>> {
    use windows_sys::Win32::Security::{
        GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorDacl, IsValidAcl, ACE_HEADER,
        SE_DACL_PROTECTED,
    };

    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect Windows DACL object {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("Windows DACL generation requires a regular file")
    }
    let mut descriptor = read_windows_dacl_descriptor(path)?;
    let mut dacl_present = 0;
    let mut dacl = std::ptr::null_mut();
    let mut dacl_defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor.as_mut_ptr().cast(),
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("failed to locate the Windows DACL");
    }
    if dacl_present == 0 || dacl.is_null() {
        anyhow::bail!("Windows authority object has no bounded DACL")
    }
    if unsafe { IsValidAcl(dacl) } == 0 {
        anyhow::bail!("Windows authority object has an invalid DACL")
    }
    let descriptor_start = descriptor.as_ptr() as usize;
    let descriptor_end = descriptor_start
        .checked_add(descriptor.len())
        .context("Windows security descriptor length overflow")?;
    let dacl_start = dacl as usize;
    if dacl_start < descriptor_start || dacl_start >= descriptor_end {
        anyhow::bail!("Windows DACL lies outside its security descriptor")
    }
    let mut control = 0;
    let mut revision = 0;
    if unsafe {
        GetSecurityDescriptorControl(descriptor.as_mut_ptr().cast(), &mut control, &mut revision)
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect Windows DACL controls");
    }
    // Windows can regenerate self-relative descriptor bookkeeping and
    // inheritance routing while preserving the effective ordered file ACEs.
    // ACL allocation fields, revisions, inheritance provenance, and flags
    // that only control propagation to descendants are representation details
    // for these file objects. ACE order, trustee, type, effective access mask,
    // and inheritance protection remain authority.
    let mut normalized_aces = Vec::new();
    for index in 0..unsafe { (*dacl).AceCount } {
        let mut ace = std::ptr::null_mut();
        if unsafe { GetAce(dacl, u32::from(index), &mut ace) } == 0 || ace.is_null() {
            anyhow::bail!("failed to enumerate the Windows DACL")
        }
        let ace_size = usize::from(unsafe { (*ace.cast::<ACE_HEADER>()).AceSize });
        let ace_start = ace as usize;
        let ace_end = ace_start
            .checked_add(ace_size)
            .context("Windows ACE length overflow")?;
        if ace_size < std::mem::size_of::<ACE_HEADER>()
            || ace_start < descriptor_start
            || ace_end > descriptor_end
        {
            anyhow::bail!("Windows DACL contains an out-of-bounds ACE")
        }
        let mut ace_bytes =
            unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), ace_size) }.to_vec();
        // An inherit-only ACE does not apply to the current object. Learning
        // transaction generations cover regular files, which have no
        // descendants to receive the ACE.
        const INHERIT_ONLY_ACE: u8 = 0x08;
        if ace_bytes[1] & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        // These flags control propagation to descendants or record where an
        // ACE came from. They do not alter access to the current file.
        const FILE_INHERITANCE_FLAGS: u8 = 0x01 | 0x02 | 0x04 | 0x08 | 0x10;
        ace_bytes[1] &= !FILE_INHERITANCE_FLAGS;
        // Effective inherited file ACEs have generic access rights mapped to
        // their file-specific equivalents. Normalize the two representations
        // because they grant the same authority and Windows may choose either
        // form while applying an otherwise identical DACL.
        const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
        const ACCESS_DENIED_ACE_TYPE: u8 = 1;
        if matches!(
            ace_bytes[0],
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE
        ) && ace_bytes.len() >= 8
        {
            let mask = u32::from_le_bytes(ace_bytes[4..8].try_into().unwrap());
            let normalized = normalize_windows_file_access_mask(mask);
            ace_bytes[4..8].copy_from_slice(&normalized.to_le_bytes());
        }
        normalized_aces.push(ace_bytes);
    }
    let ace_count = u16::try_from(normalized_aces.len())
        .context("Windows DACL contains too many effective ACEs")?;
    let mut generation = Vec::new();
    generation.push(u8::from(control & SE_DACL_PROTECTED != 0));
    generation.extend_from_slice(&ace_count.to_le_bytes());
    for ace in normalized_aces {
        generation.extend_from_slice(&ace);
    }
    Ok(generation)
}

#[cfg(windows)]
fn windows_dacl_generation_difference(expected: &[u8], actual: &[u8]) -> String {
    fn header(generation: &[u8]) -> Option<(bool, u16)> {
        Some((
            *generation.first()? != 0,
            u16::from_le_bytes([*generation.get(1)?, *generation.get(2)?]),
        ))
    }

    fn ace_at(generation: &[u8], offset: usize) -> Option<&[u8]> {
        let size = usize::from(u16::from_le_bytes([
            *generation.get(offset.checked_add(2)?)?,
            *generation.get(offset.checked_add(3)?)?,
        ]));
        (size >= 4)
            .then(|| offset.checked_add(size))
            .flatten()
            .and_then(|end| generation.get(offset..end))
    }

    let Some((expected_protected, expected_count)) = header(expected) else {
        return "expected DACL generation is malformed".to_string();
    };
    let Some((actual_protected, actual_count)) = header(actual) else {
        return "observed DACL generation is malformed".to_string();
    };
    if expected_protected != actual_protected {
        return format!(
            "inheritance protection differs (expected {expected_protected}, observed {actual_protected})"
        );
    }
    if expected_count != actual_count {
        return format!(
            "effective ACE count differs (expected {expected_count}, observed {actual_count})"
        );
    }

    let mut expected_offset = 3;
    let mut actual_offset = 3;
    for index in 0..expected_count {
        let Some(expected_ace) = ace_at(expected, expected_offset) else {
            return format!("expected ACE {index} is malformed");
        };
        let Some(actual_ace) = ace_at(actual, actual_offset) else {
            return format!("observed ACE {index} is malformed");
        };
        if expected_ace != actual_ace {
            let expected_type = expected_ace[0];
            let actual_type = actual_ace[0];
            if expected_type != actual_type {
                return format!(
                    "ACE {index} type differs (expected {expected_type}, observed {actual_type})"
                );
            }
            let expected_flags = expected_ace[1];
            let actual_flags = actual_ace[1];
            if expected_flags != actual_flags {
                return format!(
                    "ACE {index} flags differ (expected 0x{expected_flags:02x}, observed 0x{actual_flags:02x})"
                );
            }
            if expected_ace.len() != actual_ace.len() {
                return format!(
                    "ACE {index} size differs (expected {}, observed {})",
                    expected_ace.len(),
                    actual_ace.len()
                );
            }
            if matches!(expected_type, 0 | 1) && expected_ace.len() >= 8 {
                let expected_mask = u32::from_le_bytes(expected_ace[4..8].try_into().unwrap());
                let actual_mask = u32::from_le_bytes(actual_ace[4..8].try_into().unwrap());
                if expected_mask != actual_mask {
                    return format!(
                        "ACE {index} access mask differs (expected 0x{expected_mask:08x}, observed 0x{actual_mask:08x})"
                    );
                }
            }
            return format!("ACE {index} trustee or type-specific body differs");
        }
        expected_offset += expected_ace.len();
        actual_offset += actual_ace.len();
    }
    if expected_offset != expected.len() || actual_offset != actual.len() {
        return format!(
            "trailing semantic bytes differ (expected {}, observed {})",
            expected.len().saturating_sub(expected_offset),
            actual.len().saturating_sub(actual_offset)
        );
    }
    "semantic DACL generations differ without a structural difference".to_string()
}

#[cfg(windows)]
fn normalize_windows_file_access_mask(mask: u32) -> u32 {
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_EXECUTE: u32 = 0x2000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const FILE_GENERIC_READ: u32 = 0x0012_0089;
    const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
    const FILE_GENERIC_EXECUTE: u32 = 0x0012_00a0;
    const FILE_ALL_ACCESS: u32 = 0x001f_01ff;

    let mut normalized = mask & !(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
    if mask & GENERIC_READ != 0 {
        normalized |= FILE_GENERIC_READ;
    }
    if mask & GENERIC_WRITE != 0 {
        normalized |= FILE_GENERIC_WRITE;
    }
    if mask & GENERIC_EXECUTE != 0 {
        normalized |= FILE_GENERIC_EXECUTE;
    }
    if mask & GENERIC_ALL != 0 {
        normalized |= FILE_ALL_ACCESS;
    }
    normalized
}

#[cfg(windows)]
fn windows_legacy_dacl_digest(path: &Path) -> Result<String> {
    Ok(content_digest(&read_windows_dacl_descriptor(path)?))
}

#[cfg(windows)]
fn windows_dacl_generation_matches(path: &Path, expected: &str) -> Result<bool> {
    // Accept interrupted transactions written by versions that hashed the
    // complete self-relative descriptor.
    Ok(windows_dacl_digest(path)? == expected || windows_legacy_dacl_digest(path)? == expected)
}

#[cfg(all(test, windows))]
pub(crate) fn authority_dacl_digest_for_test(path: &Path) -> Result<String> {
    windows_dacl_digest(path)
}

#[cfg(windows)]
fn windows_security_descriptor(path: &Path) -> Result<(Vec<u8>, u32)> {
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorControl, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
        UNPROTECTED_DACL_SECURITY_INFORMATION,
    };
    let mut descriptor = read_windows_dacl_descriptor(path)?;
    let mut control = 0;
    let mut revision = 0;
    if unsafe {
        GetSecurityDescriptorControl(descriptor.as_mut_ptr().cast(), &mut control, &mut revision)
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect Windows DACL controls");
    }
    let protection = if control & SE_DACL_PROTECTED != 0 {
        PROTECTED_DACL_SECURITY_INFORMATION
    } else {
        UNPROTECTED_DACL_SECURITY_INFORMATION
    };
    Ok((descriptor, DACL_SECURITY_INFORMATION | protection))
}

fn remove_verified_artifact(path: &Path, expected_digest: Option<&str>) -> Result<()> {
    if !path_present(path)? {
        return Ok(());
    }
    let Some(expected_digest) = expected_digest else {
        anyhow::bail!("refusing to remove an unverified transaction artifact")
    };
    if digest_file(path)? != expected_digest {
        anyhow::bail!("transaction artifact digest does not match its marker")
    }
    remove_if_present(path)
}

fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

#[cfg(unix)]
fn rename_write_through(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}

#[cfg(windows)]
fn rename_write_through(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let wide = |value: &std::ffi::OsStr| {
        value
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>()
    };
    let source = wide(source.as_os_str());
    let destination = wide(destination.as_os_str());
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
fn rename_write_through(_source: &Path, _destination: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "durable rename is unsupported",
    ))
}

#[cfg(unix)]
fn sync_learning_parent(parent: &Path) -> Result<()> {
    sync_parent_directory(parent)
}

#[cfg(windows)]
fn sync_learning_parent(_parent: &Path) -> Result<()> {
    // Windows has no directory fsync contract. File replacement and recovery
    // flush destination handles explicitly; phase and recovery publication use
    // write-through moves to order the journal around those flushes.
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_learning_parent(_parent: &Path) -> Result<()> {
    anyhow::bail!("learning-file durability is unsupported on this platform")
}

#[cfg(unix)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn write_learning_file_atomically(
    path: &Path,
    content: &str,
) -> Result<LearningWriteOutcome> {
    write_learning_file_atomically_with_sync(path, content, sync_parent_directory)
}

#[cfg(unix)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn write_learning_file_atomically_if_unchanged(
    path: &Path,
    expected: &[u8],
    content: &str,
) -> Result<LearningWriteOutcome> {
    write_learning_file_atomically_with_sync_and_expected(
        path,
        Some(Some(expected)),
        None,
        content,
        sync_parent_directory,
    )
}

#[cfg(windows)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn write_learning_file_atomically(
    path: &Path,
    content: &str,
) -> Result<LearningWriteOutcome> {
    write_learning_file_atomically_windows(path, None, None, content)
}

#[cfg(windows)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn write_learning_file_atomically_if_unchanged(
    path: &Path,
    expected: &[u8],
    content: &str,
) -> Result<LearningWriteOutcome> {
    write_learning_file_atomically_windows(path, Some(Some(expected)), None, content)
}

#[cfg(unix)]
pub(crate) fn write_learning_file_atomically_for_locked_snapshot(
    path: &Path,
    expected: &LearningFileSnapshot,
    content: &str,
) -> Result<LearningWriteOutcome> {
    write_learning_file_atomically_with_sync_and_expected(
        path,
        Some(expected.content()),
        Some(&expected.parent_identity),
        content,
        sync_parent_directory,
    )
}

#[cfg(windows)]
pub(crate) fn write_learning_file_atomically_for_locked_snapshot(
    path: &Path,
    expected: &LearningFileSnapshot,
    content: &str,
) -> Result<LearningWriteOutcome> {
    write_learning_file_atomically_windows(
        path,
        Some(expected.content()),
        Some(&expected.parent_identity),
        content,
    )
}

#[cfg(not(any(unix, windows)))]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn write_learning_file_atomically(
    _path: &Path,
    _content: &str,
) -> Result<LearningWriteOutcome> {
    anyhow::bail!("atomic learning-file durability is unsupported on this platform")
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn write_learning_file_atomically_if_unchanged(
    _path: &Path,
    _expected: &[u8],
    _content: &str,
) -> Result<LearningWriteOutcome> {
    anyhow::bail!("atomic learning-file durability is unsupported on this platform")
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn write_learning_file_atomically_for_locked_snapshot(
    _path: &Path,
    _expected: &LearningFileSnapshot,
    _content: &str,
) -> Result<LearningWriteOutcome> {
    anyhow::bail!("atomic learning-file durability is unsupported on this platform")
}

#[cfg(any(unix, test))]
#[cfg_attr(not(test), allow(dead_code))]
fn write_learning_file_atomically_with_sync<F>(
    path: &Path,
    content: &str,
    sync_directory: F,
) -> Result<LearningWriteOutcome>
where
    F: FnMut(&Path) -> Result<()>,
{
    write_learning_file_atomically_with_sync_and_expected(path, None, None, content, sync_directory)
}

#[cfg(any(unix, test))]
fn write_learning_file_atomically_with_sync_and_expected<F>(
    path: &Path,
    expected: Option<Option<&[u8]>>,
    expected_parent: Option<&DirectoryIdentity>,
    content: &str,
    mut sync_directory: F,
) -> Result<LearningWriteOutcome>
where
    F: FnMut(&Path) -> Result<()>,
{
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    ensure_durable_directory(parent, &mut sync_directory)?;
    let lock = DestinationLock::acquire(path)?;
    let path = lock.destination();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    lock.verify_parent_binding()?;
    recover_learning_file_transaction_locked(path)?;
    if let Some(expected_parent) = expected_parent {
        if lock.parent_identity()? != *expected_parent {
            return Err(snapshot_conflict());
        }
    }
    let current = read_learning_file_snapshot_locked(&lock)?;
    if let Some(expected) = expected {
        if current.content() != expected {
            return Err(snapshot_conflict());
        }
    }
    let identity = format!("{:032x}", rand::random::<u128>());
    let paths = transaction_paths(path, &identity)?;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    let original_mode = std::fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions().mode() & 0o7777);
    #[cfg(unix)]
    if let Some(mode) = original_mode {
        validate_recoverable_unix_mode(mode)?;
    }
    #[cfg(not(unix))]
    let original_mode = None;
    let original_sha256 = path.exists().then(|| digest_file(path)).transpose()?;
    let mut marker = LearningTransactionMarker {
        version: LEARNING_TRANSACTION_VERSION,
        transaction_id: identity,
        phase: LearningTransactionPhase::Preparing,
        candidate_generation: content_digest(content.as_bytes()),
        expected_generation: original_sha256.clone(),
        expected_security_generation: None,
        expected_unix_mode: original_mode,
    };
    lock.verify_parent_binding()?;
    write_transaction_marker(&paths, &marker)?;
    sync_directory(parent)
        .with_context(|| format!("failed to sync parent directory {}", parent.display()))?;
    let mut temporary = open_owner_only_new(&paths.source)
        .with_context(|| format!("failed to create temporary file in {}", parent.display()))?;
    temporary
        .write_all(content.as_bytes())
        .with_context(|| format!("failed to write temporary file for {}", path.display()))?;
    temporary
        .sync_all()
        .with_context(|| format!("failed to sync temporary file for {}", path.display()))?;
    if path.exists() {
        copy_file_owner_only(path, &paths.backup)
            .with_context(|| format!("failed to create recovery backup for {}", path.display()))?;
        if original_sha256.as_deref() != Some(digest_file(&paths.backup)?.as_str()) {
            anyhow::bail!("learning transaction backup digest changed during creation")
        }
        sync_directory(parent)
            .with_context(|| format!("failed to sync recovery backup for {}", path.display()))?;
    }
    marker.phase = LearningTransactionPhase::Ready;
    write_transaction_marker(&paths, &marker)?;
    sync_directory(parent).with_context(|| {
        format!(
            "failed to sync ready transaction phase in {}",
            parent.display()
        )
    })?;
    marker.phase = LearningTransactionPhase::Replacing;
    write_transaction_marker(&paths, &marker)?;
    sync_directory(parent).with_context(|| {
        format!(
            "failed to sync replacing transaction phase in {}",
            parent.display()
        )
    })?;
    lock.verify_parent_binding()?;
    drop(temporary);
    if let Err(error) = rename_write_through(&paths.source, path) {
        let recovery = recover_learning_file_transaction_locked(path);
        return match recovery {
            Ok(())
                if digest_file(path).ok().as_deref()
                    == Some(marker.candidate_generation.as_str()) =>
            {
                committed_write_outcome(
                    &lock,
                    content.as_bytes(),
                    Some(anyhow::Error::new(error).context(format!(
                        "replacement reported failure after committing {}",
                        path.display()
                    ))),
                )
            }
            Ok(()) => Err(error).with_context(|| format!("failed to replace {}", path.display())),
            Err(recovery_error) => anyhow::bail!(
                "failed to replace {} and recovery failed: {} (replacement error: {})",
                path.display(),
                recovery_error,
                error
            ),
        };
    }
    if let Err(error) = restore_replacement_metadata(path, &paths, &marker)
        .and_then(|()| std::fs::File::open(path)?.sync_all().map_err(Into::into))
        .with_context(|| format!("failed to restore metadata for {}", path.display()))
    {
        return committed_write_outcome(&lock, content.as_bytes(), Some(error));
    }
    if let Err(error) = sync_directory(parent)
        .with_context(|| format!("failed to sync parent directory {}", parent.display()))
    {
        return committed_write_outcome(&lock, content.as_bytes(), Some(error));
    }
    if let Err(error) = lock.verify_parent_binding() {
        return committed_write_outcome(&lock, content.as_bytes(), Some(error));
    }
    marker.phase = LearningTransactionPhase::ReplacementDurable;
    if let Err(error) = write_transaction_marker(&paths, &marker)
        .and_then(|()| sync_directory(parent))
        .context("failed to persist durable replacement phase")
    {
        return committed_write_outcome(&lock, content.as_bytes(), Some(error));
    }
    if let Err(error) = remove_verified_artifact(&paths.backup, original_sha256.as_deref())
        .and_then(|()| {
            sync_directory(parent).with_context(|| {
                format!(
                    "failed to sync recovery-backup cleanup in {}",
                    parent.display()
                )
            })
        })
    {
        return committed_write_outcome(&lock, content.as_bytes(), Some(error));
    }
    marker.phase = LearningTransactionPhase::BackupRemoved;
    if let Err(error) = write_transaction_marker(&paths, &marker)
        .and_then(|()| sync_directory(parent))
        .context("failed to persist rollback-cleanup phase")
    {
        return committed_write_outcome(&lock, content.as_bytes(), Some(error));
    }
    if let Err(error) = remove_if_present(&paths.marker).and_then(|()| {
        sync_directory(parent).with_context(|| {
            format!(
                "failed to sync transaction-marker cleanup in {}",
                parent.display()
            )
        })
    }) {
        return committed_write_outcome(&lock, content.as_bytes(), Some(error));
    }
    committed_write_outcome(&lock, content.as_bytes(), None)
}

fn copy_file_owner_only(source: &Path, destination: &Path) -> Result<()> {
    ensure_regular_file(source)?;
    let mut input = OpenOptions::new().read(true).open(source)?;
    let mut output = open_owner_only_new(destination)?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

#[cfg(any(unix, test))]
fn ensure_durable_directory<F>(directory: &Path, sync_directory: &mut F) -> Result<()>
where
    F: FnMut(&Path) -> Result<()>,
{
    if directory.is_dir() {
        return Ok(());
    }
    let mut missing = Vec::new();
    let mut cursor = directory;
    while !cursor.as_os_str().is_empty() && !cursor.is_dir() {
        missing.push(cursor.to_path_buf());
        cursor = cursor.parent().unwrap_or_else(|| Path::new("."));
    }
    for created in missing.into_iter().rev() {
        #[cfg(unix)]
        let create = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700).create(&created)
        };
        #[cfg(not(unix))]
        let create = std::fs::create_dir(&created);
        match create {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to create {}", created.display()))
            }
        }
        sync_directory(&created)
            .with_context(|| format!("failed to sync new directory {}", created.display()))?;
        let containing = created
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        sync_directory(containing).with_context(|| {
            format!(
                "failed to sync directory entry for {} in {}",
                created.display(),
                containing.display()
            )
        })?;
    }
    Ok(())
}

/// Preserve an unreadable learning file under a unique sibling name without
/// removing the authoritative path. Callers still fail closed, while the exact
/// bytes remain available for repair.
pub(crate) fn preserve_corrupt_learning_file(path: &Path, content: &[u8]) -> Result<PathBuf> {
    if content.len() > MAX_CORRUPT_RECOVERY_BYTES {
        anyhow::bail!(
            "corrupt learning state exceeds the bounded recovery-copy size; the original remains in place"
        );
    }
    let lock = DestinationLock::acquire(path)?;
    let path = lock.destination();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let base = format!(
        ".{}.corrupt-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("learning"),
        content_digest(content)
    );
    let preserved = parent.join(format!("{base}.recovery"));
    let stable_preserved = lock.canonical_parent.join(format!("{base}.recovery"));
    if preserved.exists() {
        let verified = std::fs::read(&preserved)?;
        if verified == content {
            preserve_recovery_metadata(path, &preserved)?;
            lock.verify_parent_binding()?;
            return Ok(stable_preserved);
        }
        anyhow::bail!("content-addressed corrupt-state copy does not match its digest")
    }
    let prefix = format!(
        ".{}.corrupt-",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("learning")
    );
    let retained = std::fs::read_dir(parent)?
        .filter_map(std::result::Result::ok)
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with(&prefix) && name.ends_with(".recovery")
        })
        .count();
    if retained >= MAX_CORRUPT_RECOVERY_FILES {
        anyhow::bail!(
            "corrupt-state recovery-copy bound is full; the unique original remains in place"
        );
    }
    let mut file = open_owner_only_new(&preserved).with_context(|| {
        format!(
            "failed to create corrupt-state copy in {}",
            parent.display()
        )
    })?;
    file.write_all(content)
        .with_context(|| format!("failed to preserve corrupt state for {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync corrupt-state copy for {}", path.display()))?;
    drop(file);
    preserve_recovery_metadata(path, &preserved)?;
    #[cfg(unix)]
    sync_parent_directory(parent).with_context(|| {
        format!(
            "failed to sync corrupt-state directory {}",
            parent.display()
        )
    })?;
    let verified = std::fs::read(&preserved).with_context(|| {
        format!(
            "failed to verify corrupt-state copy {}",
            preserved.display()
        )
    })?;
    if verified != content {
        anyhow::bail!(
            "corrupt-state copy {} did not preserve the source bytes",
            preserved.display()
        );
    }
    lock.verify_parent_binding()?;
    Ok(stable_preserved)
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> Result<()> {
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn write_learning_file_atomically_windows(
    path: &Path,
    expected: Option<Option<&[u8]>>,
    expected_parent: Option<&DirectoryIdentity>,
    content: &str,
) -> Result<LearningWriteOutcome> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::{
        GetFileSecurityW, GetSecurityDescriptorControl, SetFileSecurityW,
        DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
        UNPROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, ReplaceFileW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn security_information() -> u32 {
        DACL_SECURITY_INFORMATION
    }

    fn read_security_descriptor(path: &Path) -> Result<(Vec<u8>, u32)> {
        let path = wide(path.as_os_str());
        let information = security_information();
        let mut needed = 0;
        unsafe {
            GetFileSecurityW(
                path.as_ptr(),
                information,
                std::ptr::null_mut(),
                0,
                &mut needed,
            );
        }
        if needed == 0 {
            return Err(std::io::Error::last_os_error()).context("failed to read the Windows DACL");
        }
        let mut descriptor = vec![0u8; needed as usize];
        let loaded = unsafe {
            GetFileSecurityW(
                path.as_ptr(),
                information,
                descriptor.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        };
        if loaded == 0 {
            return Err(std::io::Error::last_os_error()).context("failed to read the Windows DACL");
        }
        let mut control = 0;
        let mut revision = 0;
        if unsafe {
            GetSecurityDescriptorControl(
                descriptor.as_mut_ptr().cast(),
                &mut control,
                &mut revision,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error())
                .context("failed to inspect Windows security descriptor controls");
        }
        let mut set_information = information;
        if control & SE_DACL_PROTECTED != 0 {
            set_information |= PROTECTED_DACL_SECURITY_INFORMATION;
        } else {
            set_information |= UNPROTECTED_DACL_SECURITY_INFORMATION;
        }
        Ok((descriptor, set_information))
    }

    fn apply_security_descriptor(path: &Path, descriptor: &[u8], information: u32) -> Result<()> {
        let path = wide(path.as_os_str());
        let mut descriptor = descriptor.to_vec();
        if unsafe { SetFileSecurityW(path.as_ptr(), information, descriptor.as_mut_ptr().cast()) }
            == 0
        {
            return Err(std::io::Error::last_os_error())
                .context("failed to apply the Windows DACL");
        }
        Ok(())
    }

    fn read_owner_and_group(path: &Path) -> Result<Vec<u8>> {
        let path = wide(path.as_os_str());
        let information = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;
        let mut needed = 0;
        unsafe {
            GetFileSecurityW(
                path.as_ptr(),
                information,
                std::ptr::null_mut(),
                0,
                &mut needed,
            );
        }
        if needed == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to read the Windows owner and group");
        }
        let mut descriptor = vec![0u8; needed as usize];
        if unsafe {
            GetFileSecurityW(
                path.as_ptr(),
                information,
                descriptor.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error())
                .context("failed to read the Windows owner and group");
        }
        Ok(descriptor)
    }

    fn move_with_write_through(
        source: &Path,
        destination: &Path,
        replace: bool,
    ) -> std::io::Result<()> {
        let source = wide(source.as_os_str());
        let destination = wide(destination.as_os_str());
        let flags = MOVEFILE_WRITE_THROUGH
            | if replace {
                MOVEFILE_REPLACE_EXISTING
            } else {
                0
            };
        if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), flags) } == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    let lock = DestinationLock::acquire(path)?;
    let path = lock.destination();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    lock.verify_parent_binding()?;
    recover_learning_file_transaction_locked(path)?;
    if let Some(expected_parent) = expected_parent {
        if lock.parent_identity()? != *expected_parent {
            return Err(snapshot_conflict());
        }
    }
    let current = read_learning_file_snapshot_locked(&lock)?;
    if let Some(expected) = expected {
        if current.content() != expected {
            return Err(snapshot_conflict());
        }
    }
    let destination_exists = path.exists();
    if destination_exists {
        ensure_windows_owner_group_compatible(
            &read_owner_and_group(path)?,
            &read_owner_and_group(&destination_lock_path(path)?)?,
        )?;
    }
    let expected_security = if destination_exists {
        Some(read_security_descriptor(path).with_context(|| {
            format!(
                "cannot safely replace existing learning file {}",
                path.display()
            )
        })?)
    } else {
        None
    };
    let identity = format!("{:032x}", rand::random::<u128>());
    let paths = transaction_paths(path, &identity)?;
    let original_generation = destination_exists.then(|| digest_file(path)).transpose()?;
    let expected_security_generation = destination_exists
        .then(|| windows_dacl_generation(path))
        .transpose()?;
    let mut marker = LearningTransactionMarker {
        version: LEARNING_TRANSACTION_VERSION,
        transaction_id: identity,
        phase: LearningTransactionPhase::Preparing,
        candidate_generation: content_digest(content.as_bytes()),
        expected_generation: original_generation.clone(),
        expected_security_generation: expected_security_generation
            .as_ref()
            .map(|generation| content_digest(generation)),
        expected_unix_mode: None,
    };
    lock.verify_parent_binding()?;
    write_transaction_marker(&paths, &marker)?;
    let mut temporary = open_owner_only_new(&paths.source)
        .with_context(|| format!("failed to create temporary file in {}", parent.display()))?;
    if let Some((descriptor, information)) = &expected_security {
        // Prove that the non-elevated writer can restore the destination DACL
        // before publishing sensitive bytes. The temporary file returns to an
        // owner-only DACL for the write and replacement. ReplaceFileW retains
        // the destination metadata; the accessible DACL is verified after the
        // replacement. Owner and group are never set, and SACL access is
        // neither requested nor claimed.
        apply_security_descriptor_to_handle(&temporary, descriptor, *information).with_context(
            || {
                format!(
                    "cannot preserve security for learning file {}",
                    path.display()
                )
            },
        )?;
        apply_owner_only_windows_dacl_to_handle(&temporary)?;
    }
    temporary
        .write_all(content.as_bytes())
        .with_context(|| format!("failed to write temporary file for {}", path.display()))?;
    temporary
        .sync_all()
        .with_context(|| format!("failed to sync temporary file for {}", path.display()))?;
    if destination_exists {
        copy_file_owner_only(path, &paths.backup_staging)?;
        if let Some((descriptor, information)) = &expected_security {
            apply_security_descriptor(&paths.backup_staging, descriptor, *information)
                .with_context(|| {
                    format!("failed to preserve backup security for {}", path.display())
                })?;
        }
        if original_generation.as_deref() != Some(digest_file(&paths.backup_staging)?.as_str()) {
            anyhow::bail!("learning transaction backup digest changed during creation")
        }
        verify_windows_security_generation(
            &paths.backup_staging,
            marker.expected_security_generation.as_deref(),
        )?;
        move_with_write_through(&paths.backup_staging, &paths.backup, false)
            .with_context(|| format!("failed to publish recovery backup for {}", path.display()))?;
    }
    marker.phase = LearningTransactionPhase::Ready;
    write_transaction_marker(&paths, &marker)?;
    marker.phase = LearningTransactionPhase::Replacing;
    write_transaction_marker(&paths, &marker)?;
    lock.verify_parent_binding()?;
    drop(temporary);
    let replacement = if destination_exists {
        // ReplaceFileW provides the documented metadata-preserving replacement
        // primitive. This implementation independently verifies the accessible
        // DACL after replacement and preflights equal owner/group identities.
        // It does not request ACCESS_SYSTEM_SECURITY or inspect the SACL.
        let destination_wide = wide(path.as_os_str());
        let source_wide = wide(paths.source.as_os_str());
        if unsafe {
            ReplaceFileW(
                destination_wide.as_ptr(),
                source_wide.as_ptr(),
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } == 0
        {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    } else {
        move_with_write_through(&paths.source, path, false)
    };
    if let Err(replacement_error) = replacement {
        let recovery = recover_learning_file_transaction_locked(path);
        return match recovery {
            Ok(())
                if digest_file(path).ok().as_deref()
                    == Some(marker.candidate_generation.as_str()) =>
            {
                committed_write_outcome(
                    &lock,
                    content.as_bytes(),
                    Some(anyhow::Error::new(replacement_error).context(format!(
                        "replacement reported failure after committing {}",
                        path.display()
                    ))),
                )
            }
            Ok(()) => Err(replacement_error)
                .with_context(|| format!("failed to replace {}", path.display())),
            Err(recovery_error) => anyhow::bail!(
                "failed to replace {} and recovery failed: {} (replacement error: {})",
                path.display(),
                recovery_error,
                replacement_error
            ),
        };
    }
    let finalize = (|| -> Result<()> {
        // ReplaceFileW's write-through flag is unsupported. Flushing a newly
        // opened destination handle provides file-level durability. Windows
        // does not expose a portable directory fsync.
        let destination_file = open_windows_recovery_file(path)
            .with_context(|| format!("failed to reopen replaced file {}", path.display()))?;
        destination_file
            .sync_all()
            .with_context(|| format!("failed to flush replaced file {}", path.display()))?;
        if let Some((expected, information)) = &expected_security {
            let expected_generation = marker
                .expected_security_generation
                .as_deref()
                .context("replacement DACL generation is missing")?;
            if !windows_dacl_generation_matches(path, expected_generation)? {
                apply_security_descriptor_to_handle(&destination_file, expected, *information)
                    .with_context(|| {
                        format!("failed to restore security for {}", path.display())
                    })?;
                destination_file.sync_all()?;
                if !windows_dacl_generation_matches(path, expected_generation)? {
                    let actual_generation = windows_dacl_generation(path)?;
                    let difference = windows_dacl_generation_difference(
                        expected_security_generation
                            .as_deref()
                            .context("replacement DACL generation bytes are missing")?,
                        &actual_generation,
                    );
                    anyhow::bail!(
                        "replacement changed the Windows security descriptor for {}: {}",
                        path.display(),
                        difference
                    );
                }
            }
        }
        Ok(())
    })();
    if let Err(finalize_error) = finalize {
        // ReplaceFileW has committed the destination at this point. Keep the
        // marker and backup for restart recovery, report the late failure as a
        // committed outcome, and let callers adopt the exact candidate now on
        // disk instead of retaining stale in-memory authority.
        return committed_write_outcome(&lock, content.as_bytes(), Some(finalize_error));
    }
    if let Err(error) = lock.verify_parent_binding() {
        return committed_write_outcome(&lock, content.as_bytes(), Some(error));
    }
    marker.phase = LearningTransactionPhase::ReplacementDurable;
    if let Err(error) = write_transaction_marker(&paths, &marker) {
        return committed_write_outcome(
            &lock,
            content.as_bytes(),
            Some(error.context("failed to persist durable replacement phase")),
        );
    }
    if let Err(error) =
        remove_verified_artifact(&paths.backup, marker.expected_generation.as_deref())
    {
        return committed_write_outcome(&lock, content.as_bytes(), Some(error));
    }
    marker.phase = LearningTransactionPhase::BackupRemoved;
    if let Err(error) = write_transaction_marker(&paths, &marker) {
        return committed_write_outcome(
            &lock,
            content.as_bytes(),
            Some(error.context("failed to persist rollback-cleanup phase")),
        );
    }
    if let Err(error) = remove_if_present(&paths.marker) {
        return committed_write_outcome(&lock, content.as_bytes(), Some(error));
    }
    committed_write_outcome(
        &lock,
        content.as_bytes(),
        Some(anyhow::anyhow!(
            "Windows flushes replacement content and publishes transaction phases with write-through moves, but does not expose independent directory-entry flush confirmation"
        )),
    )
}

pub(crate) fn sanitize_learning_text(value: &str) -> String {
    redact_output_text(value)
}

#[derive(Debug, Clone)]
pub struct LearningConfig {
    pub path: PathBuf,
    pub min_approvals: u32,
    pub max_risk: i32,
    pub auto_shim: AutoShimMode,
}

impl LearningConfig {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            min_approvals: 2,
            max_risk: 2,
            auto_shim: AutoShimMode::Suggest,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoShimMode {
    Off,
    Suggest,
    Create,
}

impl AutoShimMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "false" | "0" | "none" => Some(Self::Off),
            "suggest" | "hint" | "true" | "1" => Some(Self::Suggest),
            "create" | "auto" => Some(Self::Create),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Suggest => "suggest",
            Self::Create => "create",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LearningOutcome {
    pub service: String,
    pub pattern: String,
    pub approvals: u32,
    pub required_approvals: u32,
    /// True once `approvals >= required_approvals`. This means the pattern is
    /// ready for operator review, NOT that it can now skip the LLM -- nothing
    /// in this module grants a bypass. See the module docs.
    pub is_candidate: bool,
    pub shim: Option<LearnedShim>,
    pub skipped_reason: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearnedRulesFile {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub observations: BTreeMap<String, LearnedObservation>,
    #[serde(default)]
    pub rules: Vec<LearnedRule>,
}

fn default_version() -> u32 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearnedObservation {
    pub service: String,
    pub pattern: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub equivalent_patterns: Vec<String>,
    pub approvals: u32,
    pub max_risk_seen: i32,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub last_command: String,
    pub last_reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shim: Option<LearnedShim>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearnedRule {
    pub service: String,
    pub pattern: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub equivalent_patterns: Vec<String>,
    pub approvals: u32,
    pub max_risk_seen: i32,
    pub promoted_at_unix: u64,
    pub updated_at_unix: u64,
    pub last_reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shim: Option<LearnedShim>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearnedShim {
    pub name: String,
    pub target_binary: String,
    pub target_args: Vec<String>,
    pub description: String,
}

impl LearnedShim {
    pub fn render_command(&self) -> String {
        let mut parts = Vec::with_capacity(self.target_args.len() + 1);
        parts.push(self.target_binary.clone());
        parts.extend(self.target_args.clone());
        parts.join(" ")
    }
}

#[derive(Debug, Clone)]
pub struct LearnedRuleStore {
    config: LearningConfig,
    data: LearnedRulesFile,
    snapshot: LearningFileSnapshot,
}

impl LearnedRuleStore {
    pub fn load(config: LearningConfig) -> Result<Self> {
        let path = config.path.clone();
        let (data, snapshot, warning) = rewrite_learning_file_bounded(&path, |snapshot| {
            let mut data = parse_learned_rules_snapshot(snapshot, &path)?;
            let original_observations = data.observations.len();
            let original_rules = data.rules.len();
            data.observations.retain(|_, observation| {
                !learned_observation_contains_sensitive_literals(observation)
            });
            data.rules
                .retain(|rule| !learned_rule_contains_sensitive_literals(rule));
            let mut changed = original_observations != data.observations.len()
                || original_rules != data.rules.len();
            changed |= sanitize_learned_rules_prose(&mut data);
            let content = changed
                .then(|| serde_yaml_ng::to_string(&data))
                .transpose()?;
            Ok((content, data))
        })?;
        if let Some(error) = warning {
            tracing::warn!("learning-file cleanup committed with a durability warning: {error}");
        }
        Ok(Self {
            config,
            data,
            snapshot,
        })
    }

    pub fn path(&self) -> &Path {
        &self.config.path
    }

    pub fn min_approvals(&self) -> u32 {
        self.config.min_approvals
    }

    pub fn max_risk(&self) -> i32 {
        self.config.max_risk
    }

    pub fn auto_shim(&self) -> AutoShimMode {
        self.config.auto_shim
    }

    pub fn rule_count(&self) -> usize {
        self.data.rules.len()
    }

    pub fn record_approval(
        &mut self,
        binary: &str,
        args: &[String],
        command: &str,
        risk: Option<i32>,
        reason: &str,
    ) -> Result<Option<LearningOutcome>> {
        let config = self.config.clone();
        let mut first = Some(self.clone());
        let (current, outcome) = retry_learning_snapshot_conflicts(|| {
            let mut current = match first.take() {
                Some(current) => current,
                None => Self::load(config.clone())?,
            };
            let mut candidate = current.clone();
            let outcome =
                candidate.record_approval_in_memory(binary, args, command, risk, reason)?;
            current.commit_candidate(candidate.data)?;
            Ok((current, outcome))
        })?;
        *self = current;
        Ok(outcome)
    }

    fn record_approval_in_memory(
        &mut self,
        binary: &str,
        args: &[String],
        command: &str,
        risk: Option<i32>,
        reason: &str,
    ) -> Result<Option<LearningOutcome>> {
        if command_contains_sensitive_literals(binary, args) {
            return Ok(None);
        }
        let command_metadata = crate::redact::command_metadata(binary, args);
        let risk = risk.unwrap_or(5);
        if risk > self.config.max_risk {
            return Ok(Some(LearningOutcome {
                service: binary.to_string(),
                pattern: command_metadata,
                approvals: 0,
                required_approvals: self.config.min_approvals,
                is_candidate: false,
                shim: None,
                skipped_reason: Some(format!(
                    "risk {risk} exceeds max learned-rule risk {}",
                    self.config.max_risk
                )),
            }));
        }
        if looks_dangerous_for_learned_allow(command) {
            return Ok(Some(LearningOutcome {
                service: binary.to_string(),
                pattern: command_metadata,
                approvals: 0,
                required_approvals: self.config.min_approvals,
                is_candidate: false,
                shim: None,
                skipped_reason: Some("command contains shell-control or destructive tokens".into()),
            }));
        }

        let candidate = RuleCandidate::from_command(binary, args, command);
        let reason = sanitize_learning_text(reason);
        let now = now_unix();
        let key = candidate.key();
        let observation = self
            .data
            .observations
            .entry(key)
            .or_insert_with(|| LearnedObservation {
                service: candidate.service.clone(),
                pattern: candidate.pattern.clone(),
                equivalent_patterns: candidate.equivalent_patterns.clone(),
                approvals: 0,
                max_risk_seen: risk,
                first_seen_unix: now,
                last_seen_unix: now,
                last_command: command_metadata.clone(),
                last_reason: reason.clone(),
                shim: candidate.shim.clone(),
            });

        observation.approvals = observation.approvals.saturating_add(1);
        observation.max_risk_seen = observation.max_risk_seen.max(risk);
        observation.last_seen_unix = now;
        observation.last_command = command_metadata;
        observation.last_reason = reason.clone();
        observation.shim = candidate.shim.clone();
        observation.equivalent_patterns = candidate.equivalent_patterns.clone();

        let approvals = observation.approvals;
        let is_candidate = approvals >= self.config.min_approvals;
        if is_candidate {
            if let Some(rule) = self
                .data
                .rules
                .iter_mut()
                .find(|rule| rule.pattern == candidate.pattern)
            {
                rule.approvals = approvals;
                rule.equivalent_patterns = candidate.equivalent_patterns.clone();
                rule.max_risk_seen = observation.max_risk_seen;
                rule.updated_at_unix = now;
                rule.last_reason = reason.clone();
                rule.shim = candidate.shim.clone();
            } else {
                self.data.rules.push(LearnedRule {
                    service: candidate.service.clone(),
                    pattern: candidate.pattern.clone(),
                    equivalent_patterns: candidate.equivalent_patterns.clone(),
                    approvals,
                    max_risk_seen: observation.max_risk_seen,
                    promoted_at_unix: now,
                    updated_at_unix: now,
                    last_reason: reason.clone(),
                    shim: candidate.shim.clone(),
                });
            }
        }

        Ok(Some(LearningOutcome {
            service: candidate.service,
            pattern: candidate.pattern,
            approvals,
            required_approvals: self.config.min_approvals,
            is_candidate,
            shim: candidate.shim,
            skipped_reason: None,
        }))
    }

    fn commit_candidate(&mut self, candidate: LearnedRulesFile) -> Result<()> {
        if candidate == self.data {
            return Ok(());
        }
        let outcome = self.save_data(&candidate)?;
        let (committed, warning) = outcome.into_parts();
        self.data = candidate;
        self.snapshot = committed;
        if let Some(error) = warning {
            tracing::warn!(
                "learning-file replacement committed with a durability warning: {}",
                error
            );
        }
        Ok(())
    }

    fn save_data(&self, data: &LearnedRulesFile) -> Result<LearningWriteOutcome> {
        let content = self.canonical_content(data)?;
        write_learning_file_atomically_for_locked_snapshot(
            &self.config.path,
            &self.snapshot,
            &content,
        )
    }

    fn canonical_content(&self, data: &LearnedRulesFile) -> Result<String> {
        let mut data = data.clone();
        sanitize_learned_rules_prose(&mut data);
        Ok(serde_yaml_ng::to_string(&data)?)
    }
}

impl AsyncDurableStore for LearnedRuleStore {
    fn authority_name(&self) -> &'static str {
        "learned-rule"
    }

    fn durable_path(&self) -> Option<&Path> {
        Some(&self.config.path)
    }

    fn same_durable_snapshot(&self, snapshot: &LearningFileSnapshot) -> bool {
        self.snapshot.same_authority(snapshot)
    }

    fn same_in_memory_epoch(&self, other: &Self) -> bool {
        self.snapshot.same_authority(&other.snapshot) && self.data == other.data
    }
}

fn parse_learned_rules_snapshot(
    snapshot: &LearningFileSnapshot,
    path: &Path,
) -> Result<LearnedRulesFile> {
    let Some(content) = snapshot.content() else {
        return Ok(LearnedRulesFile::default());
    };
    let content =
        std::str::from_utf8(content).with_context(|| format!("{} is not UTF-8", path.display()))?;
    if content.trim().is_empty() {
        Ok(LearnedRulesFile::default())
    } else {
        serde_yaml_ng::from_str(content)
            .with_context(|| format!("failed to parse {}", path.display()))
    }
}

fn sanitize_learned_rules_prose(data: &mut LearnedRulesFile) -> bool {
    fn sanitize(value: &mut String) -> bool {
        let sanitized = sanitize_learning_text(value);
        if sanitized == *value {
            return false;
        }
        *value = sanitized;
        true
    }

    let mut changed = false;
    for observation in data.observations.values_mut() {
        changed |= sanitize(&mut observation.last_reason);
        let pattern = crate::redact::scrub_flattened_command_metadata(&observation.pattern);
        changed |= replace_if_changed(&mut observation.pattern, pattern);
        let last_command =
            crate::redact::scrub_flattened_command_metadata(&observation.last_command);
        changed |= replace_if_changed(&mut observation.last_command, last_command);
        for equivalent in &mut observation.equivalent_patterns {
            changed |= replace_if_changed(
                equivalent,
                crate::redact::scrub_flattened_command_metadata(equivalent),
            );
        }
        if let Some(shim) = observation.shim.as_mut() {
            changed |= sanitize(&mut shim.description);
        }
    }
    for rule in &mut data.rules {
        changed |= sanitize(&mut rule.last_reason);
        let pattern = crate::redact::scrub_flattened_command_metadata(&rule.pattern);
        changed |= replace_if_changed(&mut rule.pattern, pattern);
        for equivalent in &mut rule.equivalent_patterns {
            changed |= replace_if_changed(
                equivalent,
                crate::redact::scrub_flattened_command_metadata(equivalent),
            );
        }
        if let Some(shim) = rule.shim.as_mut() {
            changed |= sanitize(&mut shim.description);
        }
    }
    changed
}

fn replace_if_changed(value: &mut String, replacement: String) -> bool {
    if *value == replacement {
        return false;
    }
    *value = replacement;
    true
}

fn learned_shim_contains_sensitive_literals(shim: &LearnedShim) -> bool {
    command_contains_sensitive_literals(&shim.target_binary, &shim.target_args)
}

fn learned_observation_contains_sensitive_literals(observation: &LearnedObservation) -> bool {
    flattened_command_contains_sensitive_literals(&observation.pattern)
        || observation
            .equivalent_patterns
            .iter()
            .any(|pattern| flattened_command_contains_sensitive_literals(pattern))
        || flattened_command_contains_sensitive_literals(&observation.last_command)
        || observation
            .shim
            .as_ref()
            .is_some_and(learned_shim_contains_sensitive_literals)
}

fn learned_rule_contains_sensitive_literals(rule: &LearnedRule) -> bool {
    flattened_command_contains_sensitive_literals(&rule.pattern)
        || rule
            .equivalent_patterns
            .iter()
            .any(|pattern| flattened_command_contains_sensitive_literals(pattern))
        || rule
            .shim
            .as_ref()
            .is_some_and(learned_shim_contains_sensitive_literals)
}

#[derive(Debug, Clone)]
struct RuleCandidate {
    service: String,
    pattern: String,
    equivalent_patterns: Vec<String>,
    shim: Option<LearnedShim>,
}

impl RuleCandidate {
    fn from_command(binary: &str, args: &[String], _command: &str) -> Self {
        let command = crate::redact::command_metadata(binary, args);
        if binary.eq_ignore_ascii_case("ssh") {
            if let Some(ssh) = parse_ssh_command(args) {
                let service = infer_ssh_service(&ssh.host, &ssh.remote_args);
                let pattern = command.clone();
                let shim = ssh.remote_args.first().and_then(|remote_tool| {
                    let name = infer_shim_name(&service, remote_tool);
                    if name == binary || !is_valid_shim_name(&name) {
                        return None;
                    }
                    let mut target_args = ssh.prefix_args.clone();
                    target_args.push(remote_tool.clone());
                    Some(LearnedShim {
                        name,
                        target_binary: binary.to_string(),
                        target_args,
                        description: sanitize_learning_text(&format!(
                            "learned wrapper for {service} via ssh host {}",
                            ssh.host
                        )),
                    })
                });
                let equivalent_patterns = shim
                    .as_ref()
                    .map(|shim| {
                        let remote_tail = ssh.remote_args.get(1..).unwrap_or_default();
                        let mut parts = Vec::with_capacity(remote_tail.len() + 1);
                        parts.push(shim.name.clone());
                        parts.extend(remote_tail.iter().cloned());
                        vec![crate::redact::command_metadata(&parts[0], &parts[1..])]
                    })
                    .unwrap_or_default();
                return Self {
                    service,
                    pattern,
                    equivalent_patterns,
                    shim,
                };
            }
        }

        let service = infer_service_from_binary(binary);
        let pattern = command;
        Self {
            service,
            pattern,
            equivalent_patterns: Vec::new(),
            shim: None,
        }
    }

    fn key(&self) -> String {
        format!("{}|{}", self.service, self.pattern)
    }
}

#[derive(Debug, Clone)]
struct SshCommandParts {
    host: String,
    prefix_args: Vec<String>,
    remote_args: Vec<String>,
}

fn parse_ssh_command(args: &[String]) -> Option<SshCommandParts> {
    let mut idx = 0usize;
    let mut host_idx = None;
    while idx < args.len() {
        let arg = &args[idx];
        if arg == "--" {
            host_idx = idx.checked_add(1);
            break;
        }
        if arg == "-" {
            return None;
        }
        if !arg.starts_with('-') {
            host_idx = Some(idx);
            break;
        }
        if ssh_option_takes_value(arg) && !ssh_option_has_inline_value(arg) {
            idx = idx.saturating_add(2);
        } else {
            idx = idx.saturating_add(1);
        }
    }

    let host_idx = host_idx?;
    let host = args.get(host_idx)?.clone();
    let prefix_args = args[..=host_idx].to_vec();
    let remote_args = args.get(host_idx + 1..).unwrap_or_default().to_vec();
    Some(SshCommandParts {
        host,
        prefix_args,
        remote_args,
    })
}

fn ssh_option_takes_value(arg: &str) -> bool {
    matches!(
        arg,
        "-b" | "-c"
            | "-D"
            | "-E"
            | "-e"
            | "-F"
            | "-I"
            | "-i"
            | "-J"
            | "-L"
            | "-l"
            | "-m"
            | "-O"
            | "-o"
            | "-p"
            | "-Q"
            | "-R"
            | "-S"
            | "-W"
            | "-w"
    ) || arg.starts_with("-o")
        || arg.starts_with("-i")
        || arg.starts_with("-p")
        || arg.starts_with("-l")
        || arg.starts_with("-J")
}

fn ssh_option_has_inline_value(arg: &str) -> bool {
    arg.len() > 2
}

fn infer_ssh_service(host: &str, remote_args: &[String]) -> String {
    let haystack = format!(
        "{} {}",
        host.to_ascii_lowercase(),
        remote_args.join(" ").to_ascii_lowercase()
    );
    if haystack.contains("opnsense") || haystack.contains("configctl") || haystack.contains("/api/")
    {
        return "opnsense-api".to_string();
    }

    let base = host
        .split('@')
        .next_back()
        .unwrap_or(host)
        .split('.')
        .next()
        .unwrap_or(host);
    sanitize_name(base, "service")
}

/// Also used by `gating::deny_shape` so both the allow-candidate and the
/// auto-deny bucketing key commands to the same "service" the same way.
pub(crate) fn infer_service_from_binary(binary: &str) -> String {
    sanitize_name(&crate::gating::executable_match_key(binary), "service")
}

fn infer_shim_name(service: &str, remote_tool: &str) -> String {
    if service == "opnsense-api" {
        return "opnsense-api".to_string();
    }
    let tool = sanitize_name(&crate::gating::executable_match_key(remote_tool), "tool");
    sanitize_name(&format!("{service}-{tool}"), "service-shim")
}

fn sanitize_name(value: &str, fallback: &str) -> String {
    let mut out = String::new();
    let mut previous_dash = false;
    for ch in value.chars() {
        let next = if ch.is_ascii_alphanumeric() {
            previous_dash = false;
            Some(ch.to_ascii_lowercase())
        } else if ch == '-' || ch == '_' || ch == '.' {
            if previous_dash {
                None
            } else {
                previous_dash = true;
                Some('-')
            }
        } else {
            None
        };
        if let Some(ch) = next {
            out.push(ch);
        }
    }
    let out = out.trim_matches('-').to_string();
    if out.is_empty() {
        fallback.to_string()
    } else {
        out
    }
}

fn is_valid_shim_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

/// Also used by `gating::allow_promotion`: both modules trust a repeated LLM
/// approval only up to the same floor of "obviously not something to ever
/// auto-trust regardless of how many times it was approved."
pub(crate) fn looks_dangerous_for_learned_allow(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    let first_token = lower.split_whitespace().next().unwrap_or_default();
    if matches!(first_token, "sudo" | "su" | "reboot" | "shutdown" | "halt") {
        return true;
    }
    let dangerous_substrings = [
        " rm -rf /",
        "rm -rf /",
        "mkfs.",
        " dd if=",
        "dd if=",
        " shutdown",
        " reboot",
        " halt",
        " sudo ",
        " su ",
        "/etc/shadow",
        "/etc/sudoers",
    ];
    if lower.contains('|')
        || lower.contains('>')
        || lower.contains('<')
        || lower.contains(';')
        || lower.contains(">>")
        || lower.contains("&&")
        || lower.contains("||")
        || lower.contains(" $(")
        || lower.contains("$(")
        || lower.contains('`')
    {
        return true;
    }
    dangerous_substrings
        .iter()
        .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_io_error_kind_preserves_already_exists_classification() {
        let already_exists = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "fixture already exists",
        ))
        .context("wrapped fixture error");
        assert!(anyhow_error_has_io_kind(
            &already_exists,
            std::io::ErrorKind::AlreadyExists
        ));
        assert!(!anyhow_error_has_io_kind(
            &already_exists,
            std::io::ErrorKind::PermissionDenied
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_file_identity_matches_read_compatible_hard_link_handles() {
        let directory = authority_tempdir();
        let authority = directory.path().join("authority.yaml");
        let alias = directory.path().join("authority-alias.yaml");
        let distinct = directory.path().join("distinct.lock");
        write_authority_file(&authority, "authority").unwrap();
        write_authority_file(&distinct, "lock").unwrap();
        std::fs::hard_link(&authority, &alias).unwrap();

        let read_handle = |path: &Path| {
            let mut options = owner_only_options();
            options.read(true).open(path).unwrap()
        };
        let authority_handle = read_handle(&authority);
        let alias_handle = read_handle(&alias);
        let distinct_handle = read_handle(&distinct);

        assert!(same_file_identity(&authority_handle, &alias_handle).unwrap());
        assert!(!same_file_identity(&authority_handle, &distinct_handle).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn operator_authority_artifact_lease_rejects_replaceable_paths() {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

        let effective_user = unsafe { libc::geteuid() };
        let root = std::env::current_dir()
            .unwrap()
            .ancestors()
            .find(|candidate| {
                let writable = std::fs::metadata(candidate).is_ok_and(|metadata| {
                    metadata.uid() == effective_user && metadata.mode() & 0o200 != 0
                });
                writable
                    && candidate.ancestors().all(|ancestor| {
                        open_parent_directory(ancestor)
                            .and_then(|handle| validate_trusted_parent(&handle, ancestor))
                            .is_ok()
                    })
            })
            .map(Path::to_path_buf)
            .expect("a trusted writable test ancestor");
        let temp = tempfile::Builder::new()
            .prefix("guard-authority-")
            .tempdir_in(&root)
            .unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let artifact = temp.path().join("credential");
        write_authority_file(&artifact, "credential").unwrap();

        lease_operator_authority_artifact(&artifact, None).unwrap();
        let file = File::open(&artifact).unwrap();
        let error = validate_operator_authority_file(&file, Some(effective_user))
            .expect_err("a child-owned authority file remains mutable after validation");
        assert!(error.to_string().contains("child identity"));
        let directory = open_parent_directory(temp.path()).unwrap();
        let error =
            validate_operator_authority_parent(&directory, temp.path(), Some(effective_user))
                .expect_err("a child-owned authority directory permits post-check replacement");
        assert!(error.to_string().contains("child identity"));
        let error = lease_operator_authority_artifact(&artifact, Some(effective_user)).unwrap_err();
        assert!(format!("{error:#}").contains("child identity"));

        std::fs::create_dir(temp.path().join("alias-parent")).unwrap();
        let noncanonical = temp
            .path()
            .join("alias-parent")
            .join("..")
            .join("credential");
        assert!(lease_operator_authority_artifact(&noncanonical, None)
            .unwrap_err()
            .to_string()
            .contains("not canonical"));

        let executable = temp.path().join("helper");
        write_authority_file(&executable, "helper").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let executable_file = File::open(&executable).unwrap();
        assert!(validate_executable_search_file(&executable_file, Some(effective_user)).is_err());
        validate_executable_search_file(&executable_file, None).unwrap();

        let link = temp.path().join("credential-link");
        symlink(&artifact, &link).unwrap();
        assert!(lease_operator_authority_artifact(&link, None)
            .unwrap_err()
            .to_string()
            .contains("symlink"));

        std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o660)).unwrap();
        assert!(lease_operator_authority_artifact(&artifact, None)
            .unwrap_err()
            .to_string()
            .contains("not trusted"));
        std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o600)).unwrap();

        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(lease_operator_authority_artifact(&artifact, None)
            .unwrap_err()
            .to_string()
            .contains("ancestor"));
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        let tree = temp.path().join("modules");
        let nested = tree.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::set_permissions(&tree, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o700)).unwrap();
        let module = nested.join("module.py");
        write_authority_file(&module, "module").unwrap();
        lease_operator_authority_artifact(&tree, None).unwrap();

        std::fs::set_permissions(&module, std::fs::Permissions::from_mode(0o660)).unwrap();
        assert!(lease_operator_authority_artifact(&tree, None)
            .unwrap_err()
            .to_string()
            .contains("not trusted"));
        std::fs::set_permissions(&module, std::fs::Permissions::from_mode(0o600)).unwrap();

        let nested_link = tree.join("module-link");
        symlink(&module, &nested_link).unwrap();
        assert!(lease_operator_authority_artifact(&tree, None)
            .unwrap_err()
            .to_string()
            .contains("contains symlink"));

        // Executable PATH lookup is shallow but still validates executable
        // link targets without traversing unrelated nested directories.
        std::fs::set_permissions(&module, std::fs::Permissions::from_mode(0o700)).unwrap();
        lease_operator_executable_search_directory(&tree, None).unwrap();
        std::fs::set_permissions(&module, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(lease_operator_executable_search_directory(&tree, None)
            .unwrap_err()
            .to_string()
            .contains("not trusted"));
        std::fs::set_permissions(&module, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            lease_operator_executable_search_directory(&nested_link, None)
                .unwrap_err()
                .to_string()
                .contains("not a real directory")
        );
    }

    #[cfg(unix)]
    #[test]
    fn atomic_writer_propagates_parent_sync_failure_after_replace() {
        let temp = authority_tempdir();
        let path = temp.path().join("learned.yaml");
        write_authority_file(&path, "old").unwrap();
        let mut syncs = 0;
        let outcome = write_learning_file_atomically_with_sync(&path, "new", |_| {
            syncs += 1;
            if syncs == 5 {
                anyhow::bail!("simulated directory sync failure")
            }
            Ok(())
        })
        .unwrap();
        let error = outcome.warning().expect("late sync failure is reported");
        assert!(error
            .to_string()
            .contains("failed to sync parent directory"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }

    #[test]
    fn atomic_writer_rejects_a_stale_candidate_under_the_destination_lock() {
        let temp = authority_tempdir();
        let path = temp.path().join("learned.yaml");
        write_authority_file(&path, "current").unwrap();
        assert!(write_learning_file_atomically_if_unchanged(&path, b"stale", "candidate").is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "current");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_writer_durably_creates_each_missing_parent() {
        let temp = authority_tempdir();
        let first = temp.path().join("one");
        let second = first.join("two");
        let path = second.join("learned.yaml");
        let mut synced = Vec::new();
        write_learning_file_atomically_with_sync(&path, "safe", |directory| {
            synced.push(directory.canonicalize().unwrap());
            Ok(())
        })
        .unwrap();

        assert_eq!(std::fs::read_to_string(path).unwrap(), "safe");
        assert_eq!(
            &synced[..4],
            &[
                first.clone(),
                temp.path().to_path_buf(),
                second.clone(),
                first
            ]
        );
        let canonical_second = second.canonicalize().unwrap();
        assert!(synced[4..]
            .iter()
            .all(|directory| directory == &canonical_second));
    }

    fn test_marker(
        destination: &Path,
        identity: u128,
        content: &[u8],
        had_destination: bool,
    ) -> LearningTransactionPaths {
        let identity = format!("{identity:032x}");
        let paths = transaction_paths(destination, &identity).unwrap();
        let marker = LearningTransactionMarker {
            version: LEARNING_TRANSACTION_VERSION,
            transaction_id: identity,
            phase: LearningTransactionPhase::Replacing,
            candidate_generation: content_digest(content),
            expected_generation: had_destination
                .then(|| std::fs::read(&paths.backup).ok())
                .flatten()
                .map(|bytes| content_digest(&bytes)),
            expected_security_generation: None,
            expected_unix_mode: None,
        };
        write_transaction_marker(&paths, &marker).unwrap();
        paths
    }

    #[test]
    fn learning_transaction_recovery_resolves_committed_and_interrupted_states() {
        let temp = authority_tempdir();
        let destination = temp.path().join("learned.yaml");
        let paths = transaction_paths(&destination, "00000000000000000000000000000001").unwrap();
        write_authority_file(&destination, "candidate").unwrap();
        write_authority_file(&paths.source, "candidate").unwrap();
        write_authority_file(&paths.backup, "original").unwrap();
        let paths = test_marker(&destination, 1, b"candidate", true);
        recover_learning_file_transaction(&destination).unwrap();
        assert_eq!(std::fs::read_to_string(&destination).unwrap(), "candidate");
        assert!(!paths.source.exists());
        assert!(!paths.backup.exists());
        assert!(!paths.marker.exists());

        let paths = transaction_paths(&destination, "00000000000000000000000000000002").unwrap();
        write_authority_file(&paths.source, "candidate-two").unwrap();
        write_authority_file(&paths.backup, "original-two").unwrap();
        std::fs::remove_file(&destination).unwrap();
        let paths = test_marker(&destination, 2, b"candidate-two", true);
        recover_learning_file_transaction(&destination).unwrap();
        assert_eq!(
            std::fs::read_to_string(&destination).unwrap(),
            "original-two"
        );
        assert!(!paths.source.exists());
        assert!(!paths.marker.exists());
    }

    fn write_current_phase_marker(
        destination: &Path,
        identity: &str,
        phase: LearningTransactionPhase,
        candidate: &[u8],
        expected: Option<&[u8]>,
    ) -> LearningTransactionPaths {
        let paths = transaction_paths(destination, identity).unwrap();
        write_transaction_marker(
            &paths,
            &LearningTransactionMarker {
                version: LEARNING_TRANSACTION_VERSION,
                transaction_id: identity.to_string(),
                phase,
                candidate_generation: content_digest(candidate),
                expected_generation: expected.map(content_digest),
                expected_security_generation: None,
                expected_unix_mode: None,
            },
        )
        .unwrap();
        paths
    }

    #[test]
    fn phase_journal_recovers_every_precommit_and_committed_transition() {
        let phases = [
            LearningTransactionPhase::Preparing,
            LearningTransactionPhase::Ready,
            LearningTransactionPhase::Replacing,
        ];
        for (index, phase) in phases.into_iter().enumerate() {
            let temp = authority_tempdir();
            let destination = temp.path().join("learned.yaml");
            write_authority_file(&destination, "original").unwrap();
            let identity = format!("{index:032x}");
            let paths = transaction_paths(&destination, &identity).unwrap();
            write_authority_file(&paths.source, "candidate").unwrap();
            write_authority_file(&paths.backup, "original").unwrap();
            write_current_phase_marker(
                &destination,
                &identity,
                phase,
                b"candidate",
                Some(b"original"),
            );

            recover_learning_file_transaction(&destination).unwrap();
            assert_eq!(std::fs::read(&destination).unwrap(), b"original");
            assert!(transaction_artifacts(&destination).unwrap().is_empty());
            assert!(!paths.marker.exists());
        }

        for phase in [
            LearningTransactionPhase::Replacing,
            LearningTransactionPhase::ReplacementDurable,
            LearningTransactionPhase::BackupRemoved,
        ] {
            let temp = authority_tempdir();
            let destination = temp.path().join("learned.yaml");
            write_authority_file(&destination, "candidate").unwrap();
            let identity = format!("{:032x}", phase as u8 + 10);
            let paths = transaction_paths(&destination, &identity).unwrap();
            if phase != LearningTransactionPhase::BackupRemoved {
                write_authority_file(&paths.backup, "original").unwrap();
            }
            write_current_phase_marker(
                &destination,
                &identity,
                phase,
                b"candidate",
                Some(b"original"),
            );

            recover_learning_file_transaction(&destination).unwrap();
            assert_eq!(std::fs::read(&destination).unwrap(), b"candidate");
            assert!(transaction_artifacts(&destination).unwrap().is_empty());
            assert!(!paths.marker.exists());
        }

        let temp = authority_tempdir();
        let destination = temp.path().join("learned.yaml");
        let identity = "00000000000000000000000000000020";
        let paths = transaction_paths(&destination, identity).unwrap();
        write_authority_file(&paths.backup, "original").unwrap();
        write_current_phase_marker(
            &destination,
            identity,
            LearningTransactionPhase::Replacing,
            b"candidate",
            Some(b"original"),
        );
        recover_learning_file_transaction(&destination).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"original");
        assert!(transaction_artifacts(&destination).unwrap().is_empty());
    }

    #[test]
    fn preparing_phase_cleans_only_derived_partial_artifacts() {
        for partial_role in [
            "none",
            "marker_staging",
            "source",
            "backup_staging",
            "backup",
        ] {
            let temp = authority_tempdir();
            let destination = temp.path().join("learned.yaml");
            write_authority_file(&destination, "original").unwrap();
            let identity = "00000000000000000000000000000021";
            let paths = transaction_paths(&destination, identity).unwrap();
            write_current_phase_marker(
                &destination,
                identity,
                LearningTransactionPhase::Preparing,
                b"candidate",
                Some(b"original"),
            );
            match partial_role {
                "marker_staging" => write_authority_file(&paths.marker_staging, "partial").unwrap(),
                "source" => write_authority_file(&paths.source, "partial").unwrap(),
                "backup_staging" => write_authority_file(&paths.backup_staging, "partial").unwrap(),
                "backup" => write_authority_file(&paths.backup, "partial").unwrap(),
                _ => {}
            }
            recover_learning_file_transaction(&destination).unwrap();
            assert_eq!(std::fs::read(&destination).unwrap(), b"original");
            assert!(transaction_artifacts(&destination).unwrap().is_empty());
        }
    }

    #[test]
    fn cleanup_phase_never_discards_unrecorded_rollback_state() {
        let temp = authority_tempdir();
        let destination = temp.path().join("learned.yaml");
        write_authority_file(&destination, "candidate").unwrap();
        let identity = "00000000000000000000000000000025";
        let paths = transaction_paths(&destination, identity).unwrap();
        write_authority_file(&paths.backup, "original").unwrap();
        write_current_phase_marker(
            &destination,
            identity,
            LearningTransactionPhase::BackupRemoved,
            b"candidate",
            Some(b"original"),
        );

        assert!(recover_learning_file_transaction(&destination).is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), b"candidate");
        assert_eq!(std::fs::read(&paths.backup).unwrap(), b"original");
        assert!(paths.marker.exists());
    }

    fn write_v1_marker(
        destination: &Path,
        identity: &str,
        candidate: &[u8],
        expected: Option<&[u8]>,
    ) -> LearningTransactionPaths {
        let paths = transaction_paths(destination, identity).unwrap();
        let marker = serde_json::json!({
            "version": 1,
            "destination": destination.file_name().unwrap().to_str().unwrap(),
            "source": paths.source.file_name().unwrap().to_str().unwrap(),
            "backup": paths.backup.file_name().unwrap().to_str().unwrap(),
            "content_sha256": content_digest(candidate),
            "original_sha256": expected.map(content_digest),
            "had_destination": expected.is_some(),
        });
        write_raw_marker(destination, &serde_json::to_vec(&marker).unwrap());
        paths
    }

    #[test]
    fn version_one_transactions_recover_only_unambiguous_derived_states() {
        for state in ["precommit", "committed", "restore", "new_precommit"] {
            let temp = authority_tempdir();
            let destination = temp.path().join("learned.yaml");
            let identity = "00000000000000000000000000000022";
            let expected = (state != "new_precommit").then_some(b"original".as_slice());
            let paths = transaction_paths(&destination, identity).unwrap();
            write_authority_file(&paths.source, "candidate").unwrap();
            if expected.is_some() {
                write_authority_file(&paths.backup, "original").unwrap();
            }
            match state {
                "precommit" => write_authority_file(&destination, "original").unwrap(),
                "committed" => write_authority_file(&destination, "candidate").unwrap(),
                "restore" | "new_precommit" => {}
                _ => unreachable!(),
            }
            write_v1_marker(&destination, identity, b"candidate", expected);

            recover_learning_file_transaction(&destination).unwrap();
            let expected_destination = if state == "committed" {
                Some(b"candidate".as_slice())
            } else if state == "new_precommit" {
                None
            } else {
                Some(b"original".as_slice())
            };
            assert_eq!(
                destination
                    .exists()
                    .then(|| std::fs::read(&destination).unwrap()),
                expected_destination.map(Vec::from)
            );
            assert!(transaction_artifacts(&destination).unwrap().is_empty());
        }
    }

    #[test]
    fn version_two_transaction_recovers_with_constrained_derived_paths() {
        let temp = authority_tempdir();
        let destination = temp.path().join("learned.yaml");
        write_authority_file(&destination, "candidate").unwrap();
        let identity = "00000000000000000000000000000027";
        let paths = transaction_paths(&destination, identity).unwrap();
        write_authority_file(&paths.source, "candidate").unwrap();
        write_authority_file(&paths.backup, "original").unwrap();
        let marker = serde_json::json!({
            "version": 2,
            "transaction_id": identity,
            "content_sha256": content_digest(b"candidate"),
            "original_sha256": content_digest(b"original"),
            "had_destination": true,
        });
        write_raw_marker(&destination, &serde_json::to_vec(&marker).unwrap());

        recover_learning_file_transaction(&destination).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"candidate");
        assert!(transaction_artifacts(&destination).unwrap().is_empty());
        assert!(!paths.marker.exists());
    }

    #[test]
    fn version_one_markers_reject_foreign_paths_and_digest_mismatches() {
        for (field, foreign) in [
            ("source", "../operator.yaml"),
            ("source", "learned.yaml"),
            ("backup", "sibling.yaml"),
            ("destination", "sibling.yaml"),
        ] {
            let temp = authority_tempdir();
            let destination = temp.path().join("learned.yaml");
            write_authority_file(&destination, "original").unwrap();
            let identity = "00000000000000000000000000000023";
            let paths = transaction_paths(&destination, identity).unwrap();
            write_authority_file(&paths.source, "candidate").unwrap();
            write_authority_file(&paths.backup, "original").unwrap();
            let mut marker = serde_json::json!({
                "version": 1,
                "destination": destination.file_name().unwrap().to_str().unwrap(),
                "source": paths.source.file_name().unwrap().to_str().unwrap(),
                "backup": paths.backup.file_name().unwrap().to_str().unwrap(),
                "content_sha256": content_digest(b"candidate"),
                "original_sha256": content_digest(b"original"),
                "had_destination": true,
            });
            marker.as_object_mut().unwrap().insert(
                field.to_string(),
                serde_json::Value::String(foreign.to_string()),
            );
            write_raw_marker(&destination, &serde_json::to_vec(&marker).unwrap());
            assert!(recover_learning_file_transaction(&destination).is_err());
            assert!(paths.source.exists());
            assert!(paths.backup.exists());
        }

        let temp = authority_tempdir();
        let destination = temp.path().join("learned.yaml");
        write_authority_file(&destination, "original").unwrap();
        let identity = "00000000000000000000000000000024";
        let paths = transaction_paths(&destination, identity).unwrap();
        write_authority_file(&paths.source, "candidate").unwrap();
        write_authority_file(&paths.backup, "original").unwrap();
        write_v1_marker(
            &destination,
            identity,
            b"different-candidate",
            Some(b"different-original"),
        );
        assert!(recover_learning_file_transaction(&destination).is_err());
        assert!(paths.source.exists());
        assert!(paths.backup.exists());
    }

    #[test]
    fn ambiguous_learning_transaction_fails_closed_and_preserves_copies() {
        let temp = authority_tempdir();
        let destination = temp.path().join("learned.yaml");
        let paths = transaction_paths(&destination, "00000000000000000000000000000003").unwrap();
        write_authority_file(&destination, "unexpected").unwrap();
        write_authority_file(&paths.source, "candidate").unwrap();
        write_authority_file(&paths.backup, "original").unwrap();
        let paths = test_marker(&destination, 3, b"candidate", true);

        assert!(recover_learning_file_transaction(&destination).is_err());
        assert!(destination.exists());
        assert!(paths.source.exists());
        assert!(paths.backup.exists());
        assert!(paths.marker.exists());
    }

    #[test]
    fn destination_lock_serializes_independent_writers() {
        let temp = authority_tempdir();
        let destination = temp.path().join("learned.yaml");
        let first = DestinationLock::acquire(&destination).unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let contender = destination.clone();
        let thread = std::thread::spawn(move || {
            let lock = DestinationLock::acquire(&contender).unwrap();
            send.send(()).unwrap();
            drop(lock);
        });
        assert!(receive
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err());
        drop(first);
        receive
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        thread.join().unwrap();
    }

    #[test]
    fn destination_lock_contention_has_a_bounded_failure() {
        let temp = authority_tempdir();
        let destination = temp.path().join("learned.yaml");
        let first = DestinationLock::acquire(&destination).unwrap();
        let contender = destination.clone();
        let error = std::thread::spawn(move || {
            DestinationLock::acquire_with_mode_and_timeout(
                &contender,
                true,
                Duration::from_millis(100),
            )
            .err()
            .unwrap()
        })
        .join()
        .unwrap();
        assert!(is_authority_lock_timeout(&error));
        drop(first);
        DestinationLock::acquire(&destination).unwrap();
    }

    #[tokio::test]
    async fn in_process_authority_coordination_has_a_bounded_failure() {
        let temp = authority_tempdir();
        let destination = temp.path().join("learned.yaml");
        let first = acquire_durable_store_write_permit(&destination)
            .await
            .unwrap();
        let error = acquire_durable_store_write_permit_with_timeout(
            &destination,
            Duration::from_millis(100),
        )
        .await
        .unwrap_err();
        assert!(is_authority_lock_timeout(&error));
        drop(first);
        let _permit = acquire_durable_store_write_permit(&destination)
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn asynchronous_mutation_keeps_current_thread_runtime_and_readers_responsive() {
        let temp = authority_tempdir();
        let config = LearningConfig {
            path: temp.path().join("learned.yaml"),
            min_approvals: 2,
            max_risk: 2,
            auto_shim: AutoShimMode::Off,
        };
        let store = Arc::new(RwLock::new(LearnedRuleStore::load(config.clone()).unwrap()));
        let acquired = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let lock_thread = {
            let path = config.path.clone();
            let acquired = acquired.clone();
            let release = release.clone();
            std::thread::spawn(move || hold_learning_file_lock_for_test(&path, &acquired, &release))
        };
        acquired.wait();

        let attempted = observe_durable_store_write_attempt(&config.path);
        let mutation_store = store.clone();
        let mutation = tokio::spawn(async move {
            run_async_durable_store_operation(
                &mutation_store,
                "responsive learned-rule mutation",
                |candidate| {
                    candidate.record_approval(
                        "fixturectl",
                        &["status".to_string()],
                        "fixturectl status",
                        Some(1),
                        "safe",
                    )
                },
            )
            .await
        });

        attempted.acquire().await.unwrap().forget();
        assert_eq!(store.read().await.rule_count(), 0);

        release.wait();
        assert!(mutation.await.unwrap().unwrap().is_some());
        lock_thread.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn destination_coordinator_never_replays_a_committed_observation() {
        let temp = authority_tempdir();
        let config = LearningConfig {
            path: temp.path().join("learned.yaml"),
            min_approvals: 3,
            max_risk: 2,
            auto_shim: AutoShimMode::Off,
        };
        let store = Arc::new(RwLock::new(LearnedRuleStore::load(config.clone()).unwrap()));
        let hook_identity =
            crate::redact::command_metadata("fixturectl", &["async-race".to_string()]);
        let (committed, release) = pause_post_commit_adoption_for_test(&hook_identity);
        let first_store = store.clone();
        let first = tokio::spawn(async move {
            run_async_durable_store_operation(
                &first_store,
                "first coordinated observation",
                |candidate| {
                    candidate.record_approval(
                        "fixturectl",
                        &["async-race".to_string()],
                        "fixturectl async-race",
                        Some(1),
                        "safe",
                    )
                },
            )
            .await
        });
        tokio::task::spawn_blocking(move || committed.wait())
            .await
            .unwrap();

        let attempted = observe_durable_store_write_attempt(&config.path);
        let second_store = store.clone();
        let (second_result_tx, mut second_result_rx) = tokio::sync::oneshot::channel();
        let second = tokio::spawn(async move {
            let result = run_async_durable_store_operation(
                &second_store,
                "second coordinated observation",
                |candidate| {
                    candidate.record_approval(
                        "fixturectl",
                        &["async-race".to_string()],
                        "fixturectl async-race",
                        Some(1),
                        "safe",
                    )
                },
            )
            .await;
            let _ = second_result_tx.send(result);
        });
        attempted.acquire().await.unwrap().forget();
        assert!(matches!(
            second_result_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        tokio::task::spawn_blocking(move || release.wait())
            .await
            .unwrap();

        assert_eq!(first.await.unwrap().unwrap().unwrap().approvals, 1);
        assert_eq!(
            second_result_rx.await.unwrap().unwrap().unwrap().approvals,
            2
        );
        second.await.unwrap();
        let loaded = LearnedRuleStore::load(config).unwrap();
        assert_eq!(
            loaded.data.observations.values().next().unwrap().approvals,
            2
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_caller_cannot_release_coordination_before_detached_adoption() {
        let temp = authority_tempdir();
        let config = LearningConfig {
            path: temp.path().join("learned.yaml"),
            min_approvals: 3,
            max_risk: 2,
            auto_shim: AutoShimMode::Off,
        };
        let store = Arc::new(RwLock::new(LearnedRuleStore::load(config.clone()).unwrap()));
        let hook_identity =
            crate::redact::command_metadata("fixturectl", &["cancel-race".to_string()]);
        let (committed, release) = pause_post_commit_adoption_for_test(&hook_identity);
        let first_store = store.clone();
        let first = tokio::spawn(async move {
            run_async_durable_store_operation(
                &first_store,
                "cancelled coordinated observation",
                |candidate| {
                    candidate.record_approval(
                        "fixturectl",
                        &["cancel-race".to_string()],
                        "fixturectl cancel-race",
                        Some(1),
                        "safe",
                    )
                },
            )
            .await
        });
        tokio::task::spawn_blocking(move || committed.wait())
            .await
            .unwrap();
        first.abort();

        let attempted = observe_durable_store_write_attempt(&config.path);
        let second_store = store.clone();
        let (result_tx, mut result_rx) = tokio::sync::oneshot::channel();
        let second = tokio::spawn(async move {
            let result = run_async_durable_store_operation(
                &second_store,
                "successor coordinated observation",
                |candidate| {
                    candidate.record_approval(
                        "fixturectl",
                        &["cancel-race".to_string()],
                        "fixturectl cancel-race",
                        Some(1),
                        "safe",
                    )
                },
            )
            .await;
            let _ = result_tx.send(result);
        });
        attempted.acquire().await.unwrap().forget();
        assert!(matches!(
            result_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        tokio::task::spawn_blocking(move || release.wait())
            .await
            .unwrap();

        assert_eq!(result_rx.await.unwrap().unwrap().unwrap().approvals, 2);
        second.await.unwrap();
        let loaded = LearnedRuleStore::load(config).unwrap();
        assert_eq!(
            loaded.data.observations.values().next().unwrap().approvals,
            2
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authority_use_lease_blocks_an_independent_writer_until_use_finishes() {
        let temp = authority_tempdir();
        let config = LearningConfig {
            path: temp.path().join("learned.yaml"),
            min_approvals: 2,
            max_risk: 2,
            auto_shim: AutoShimMode::Off,
        };
        let store = Arc::new(RwLock::new(LearnedRuleStore::load(config.clone()).unwrap()));
        let lease = acquire_async_authority_use_lease(&store, "learning authority use")
            .await
            .unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            let mut independent = LearnedRuleStore::load(config).unwrap();
            independent
                .record_approval(
                    "fixturectl",
                    &["status".to_string()],
                    "fixturectl status",
                    Some(1),
                    "safe",
                )
                .unwrap();
            send.send(()).unwrap();
        });
        assert!(receive.recv_timeout(Duration::from_millis(100)).is_err());
        assert_eq!(lease.rule_count(), 0);
        drop(lease);
        receive.recv_timeout(Duration::from_secs(2)).unwrap();
        writer.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authority_use_leases_are_shared_between_concurrent_decisions() {
        let temp = authority_tempdir();
        let config = LearningConfig {
            path: temp.path().join("learned.yaml"),
            min_approvals: 2,
            max_risk: 2,
            auto_shim: AutoShimMode::Off,
        };
        let store = Arc::new(RwLock::new(LearnedRuleStore::load(config).unwrap()));
        let first = acquire_async_authority_use_lease(&store, "first authority reader")
            .await
            .unwrap();
        let second = tokio::time::timeout(
            Duration::from_millis(250),
            acquire_async_authority_use_lease(&store, "second authority reader"),
        )
        .await
        .expect("concurrent authority readers do not serialize")
        .unwrap();
        assert_eq!(first.rule_count(), second.rule_count());
    }

    #[cfg(unix)]
    #[test]
    fn destination_lock_uses_the_canonical_parent_identity() {
        let temp = authority_tempdir();
        let real = temp.path().join("real");
        let alias = temp.path().join("alias");
        create_authority_directory(&real).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let first = DestinationLock::acquire(&real.join("learned.yaml")).unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let contender = alias.join("learned.yaml");
        let thread = std::thread::spawn(move || {
            let lock = DestinationLock::acquire(&contender).unwrap();
            send.send(()).unwrap();
            drop(lock);
        });
        assert!(receive
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err());
        drop(first);
        receive
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        thread.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn destination_binding_detects_parent_retargeting_before_file_operations() {
        let temp = authority_tempdir();
        let parent = temp.path().join("authority");
        let moved = temp.path().join("authority-moved");
        create_authority_directory(&parent).unwrap();
        let destination = parent.join("learned.yaml");
        let lock = DestinationLock::acquire(&destination).unwrap();

        std::fs::rename(&parent, &moved).unwrap();
        create_authority_directory(&parent).unwrap();
        let unrelated = parent.join("unrelated.yaml");
        write_authority_file(&unrelated, "operator state").unwrap();

        assert!(lock.verify_parent_binding().is_err());
        assert_eq!(
            std::fs::read_to_string(unrelated).unwrap(),
            "operator state"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn atomic_writer_never_redirects_into_a_retargeted_parent() {
        let temp = authority_tempdir();
        let parent = temp.path().join("authority");
        let moved = temp.path().join("authority-moved");
        create_authority_directory(&parent).unwrap();
        let destination = parent.join("learned.yaml");
        write_authority_file(&destination, "original").unwrap();
        let replacement_destination = destination.clone();
        let mut syncs = 0;

        let result =
            write_learning_file_atomically_with_sync(&destination, "candidate", |bound_parent| {
                syncs += 1;
                if syncs == 1 {
                    std::fs::rename(&parent, &moved)?;
                    create_authority_directory(&parent)?;
                    write_authority_file(&replacement_destination, "unrelated")?;
                }
                sync_parent_directory(bound_parent)
            });

        assert!(result.is_err());
        assert_eq!(
            std::fs::read_to_string(&replacement_destination).unwrap(),
            "unrelated"
        );
        let moved_destination = moved.join("learned.yaml");
        assert_eq!(
            std::fs::read_to_string(&moved_destination).unwrap(),
            "original"
        );
        recover_learning_file_transaction(&moved_destination).unwrap();
        assert!(transaction_artifacts(&moved_destination)
            .unwrap()
            .is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn hardened_initial_creation_is_restrictive_from_nested_parent_creation() {
        use std::os::unix::fs::PermissionsExt;

        let temp = authority_tempdir();
        let first = temp.path().join("state");
        let second = first.join("catalog");
        let destination = second.join("verbs.yaml");
        create_hardened_file_if_absent(&destination, "verbs: []\n").unwrap();

        assert_eq!(
            std::fs::metadata(&first).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&second).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&destination)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_to_string(destination).unwrap(), "verbs: []\n");
    }

    fn write_raw_marker(destination: &Path, bytes: &[u8]) -> PathBuf {
        let marker = learning_sibling(destination, "transaction", None);
        let mut file = open_owner_only_new(&marker).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        marker
    }

    #[test]
    fn transaction_marker_rejects_malformed_bounded_and_foreign_identities() {
        for bytes in [b"{".as_slice(), b"[]".as_slice()] {
            let temp = authority_tempdir();
            let destination = temp.path().join("learned.yaml");
            write_raw_marker(&destination, bytes);
            assert!(recover_learning_file_transaction(&destination).is_err());
        }

        let temp = authority_tempdir();
        let destination = temp.path().join("learned.yaml");
        write_raw_marker(
            &destination,
            &vec![b'x'; MAX_TRANSACTION_MARKER_BYTES as usize + 1],
        );
        assert!(recover_learning_file_transaction(&destination).is_err());

        for identity in [
            "../00000000000000000000000000000",
            "sibling",
            "ABCDEF00000000000000000000000000",
        ] {
            let temp = authority_tempdir();
            let destination = temp.path().join("learned.yaml");
            let marker = serde_json::json!({
                "version": LEARNING_TRANSACTION_VERSION,
                "transaction_id": identity,
                "phase": "preparing",
                "candidate_generation": content_digest(b"candidate"),
                "expected_generation": null,
            });
            write_raw_marker(&destination, &serde_json::to_vec(&marker).unwrap());
            assert!(recover_learning_file_transaction(&destination).is_err());
        }

        for (field, value) in [
            ("source", "../unrelated"),
            ("backup", "learned.yaml"),
            ("destination", "sibling.yaml"),
        ] {
            let temp = authority_tempdir();
            let destination = temp.path().join("learned.yaml");
            let mut marker = serde_json::json!({
                "version": LEARNING_TRANSACTION_VERSION,
                "transaction_id": "00000000000000000000000000000005",
                "phase": "preparing",
                "candidate_generation": content_digest(b"candidate"),
                "expected_generation": null,
            });
            marker.as_object_mut().unwrap().insert(
                field.to_string(),
                serde_json::Value::String(value.to_string()),
            );
            write_raw_marker(&destination, &serde_json::to_vec(&marker).unwrap());
            assert!(recover_learning_file_transaction(&destination).is_err());
        }
    }

    #[test]
    fn transaction_recovery_never_removes_unverified_or_unrelated_files() {
        let temp = authority_tempdir();
        let destination = temp.path().join("learned.yaml");
        let unrelated = temp.path().join("operator.yaml");
        write_authority_file(&unrelated, "operator data").unwrap();
        let paths = transaction_paths(&destination, "00000000000000000000000000000004").unwrap();
        write_authority_file(&paths.source, "different candidate").unwrap();
        write_authority_file(&paths.backup, "different original").unwrap();
        write_transaction_marker(
            &paths,
            &LearningTransactionMarker {
                version: LEARNING_TRANSACTION_VERSION,
                transaction_id: "00000000000000000000000000000004".to_string(),
                phase: LearningTransactionPhase::ReplacementDurable,
                candidate_generation: content_digest(b"candidate"),
                expected_generation: Some(content_digest(b"expected original")),
                expected_security_generation: None,
                expected_unix_mode: None,
            },
        )
        .unwrap();
        assert!(recover_learning_file_transaction(&destination).is_err());
        assert!(paths.source.exists());
        assert!(paths.backup.exists());
        assert_eq!(std::fs::read_to_string(unrelated).unwrap(), "operator data");
    }

    #[cfg(unix)]
    #[test]
    fn transaction_recovery_rejects_symlinked_artifacts_without_touching_the_target() {
        let temp = authority_tempdir();
        let destination = temp.path().join("learned.yaml");
        let unrelated = temp.path().join("operator.yaml");
        write_authority_file(&unrelated, "operator data").unwrap();
        let paths = transaction_paths(&destination, "00000000000000000000000000000006").unwrap();
        std::os::unix::fs::symlink(&unrelated, &paths.source).unwrap();
        write_transaction_marker(
            &paths,
            &LearningTransactionMarker {
                version: LEARNING_TRANSACTION_VERSION,
                transaction_id: "00000000000000000000000000000006".to_string(),
                phase: LearningTransactionPhase::Preparing,
                candidate_generation: content_digest(b"candidate"),
                expected_generation: None,
                expected_security_generation: None,
                expected_unix_mode: None,
            },
        )
        .unwrap();

        assert!(recover_learning_file_transaction(&destination).is_err());
        assert!(paths.source.is_symlink());
        assert_eq!(std::fs::read_to_string(unrelated).unwrap(), "operator data");
    }

    #[cfg(unix)]
    #[test]
    fn transaction_artifacts_are_owner_only_before_sensitive_bytes_are_committed() {
        use std::os::unix::fs::PermissionsExt;

        let temp = authority_tempdir();
        let destination = temp.path().join("learned.yaml");
        write_authority_file(&destination, "original").unwrap();
        let mut syncs = 0;
        let outcome =
            write_learning_file_atomically_with_sync(&destination, "candidate", |parent| {
                syncs += 1;
                if syncs == 2 {
                    let artifacts = transaction_artifacts(&destination).unwrap();
                    assert_eq!(artifacts.len(), 2);
                    for artifact in artifacts {
                        assert_eq!(
                            std::fs::metadata(artifact).unwrap().permissions().mode() & 0o777,
                            0o600
                        );
                    }
                    let marker = learning_sibling(&destination, "transaction", None);
                    assert_eq!(
                        std::fs::metadata(marker).unwrap().permissions().mode() & 0o777,
                        0o600
                    );
                }
                sync_parent_directory(parent)
            })
            .unwrap();
        assert!(outcome.warning().is_none());
    }

    #[test]
    fn post_commit_sync_failure_leaves_recoverable_artifacts_until_restart() {
        let temp = authority_tempdir();
        let destination = temp.path().join("learned.yaml");
        write_authority_file(&destination, "original").unwrap();
        let mut syncs = 0;
        let outcome =
            write_learning_file_atomically_with_sync(&destination, "candidate", |parent| {
                syncs += 1;
                if syncs == 5 {
                    anyhow::bail!("simulated post-commit sync failure")
                }
                sync_learning_parent(parent)
            })
            .unwrap();
        assert!(outcome.warning().is_some());
        assert!(learning_sibling(&destination, "transaction", None).exists());
        assert!(!transaction_artifacts(&destination).unwrap().is_empty());

        recover_learning_file_transaction(&destination).unwrap();
        assert_eq!(std::fs::read_to_string(&destination).unwrap(), "candidate");
        assert!(!learning_sibling(&destination, "transaction", None).exists());
        assert!(transaction_artifacts(&destination).unwrap().is_empty());
    }

    #[test]
    fn corrupt_recovery_copy_is_content_addressed_and_preserves_permissions() {
        let temp = authority_tempdir();
        let path = temp.path().join("learned.yaml");
        let bytes = b"not valid state";
        write_authority_file(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let first = preserve_corrupt_learning_file(&path, bytes).unwrap();
        let second = preserve_corrupt_learning_file(&path, bytes).unwrap();
        assert_eq!(first, second);
        assert_eq!(std::fs::read(&first).unwrap(), bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(first).unwrap().permissions().mode() & 0o777,
                0o400
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_mutation_masks_cover_content_metadata_and_replacement_rights() {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA, FILE_DELETE_CHILD,
            FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
        };

        for right in [
            FILE_WRITE_ATTRIBUTES,
            FILE_WRITE_EA,
            0x0001_0000,
            0x0004_0000,
            0x0008_0000,
            0x1000_0000,
            0x4000_0000,
        ] {
            assert_ne!(windows_authority_mutation_mask(false) & right, 0);
            assert_ne!(windows_authority_mutation_mask(true) & right, 0);
        }
        for right in [FILE_WRITE_DATA, FILE_APPEND_DATA] {
            assert_ne!(windows_authority_mutation_mask(false) & right, 0);
        }
        for right in [FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_DELETE_CHILD] {
            assert_ne!(windows_authority_mutation_mask(true) & right, 0);
        }
    }

    #[cfg(windows)]
    fn apply_windows_test_dacl(path: &Path, sddl: &str) {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::{
            SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        };

        let path = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let sddl = sddl
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut descriptor = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let applied = unsafe {
            SetFileSecurityW(
                path.as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor,
            )
        };
        unsafe { LocalFree(descriptor) };
        assert_ne!(applied, 0);
    }

    #[cfg(windows)]
    #[test]
    fn windows_authority_validation_reads_every_raw_ace_and_rejects_inherited_mutation() {
        let temp = authority_tempdir();
        let path = temp.path().join("learned.yaml");
        write_authority_file(&path, "version: 1\n").unwrap();
        let file = owner_only_options()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();

        apply_windows_test_dacl(&path, "D:P(A;;FA;;;OW)(A;ID;GR;;;AU)");
        validate_authority_file(&file).unwrap();

        apply_windows_test_dacl(&path, "D:P(A;;FA;;;OW)(D;ID;GW;;;AU)");
        validate_authority_file(&file).unwrap();

        apply_windows_test_dacl(&path, "D:P(A;;FA;;;OW)(A;ID;GW;;;AU)");
        let error = validate_authority_file(&file).unwrap_err();
        assert!(error
            .to_string()
            .contains("grants mutation rights to an untrusted principal"));

        let inherited_parent = temp.path().join("inherited");
        std::fs::create_dir(&inherited_parent).unwrap();
        apply_windows_test_dacl(
            &inherited_parent,
            "D:P(A;;FA;;;OW)(A;OICI;FA;;;CO)(A;OICI;GR;;;AU)",
        );
        let read_only_child = inherited_parent.join("read-only.yaml");
        std::fs::write(&read_only_child, "version: 1\n").unwrap();
        let read_only_child = owner_only_options()
            .read(true)
            .write(true)
            .open(read_only_child)
            .unwrap();
        validate_authority_file(&read_only_child).unwrap();

        apply_windows_test_dacl(
            &inherited_parent,
            "D:P(A;;FA;;;OW)(A;OICI;FA;;;CO)(A;OICI;GW;;;AU)",
        );
        let writable_child = inherited_parent.join("writable.yaml");
        std::fs::write(&writable_child, "version: 1\n").unwrap();
        let writable_child = owner_only_options()
            .read(true)
            .write(true)
            .open(writable_child)
            .unwrap();
        let error = validate_authority_file(&writable_child).unwrap_err();
        assert!(error
            .to_string()
            .contains("grants mutation rights to an untrusted principal"));

        let inherit_only_parent = temp.path().join("inherit-only");
        std::fs::create_dir(&inherit_only_parent).unwrap();
        apply_windows_test_dacl(&inherit_only_parent, "D:P(A;;FA;;;OW)(A;OICIIO;FA;;;AU)");
        let inherit_only_handle = open_parent_directory(&inherit_only_parent).unwrap();
        validate_windows_authority_handle_with_current_user(&inherit_only_handle, true, true)
            .unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_dacl_generation_ignores_inheritance_provenance() {
        let temp = authority_tempdir();
        let direct = temp.path().join("direct.yaml");
        let inherited = temp.path().join("inherited.yaml");
        write_authority_file(&direct, "version: 1\n").unwrap();
        write_authority_file(&inherited, "version: 1\n").unwrap();
        apply_windows_test_dacl(&direct, "D:P(A;;FA;;;OW)(A;;GR;;;AU)");
        apply_windows_test_dacl(&inherited, "D:P(A;;FA;;;OW)(A;ID;GR;;;AU)");

        assert_eq!(
            windows_dacl_digest(&direct).unwrap(),
            windows_dacl_digest(&inherited).unwrap()
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_dacl_generation_ignores_file_inheritance_routing() {
        let temp = authority_tempdir();
        let direct = temp.path().join("direct.yaml");
        let propagating = temp.path().join("propagating.yaml");
        write_authority_file(&direct, "version: 1\n").unwrap();
        write_authority_file(&propagating, "version: 1\n").unwrap();
        apply_windows_test_dacl(&direct, "D:P(A;;FA;;;OW)(A;;GR;;;AU)");
        apply_windows_test_dacl(&propagating, "D:P(A;;FA;;;OW)(A;OICINP;GR;;;AU)");

        assert_eq!(
            windows_dacl_digest(&direct).unwrap(),
            windows_dacl_digest(&propagating).unwrap()
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_dacl_generation_ignores_inherit_only_file_aces() {
        let temp = authority_tempdir();
        let direct = temp.path().join("direct.yaml");
        let inherit_only = temp.path().join("inherit-only.yaml");
        write_authority_file(&direct, "version: 1\n").unwrap();
        write_authority_file(&inherit_only, "version: 1\n").unwrap();
        apply_windows_test_dacl(&direct, "D:P(A;;FA;;;OW)");
        apply_windows_test_dacl(&inherit_only, "D:P(A;;FA;;;OW)(A;OICIIO;GR;;;AU)");

        assert_eq!(
            windows_dacl_digest(&direct).unwrap(),
            windows_dacl_digest(&inherit_only).unwrap()
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_dacl_generation_difference_does_not_expose_trustee_bytes() {
        let mut expected = vec![1, 1, 0, 0, 0, 12, 0, 0xff, 0x01, 0x1f, 0];
        expected.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let mut actual = expected.clone();
        actual[14] = 0x00;

        assert_eq!(
            windows_dacl_generation_difference(&expected, &actual),
            "ACE 0 trustee or type-specific body differs"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_dacl_generation_normalizes_generic_file_rights() {
        let temp = authority_tempdir();
        let generic = temp.path().join("generic.yaml");
        let specific = temp.path().join("specific.yaml");
        write_authority_file(&generic, "version: 1\n").unwrap();
        write_authority_file(&specific, "version: 1\n").unwrap();
        apply_windows_test_dacl(&generic, "D:P(A;;FA;;;OW)(A;;GR;;;AU)");
        apply_windows_test_dacl(&specific, "D:P(A;;FA;;;OW)(A;;0x00120089;;;AU)");

        assert_eq!(
            windows_dacl_digest(&generic).unwrap(),
            windows_dacl_digest(&specific).unwrap()
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_atomic_rewrite_preserves_an_inherited_dacl() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("authority.yaml");
        std::fs::write(&path, "version: 1\n").unwrap();
        let expected_dacl = windows_dacl_digest(&path).unwrap();

        let outcome = write_learning_file_atomically_windows(
            &path,
            Some(Some(b"version: 1\n")),
            None,
            "version: 2\n",
        )
        .unwrap();

        if let Some(warning) = outcome.warning() {
            panic!("atomic rewrite reported a warning: {warning:#}");
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "version: 2\n");
        assert_eq!(windows_dacl_digest(&path).unwrap(), expected_dacl);
    }

    #[cfg(windows)]
    #[test]
    fn windows_operator_artifacts_reject_untrusted_mutation_and_reparse_points() {
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let temp = authority_tempdir();
        let artifact = temp.path().join("credential");
        write_authority_file(&artifact, "credential").unwrap();
        let file = owner_only_options()
            .read(true)
            .write(true)
            .open(&artifact)
            .unwrap();
        apply_windows_test_dacl(&artifact, "D:P(A;;FA;;;OW)(A;ID;GW;;;AU)");
        let error =
            validate_windows_authority_handle_with_current_user(&file, false, true).unwrap_err();
        assert!(error
            .to_string()
            .contains("grants mutation rights to an untrusted principal"));
        assert!(open_operator_authority_file(&artifact, None).is_err());
        apply_windows_test_dacl(&artifact, "D:P(A;;FA;;;OW)(A;ID;GR;;;AU)");
        validate_windows_authority_handle_with_current_user(&file, false, true).unwrap();
        drop(file);

        let link = temp.path().join("credential-link");
        symlink_file(&artifact, &link).unwrap();
        assert!(lease_operator_authority_artifact(&link, None)
            .unwrap_err()
            .to_string()
            .contains("symlink"));
        let error = open_operator_authority_file(&link, None).unwrap_err();
        assert!(format!("{error:#}").contains("reparse point"));

        let directory = temp.path().join("modules");
        std::fs::create_dir(&directory).unwrap();
        let directory_link = temp.path().join("modules-link");
        symlink_dir(&directory, &directory_link).unwrap();
        let handle = open_parent_directory(&directory_link).unwrap();
        let error = validate_trusted_parent(&handle, &directory_link).unwrap_err();
        assert!(format!("{error:#}").contains("reparse point"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_owner_rights_descriptor_supports_fresh_write_recovery_and_reload() {
        let temp = authority_tempdir();
        let destination = temp.path().join("state").join("learned.yaml");
        create_hardened_file_if_absent(&destination, "version: 1\n").unwrap();
        let first = load_learning_file_snapshot(&destination).unwrap();
        let outcome = write_learning_file_atomically_for_locked_snapshot(
            &destination,
            &first,
            "version: 1\nrules: []\n",
        )
        .unwrap();
        let (second, warning) = outcome.into_parts();
        assert!(warning.is_some_and(|warning| warning
            .to_string()
            .contains("does not expose independent directory-entry flush confirmation")));
        write_learning_file_atomically_for_locked_snapshot(
            &destination,
            &second,
            "version: 1\nrules: []\nobservations: {}\n",
        )
        .unwrap();
        recover_learning_file_transaction(&destination).unwrap();
        let file = owner_only_options()
            .read(true)
            .write(true)
            .open(&destination)
            .unwrap();
        validate_authority_file(&file).unwrap();
        DestinationLock::acquire(&destination).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_owner_group_preflight_accepts_non_elevated_rewrites_and_rejects_mismatch() {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };

        fn descriptor(sddl: &str) -> Vec<u8> {
            let sddl = sddl
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>();
            let mut descriptor = std::ptr::null_mut();
            let mut length = 0;
            assert_ne!(
                unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddl.as_ptr(),
                        SDDL_REVISION_1,
                        &mut descriptor,
                        &mut length,
                    )
                },
                0
            );
            let bytes = unsafe {
                std::slice::from_raw_parts(descriptor.cast::<u8>(), length as usize).to_vec()
            };
            unsafe { LocalFree(descriptor) };
            bytes
        }

        let system = descriptor("O:SYG:SYD:P(A;;FA;;;SY)");
        let administrators = descriptor("O:BAG:BAD:P(A;;FA;;;BA)");
        assert!(ensure_windows_owner_group_compatible(&system, &system).is_ok());
        assert!(ensure_windows_owner_group_compatible(&system, &administrators).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_atomic_writer_preserves_restricted_security_and_attributes() {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::{
            GetFileSecurityW, SetFileSecurityW, DACL_SECURITY_INFORMATION,
            GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileAttributesW, SetFileAttributesW, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_HIDDEN,
            FILE_ATTRIBUTE_NORMAL,
        };

        fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
            value.encode_wide().chain(std::iter::once(0)).collect()
        }
        fn security(path: &Path) -> Vec<u8> {
            let path = wide(path.as_os_str());
            let information =
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
            let mut needed = 0;
            unsafe {
                GetFileSecurityW(
                    path.as_ptr(),
                    information,
                    std::ptr::null_mut(),
                    0,
                    &mut needed,
                );
            }
            let mut descriptor = vec![0u8; needed as usize];
            let loaded = unsafe {
                GetFileSecurityW(
                    path.as_ptr(),
                    information,
                    descriptor.as_mut_ptr().cast(),
                    needed,
                    &mut needed,
                )
            };
            assert_ne!(loaded, 0);
            descriptor
        }

        let temp = authority_tempdir();
        let path = temp.path().join("learned.yaml");
        write_authority_file(&path, "old").unwrap();
        let path_wide = wide(path.as_os_str());
        let sddl = wide(std::ffi::OsStr::new("D:P(A;;FA;;;OW)"));
        let mut descriptor = std::ptr::null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(converted, 0);
        let secured = unsafe {
            SetFileSecurityW(
                path_wide.as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor,
            )
        };
        unsafe {
            LocalFree(descriptor);
        }
        assert_ne!(secured, 0);
        assert_ne!(
            unsafe { SetFileAttributesW(path_wide.as_ptr(), FILE_ATTRIBUTE_HIDDEN) },
            0
        );
        let before_security = security(&path);
        let before_dacl = windows_dacl_digest(&path).unwrap();
        let before_attributes = unsafe { GetFileAttributesW(path_wide.as_ptr()) };

        write_learning_file_atomically(&path, "new").unwrap();
        write_learning_file_atomically(&path, "newer").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "newer");
        let after_security = security(&path);
        ensure_windows_owner_group_compatible(&before_security, &after_security).unwrap();
        assert_eq!(windows_dacl_digest(&path).unwrap(), before_dacl);
        let after_attributes = unsafe { GetFileAttributesW(path_wide.as_ptr()) };
        assert_eq!(
            after_attributes & !FILE_ATTRIBUTE_ARCHIVE,
            before_attributes & !FILE_ATTRIBUTE_ARCHIVE
        );
        assert_ne!(after_attributes & FILE_ATTRIBUTE_ARCHIVE, 0);
        assert_ne!(
            unsafe { SetFileAttributesW(path_wide.as_ptr(), FILE_ATTRIBUTE_NORMAL) },
            0
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_recovery_restores_only_the_recorded_backup_dacl() {
        let temp = authority_tempdir();
        let destination = temp.path().join("learned.yaml");
        let mut original = open_owner_only_new(&destination).unwrap();
        original.write_all(b"original").unwrap();
        original.sync_all().unwrap();
        drop(original);
        let identity = "00000000000000000000000000000026";
        let paths = transaction_paths(&destination, identity).unwrap();
        copy_file_owner_only(&destination, &paths.backup).unwrap();
        let security_generation = windows_dacl_digest(&destination).unwrap();
        std::fs::remove_file(&destination).unwrap();
        write_transaction_marker(
            &paths,
            &LearningTransactionMarker {
                version: LEARNING_TRANSACTION_VERSION,
                transaction_id: identity.to_string(),
                phase: LearningTransactionPhase::Replacing,
                candidate_generation: content_digest(b"candidate"),
                expected_generation: Some(content_digest(b"original")),
                expected_security_generation: Some(security_generation.clone()),
                expected_unix_mode: None,
            },
        )
        .unwrap();

        recover_learning_file_transaction(&destination).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"original");
        assert_eq!(
            windows_dacl_digest(&destination).unwrap(),
            security_generation
        );
    }

    #[test]
    fn ssh_parser_keeps_prefix_through_host() {
        let args = vec![
            "-i".to_string(),
            "key.pem".to_string(),
            "-o".to_string(),
            "StrictHostKeyChecking=no".to_string(),
            "fw.example".to_string(),
            "configctl".to_string(),
            "system".to_string(),
            "status".to_string(),
        ];
        let parsed = parse_ssh_command(&args).expect("ssh parts");
        assert_eq!(parsed.host, "fw.example");
        assert_eq!(parsed.remote_args[0], "configctl");
        assert_eq!(
            parsed.prefix_args,
            vec![
                "-i".to_string(),
                "key.pem".to_string(),
                "-o".to_string(),
                "StrictHostKeyChecking=no".to_string(),
                "fw.example".to_string()
            ]
        );
    }

    #[test]
    fn opnsense_ssh_candidate_promotes_service_shim() {
        let args = vec![
            "firewall".to_string(),
            "configctl".to_string(),
            "system".to_string(),
            "status".to_string(),
        ];
        let candidate =
            RuleCandidate::from_command("ssh", &args, "ssh firewall configctl system status");
        assert_eq!(candidate.service, "opnsense-api");
        assert_eq!(
            candidate.pattern,
            crate::redact::command_metadata("ssh", &args)
        );
        assert_eq!(
            candidate.equivalent_patterns,
            vec![crate::redact::command_metadata(
                "opnsense-api",
                &["system".to_string(), "status".to_string()]
            )]
        );
        assert_eq!(
            candidate.shim.as_ref().map(|shim| shim.name.as_str()),
            Some("opnsense-api")
        );
    }

    #[test]
    fn repeated_low_risk_approval_becomes_a_candidate_not_a_bypass() {
        let temp = authority_tempdir();
        let config = LearningConfig {
            path: temp.path().join("learned.yaml"),
            min_approvals: 2,
            max_risk: 2,
            auto_shim: AutoShimMode::Suggest,
        };
        let mut store = LearnedRuleStore::load(config).unwrap();
        let args = vec!["status".to_string()];
        let first = store
            .record_approval("opnsense-api", &args, "opnsense-api status", Some(1), "ok")
            .unwrap()
            .unwrap();
        assert!(!first.is_candidate);
        assert_eq!(store.rule_count(), 0);

        let second = store
            .record_approval("opnsense-api", &args, "opnsense-api status", Some(1), "ok")
            .unwrap()
            .unwrap();
        assert!(second.is_candidate);
        // Crossing the threshold persists a reviewable candidate record, but
        // grants nothing: this module has no lookup that can return an allow.
        assert_eq!(store.rule_count(), 1);
    }

    #[test]
    fn failed_learned_rule_write_keeps_memory_and_durable_state_unchanged() {
        let temp = authority_tempdir();
        let path = temp.path().join("learned.yaml");
        let config = LearningConfig {
            path: path.clone(),
            min_approvals: 2,
            max_risk: 2,
            auto_shim: AutoShimMode::Suggest,
        };
        let mut store = LearnedRuleStore::load(config).unwrap();
        let command_args = vec!["status".to_string()];
        store
            .record_approval(
                "fixturectl",
                &command_args,
                "fixturectl status",
                Some(1),
                "safe",
            )
            .unwrap();
        let before_memory = store.data.clone();
        let before_file = std::fs::read(&path).unwrap();
        let blocker = temp.path().join("blocker");
        write_authority_file(&blocker, "not a directory").unwrap();
        store.config.path = blocker.join("learned.yaml");

        assert!(store
            .record_approval(
                "fixturectl",
                &command_args,
                "fixturectl status",
                Some(1),
                "safe",
            )
            .is_err());
        assert_eq!(store.data, before_memory);
        assert_eq!(std::fs::read(path).unwrap(), before_file);
    }

    #[test]
    fn sensitive_learning_records_are_rejected_and_purged_idempotently() {
        let temp = authority_tempdir();
        let path = temp.path().join("learned.yaml");
        let config = LearningConfig {
            path: path.clone(),
            min_approvals: 1,
            max_risk: 2,
            auto_shim: AutoShimMode::Suggest,
        };
        let mut store = LearnedRuleStore::load(config.clone()).unwrap();
        let safe_args = vec!["status".to_string()];
        store
            .record_approval("fixturectl", &safe_args, "fixturectl status", Some(1), "ok")
            .unwrap();
        assert!(store
            .data
            .observations
            .values()
            .all(|observation| observation.last_command.contains("[argv-sha256:")));
        let safe_bytes = std::fs::read(&path).unwrap();
        let value = ["q", "7"].concat();
        assert!(store
            .record_approval(
                "curl",
                &["-u".to_string(), value.clone()],
                &format!("curl -u {value}"),
                Some(1),
                "ignored"
            )
            .unwrap()
            .is_none());
        assert_eq!(std::fs::read(&path).unwrap(), safe_bytes);

        let mut contaminated = store.data.clone();
        for observation in contaminated.observations.values_mut() {
            observation.pattern = "fixturectl status".to_string();
            observation.last_command = "fixturectl status".to_string();
        }
        contaminated.rules[0].pattern = "fixturectl status".to_string();
        let mut observation = contaminated.observations.values().next().unwrap().clone();
        observation.pattern = format!("curl -u {value}");
        observation.last_command = observation.pattern.clone();
        contaminated
            .observations
            .insert("sensitive".to_string(), observation);
        let mut rule = contaminated.rules[0].clone();
        rule.pattern = format!("curl --user={value}");
        contaminated.rules.push(rule);
        write_learning_file_atomically(&path, &serde_yaml_ng::to_string(&contaminated).unwrap())
            .unwrap();

        let loaded = LearnedRuleStore::load(config.clone()).unwrap();
        assert_eq!(loaded.data.observations.len(), 1);
        assert_eq!(loaded.data.rules.len(), 1);
        assert!(loaded.data.rules[0]
            .pattern
            .starts_with("[legacy-command-sha256:"));
        assert!(loaded
            .data
            .observations
            .values()
            .all(|observation| observation
                .last_command
                .starts_with("[legacy-command-sha256:")));
        let sanitized = std::fs::read(&path).unwrap();
        assert!(!sanitized
            .windows(value.len())
            .any(|window| window == value.as_bytes()));
        LearnedRuleStore::load(config).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), sanitized);
    }

    #[test]
    fn learned_rule_prose_is_sanitized_without_changing_safe_authority() {
        let temp = authority_tempdir();
        let path = temp.path().join("learned.yaml");
        let config = LearningConfig {
            path: path.clone(),
            min_approvals: 1,
            max_risk: 2,
            auto_shim: AutoShimMode::Suggest,
        };
        let value = ["q", "7"].concat();
        let reason = format!("password={value}");
        let mut store = LearnedRuleStore::load(config.clone()).unwrap();
        store
            .record_approval(
                "fixturectl",
                &["status".to_string()],
                "fixturectl status",
                Some(1),
                &reason,
            )
            .unwrap();
        let expected_pattern = store.data.rules[0].pattern.clone();
        assert!(!std::fs::read(&path)
            .unwrap()
            .windows(value.len())
            .any(|window| window == value.as_bytes()));

        let mut contaminated = store.data.clone();
        contaminated
            .observations
            .values_mut()
            .for_each(|observation| observation.last_reason = reason.clone());
        contaminated.rules[0].last_reason = reason.clone();
        contaminated.rules[0].shim = Some(LearnedShim {
            name: "fixture-wrapper".to_string(),
            target_binary: "fixturectl".to_string(),
            target_args: vec!["status".to_string()],
            description: reason,
        });
        write_learning_file_atomically(&path, &serde_yaml_ng::to_string(&contaminated).unwrap())
            .unwrap();

        let loaded = LearnedRuleStore::load(config.clone()).unwrap();
        assert_eq!(loaded.data.rules.len(), 1);
        assert_eq!(loaded.data.rules[0].pattern, expected_pattern);
        let sanitized = std::fs::read(&path).unwrap();
        assert!(!sanitized
            .windows(value.len())
            .any(|window| window == value.as_bytes()));
        LearnedRuleStore::load(config).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), sanitized);
    }

    #[test]
    fn high_risk_approval_is_not_learned() {
        let temp = authority_tempdir();
        let config = LearningConfig {
            path: temp.path().join("learned.yaml"),
            min_approvals: 1,
            max_risk: 2,
            auto_shim: AutoShimMode::Suggest,
        };
        let mut store = LearnedRuleStore::load(config).unwrap();
        let result = store
            .record_approval(
                "rm",
                &["-rf".into(), "/".into()],
                "rm -rf /",
                Some(9),
                "bad",
            )
            .unwrap()
            .unwrap();
        assert!(result.skipped_reason.is_some());
        assert_eq!(store.rule_count(), 0);
    }

    #[test]
    fn shell_control_without_spaces_is_not_learned() {
        let temp = authority_tempdir();
        let config = LearningConfig {
            path: temp.path().join("learned.yaml"),
            min_approvals: 1,
            max_risk: 2,
            auto_shim: AutoShimMode::Suggest,
        };
        let mut store = LearnedRuleStore::load(config).unwrap();
        let result = store
            .record_approval(
                "ssh",
                &[
                    "firewall".into(),
                    "configctl".into(),
                    "status;reboot".into(),
                ],
                "ssh firewall configctl status;reboot",
                Some(1),
                "ok",
            )
            .unwrap()
            .unwrap();
        assert!(result.skipped_reason.is_some());
        assert_eq!(store.rule_count(), 0);
    }

    #[test]
    fn leading_privileged_command_is_not_learned() {
        assert!(looks_dangerous_for_learned_allow("sudo configctl status"));
        assert!(looks_dangerous_for_learned_allow("reboot"));
        assert!(looks_dangerous_for_learned_allow("shutdown /s"));
        assert!(looks_dangerous_for_learned_allow("halt"));
        assert!(looks_dangerous_for_learned_allow("su root"));
    }

    #[test]
    fn stale_learning_instances_reapply_observations_without_losing_authority() {
        let temp = authority_tempdir();
        let config = LearningConfig {
            path: temp.path().join("learned.yaml"),
            min_approvals: 2,
            max_risk: 2,
            auto_shim: AutoShimMode::Suggest,
        };
        let mut first = LearnedRuleStore::load(config.clone()).unwrap();
        let mut second = LearnedRuleStore::load(config.clone()).unwrap();
        let args = ["status".to_string()];

        first
            .record_approval("fixturectl", &args, "fixturectl status", Some(1), "safe")
            .unwrap();
        let outcome = second
            .record_approval("fixturectl", &args, "fixturectl status", Some(1), "safe")
            .unwrap()
            .unwrap();
        assert_eq!(outcome.approvals, 2);

        let loaded = LearnedRuleStore::load(config).unwrap();
        assert_eq!(loaded.rule_count(), 1);
        assert_eq!(
            loaded.data.observations.values().next().unwrap().approvals,
            2
        );
    }

    #[test]
    fn successor_commit_after_replacement_does_not_replay_the_first_observation() {
        let temp = authority_tempdir();
        let config = LearningConfig {
            path: temp.path().join("learned.yaml"),
            min_approvals: 3,
            max_risk: 2,
            auto_shim: AutoShimMode::Off,
        };
        let mut first = LearnedRuleStore::load(config.clone()).unwrap();
        let mut successor = LearnedRuleStore::load(config.clone()).unwrap();
        let hook_identity =
            crate::redact::command_metadata("fixturectl", &["post-commit-race".to_string()]);
        let (committed, release) = pause_post_commit_adoption_for_test(&hook_identity);

        let first_thread = std::thread::spawn(move || {
            let args = ["post-commit-race".to_string()];
            let outcome = first
                .record_approval(
                    "fixturectl",
                    &args,
                    "fixturectl post-commit-race",
                    Some(1),
                    "safe",
                )
                .unwrap()
                .unwrap();
            (first, outcome.approvals)
        });
        committed.wait();
        let args = ["post-commit-race".to_string()];
        let successor_outcome = successor
            .record_approval(
                "fixturectl",
                &args,
                "fixturectl post-commit-race",
                Some(1),
                "safe",
            )
            .unwrap()
            .unwrap();
        assert_eq!(successor_outcome.approvals, 2);
        release.wait();
        let (mut first, first_approvals) = first_thread.join().unwrap();
        assert_eq!(first_approvals, 1);

        let final_outcome = first
            .record_approval(
                "fixturectl",
                &args,
                "fixturectl post-commit-race",
                Some(1),
                "safe",
            )
            .unwrap()
            .unwrap();
        assert_eq!(final_outcome.approvals, 3);
        let loaded = LearnedRuleStore::load(config).unwrap();
        assert_eq!(
            loaded.data.observations.values().next().unwrap().approvals,
            3
        );
    }

    #[test]
    fn three_stale_learning_instances_preserve_every_commutative_observation() {
        let temp = authority_tempdir();
        let config = LearningConfig {
            path: temp.path().join("learned.yaml"),
            min_approvals: 3,
            max_risk: 3,
            auto_shim: AutoShimMode::Off,
        };
        let mut stores = [
            LearnedRuleStore::load(config.clone()).unwrap(),
            LearnedRuleStore::load(config.clone()).unwrap(),
            LearnedRuleStore::load(config.clone()).unwrap(),
        ];
        let args = vec!["status".to_string()];
        for store in &mut stores {
            store
                .record_approval("fixturectl", &args, "fixturectl status", Some(1), "safe")
                .unwrap();
        }
        let loaded = LearnedRuleStore::load(config).unwrap();
        assert_eq!(
            loaded.data.observations.values().next().unwrap().approvals,
            3
        );
        assert_eq!(loaded.rule_count(), 1);
    }

    #[test]
    fn markerless_staging_is_cleaned_before_authority_is_loaded() {
        let temp = authority_tempdir();
        let destination = temp.path().join("learned.yaml");
        write_authority_file(&destination, "safe").unwrap();
        let paths = transaction_paths(&destination, "000000000000000000000000000000aa").unwrap();
        let mut staging = open_owner_only_new(&paths.marker_staging).unwrap();
        staging.write_all(b"{").unwrap();
        staging.sync_all().unwrap();
        drop(staging);

        let first = load_learning_file_snapshot(&destination).unwrap();
        assert_eq!(first.content(), Some(b"safe".as_slice()));
        assert!(!paths.marker_staging.exists());
        let second = load_learning_file_snapshot(&destination).unwrap();
        assert!(first.same_authority(&second));
    }

    #[test]
    fn concurrent_equivalent_initialization_converges() {
        let temp = authority_tempdir();
        let destination = temp.path().join("verbs.yaml");
        let first_path = destination.clone();
        let second_path = destination.clone();
        let first =
            std::thread::spawn(move || create_hardened_file_if_absent(&first_path, "verbs: []\n"));
        let second =
            std::thread::spawn(move || create_hardened_file_if_absent(&second_path, "verbs: []\n"));
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();
        let snapshot = load_learning_file_snapshot(&destination).unwrap();
        assert_eq!(snapshot.content(), Some(b"verbs: []\n".as_slice()));
    }

    #[cfg(unix)]
    #[test]
    fn untrusted_parent_and_replaced_lock_fail_closed() {
        use std::os::unix::fs::PermissionsExt;

        let temp = authority_tempdir();
        let unsafe_parent = temp.path().join("unsafe");
        create_authority_directory(&unsafe_parent).unwrap();
        std::fs::set_permissions(&unsafe_parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(DestinationLock::acquire(&unsafe_parent.join("learned.yaml")).is_err());

        let same_group_parent = temp.path().join("same-group");
        create_authority_directory(&same_group_parent).unwrap();
        std::fs::set_permissions(&same_group_parent, std::fs::Permissions::from_mode(0o770))
            .unwrap();
        assert!(DestinationLock::acquire(&same_group_parent.join("learned.yaml")).is_err());

        let writable_destination = temp.path().join("writable.yaml");
        write_authority_file(&writable_destination, "safe").unwrap();
        std::fs::set_permissions(
            &writable_destination,
            std::fs::Permissions::from_mode(0o620),
        )
        .unwrap();
        assert!(load_learning_file_snapshot(&writable_destination).is_err());

        let destination = temp.path().join("safe.yaml");
        let lock = DestinationLock::acquire(&destination).unwrap();
        let displaced = temp.path().join("displaced-lock");
        std::fs::rename(&lock.canonical_lock_path, &displaced).unwrap();
        write_authority_file(&lock.canonical_lock_path, "replacement").unwrap();
        assert!(lock.verify_parent_binding().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn current_journal_rejects_unsafe_recorded_modes_before_recovery() {
        use std::os::unix::fs::PermissionsExt;

        let temp = authority_tempdir();
        let destination = temp.path().join("learned.yaml");
        write_authority_file(&destination, "safe").unwrap();
        let original_mode = std::fs::metadata(&destination)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        let paths = transaction_paths(&destination, "000000000000000000000000000000bb").unwrap();
        for mode in [0o700, 0o660, 0o602, 0o4600, 0o400, 0o10_600] {
            let marker = LearningTransactionMarker {
                version: LEARNING_TRANSACTION_VERSION,
                transaction_id: "000000000000000000000000000000bb".to_string(),
                phase: LearningTransactionPhase::ReplacementDurable,
                candidate_generation: content_digest(b"safe"),
                expected_generation: Some(content_digest(b"original")),
                expected_security_generation: None,
                expected_unix_mode: Some(mode),
            };
            write_authority_file(&paths.marker, serde_json::to_vec(&marker).unwrap()).unwrap();
            assert!(read_transaction_marker(&paths.marker, &destination).is_err());
            assert_eq!(
                std::fs::metadata(&destination)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                original_mode
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn locked_snapshot_rejects_parent_retarget_during_read() {
        let temp = authority_tempdir();
        let parent = temp.path().join("authority");
        let moved = temp.path().join("authority-moved");
        create_authority_directory(&parent).unwrap();
        let destination = parent.join("learned.yaml");
        write_authority_file(&destination, "safe").unwrap();
        let lock = DestinationLock::acquire(&destination).unwrap();
        std::fs::rename(&parent, &moved).unwrap();
        create_authority_directory(&parent).unwrap();
        write_authority_file(parent.join("learned.yaml"), "other").unwrap();
        assert!(read_learning_file_snapshot_locked(&lock).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn committed_recovery_restores_journaled_file_mode_before_cleanup() {
        use std::os::unix::fs::PermissionsExt;

        let temp = authority_tempdir();
        let destination = temp.path().join("learned.yaml");
        write_authority_file(&destination, "candidate").unwrap();
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o600)).unwrap();
        let identity = "000000000000000000000000000000bb";
        let paths = transaction_paths(&destination, identity).unwrap();
        write_authority_file(&paths.backup, "original").unwrap();
        write_transaction_marker(
            &paths,
            &LearningTransactionMarker {
                version: LEARNING_TRANSACTION_VERSION,
                transaction_id: identity.to_string(),
                phase: LearningTransactionPhase::Replacing,
                candidate_generation: content_digest(b"candidate"),
                expected_generation: Some(content_digest(b"original")),
                expected_security_generation: None,
                expected_unix_mode: Some(0o640),
            },
        )
        .unwrap();

        recover_learning_file_transaction(&destination).unwrap();
        assert_eq!(
            std::fs::metadata(destination).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }
}
