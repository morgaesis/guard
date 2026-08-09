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
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::env::now_unix;
use crate::redact::{
    command_contains_sensitive_literals, flattened_command_contains_sensitive_literals,
    redact_output_text,
};

/// Outcome of an atomic learning-file replacement.
///
/// `CommittedWithWarning` means the destination contains the requested bytes,
/// but a later durability or cleanup operation failed. Callers must adopt the
/// candidate in memory before returning the warning to avoid diverging from
/// the authority on disk.
#[derive(Debug)]
pub(crate) enum LearningWriteOutcome {
    Durable,
    CommittedWithWarning(anyhow::Error),
}

impl LearningWriteOutcome {
    pub(crate) fn warning(self) -> Option<anyhow::Error> {
        match self {
            Self::Durable => None,
            Self::CommittedWithWarning(error) => Some(error),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LearningTransactionMarker {
    version: u32,
    destination: String,
    source: String,
    backup: String,
    content_sha256: String,
    original_sha256: Option<String>,
    had_destination: bool,
}

const LEARNING_TRANSACTION_VERSION: u32 = 1;
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

fn preserve_recovery_metadata(source: &Path, recovery: &Path) -> Result<()> {
    if let Ok(metadata) = std::fs::metadata(source) {
        std::fs::set_permissions(recovery, metadata.permissions()).with_context(|| {
            format!(
                "failed to preserve recovery metadata for {}",
                source.display()
            )
        })?;
    }
    #[cfg(windows)]
    copy_accessible_windows_security(source, recovery)?;
    std::fs::File::open(recovery)?
        .sync_all()
        .with_context(|| format!("failed to sync recovery metadata for {}", source.display()))
}

fn marker_component(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .context("learning transaction path is not a portable file name")
}

fn write_transaction_marker(path: &Path, marker: &LearningTransactionMarker) -> Result<()> {
    let bytes = serde_json::to_vec(marker)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed to create transaction marker {}", path.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("failed to write transaction marker {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync transaction marker {}", path.display()))
}

fn validate_transaction_component(parent: &Path, value: &str) -> Result<PathBuf> {
    let candidate = Path::new(value);
    if candidate.components().count() != 1 || candidate.file_name().is_none() {
        anyhow::bail!("invalid learning transaction component")
    }
    Ok(parent.join(candidate))
}

/// Recover a destination-bound learning transaction before loading authority.
/// A malformed or ambiguous state fails closed instead of guessing which copy
/// is authoritative.
pub(crate) fn recover_learning_file_transaction(path: &Path) -> Result<()> {
    let marker_path = learning_sibling(path, "transaction", None);
    if !marker_path.exists() {
        return Ok(());
    }
    let marker_bytes = std::fs::read(&marker_path).with_context(|| {
        format!(
            "failed to read transaction marker {}",
            marker_path.display()
        )
    })?;
    let marker: LearningTransactionMarker = serde_json::from_slice(&marker_bytes)
        .with_context(|| format!("invalid transaction marker {}", marker_path.display()))?;
    if marker.version != LEARNING_TRANSACTION_VERSION
        || marker.destination != marker_component(path)?
    {
        anyhow::bail!("transaction marker does not belong to the learning file")
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let source = validate_transaction_component(parent, &marker.source)?;
    let backup = validate_transaction_component(parent, &marker.backup)?;
    let destination_digest = std::fs::read(path).ok().map(|bytes| content_digest(&bytes));

    if destination_digest.as_deref() == Some(marker.content_sha256.as_str()) {
        remove_if_present(&source)?;
        remove_if_present(&backup)?;
        remove_if_present(&marker_path)?;
        sync_learning_parent(parent)?;
        return Ok(());
    }

    if path.exists() {
        if marker.had_destination {
            let current = std::fs::read(path)?;
            if marker.original_sha256.as_deref() != Some(content_digest(&current).as_str()) {
                anyhow::bail!("learning transaction destination does not match its original digest")
            }
            if backup.exists() {
                let old = std::fs::read(&backup)?;
                if current != old {
                    anyhow::bail!(
                        "learning transaction has conflicting destination and backup data"
                    )
                }
            }
        } else {
            anyhow::bail!("new learning-file transaction has an unexpected destination")
        }
        remove_if_present(&source)?;
        remove_if_present(&backup)?;
        remove_if_present(&marker_path)?;
        sync_learning_parent(parent)?;
        return Ok(());
    }

    if marker.had_destination {
        if !backup.exists() {
            anyhow::bail!("learning transaction lost both destination and recovery backup")
        }
        rename_write_through(&backup, path).with_context(|| {
            format!(
                "failed to restore learning file {} from backup",
                path.display()
            )
        })?;
    }
    remove_if_present(&source)?;
    remove_if_present(&marker_path)?;
    sync_learning_parent(parent)?;
    Ok(())
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
    // use write-through moves, and destination handles are flushed explicitly.
    Ok(())
}

#[cfg(windows)]
fn copy_accessible_windows_security(source: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::{
        GetFileSecurityW, GetSecurityDescriptorControl, SetFileSecurityW,
        DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
    };
    let wide = |value: &std::ffi::OsStr| {
        value
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>()
    };
    let source = wide(source.as_os_str());
    let information =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut needed = 0;
    unsafe {
        GetFileSecurityW(
            source.as_ptr(),
            information,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to read recovery source owner, group, and DACL");
    }
    let mut descriptor = vec![0u8; needed as usize];
    if unsafe {
        GetFileSecurityW(
            source.as_ptr(),
            information,
            descriptor.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to read recovery source owner, group, and DACL");
    }
    let mut control = 0;
    let mut revision = 0;
    if unsafe {
        GetSecurityDescriptorControl(descriptor.as_mut_ptr().cast(), &mut control, &mut revision)
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect recovery source DACL controls");
    }
    let information = information
        | if control & SE_DACL_PROTECTED != 0 {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            0
        };
    let destination = wide(destination.as_os_str());
    if unsafe {
        SetFileSecurityW(
            destination.as_ptr(),
            information,
            descriptor.as_mut_ptr().cast(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to preserve recovery owner, group, and DACL");
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_learning_parent(_parent: &Path) -> Result<()> {
    anyhow::bail!("learning-file durability is unsupported on this platform")
}

#[cfg(unix)]
pub(crate) fn write_learning_file_atomically(
    path: &Path,
    content: &str,
) -> Result<LearningWriteOutcome> {
    write_learning_file_atomically_with_sync(path, content, sync_parent_directory)
}

#[cfg(windows)]
pub(crate) fn write_learning_file_atomically(
    path: &Path,
    content: &str,
) -> Result<LearningWriteOutcome> {
    write_learning_file_atomically_windows(path, content)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn write_learning_file_atomically(
    _path: &Path,
    _content: &str,
) -> Result<LearningWriteOutcome> {
    anyhow::bail!("atomic learning-file durability is unsupported on this platform")
}

#[cfg(any(unix, test))]
fn write_learning_file_atomically_with_sync<F>(
    path: &Path,
    content: &str,
    mut sync_directory: F,
) -> Result<LearningWriteOutcome>
where
    F: FnMut(&Path) -> Result<()>,
{
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    ensure_durable_directory(parent, &mut sync_directory)?;
    recover_learning_file_transaction(path)?;
    let identity = rand::random::<u128>();
    let source = learning_sibling(path, "new", Some(identity));
    let backup = learning_sibling(path, "old", Some(identity));
    let marker_path = learning_sibling(path, "transaction", None);
    let marker = LearningTransactionMarker {
        version: LEARNING_TRANSACTION_VERSION,
        destination: marker_component(path)?,
        source: marker_component(&source)?,
        backup: marker_component(&backup)?,
        content_sha256: content_digest(content.as_bytes()),
        original_sha256: std::fs::read(path).ok().map(|bytes| content_digest(&bytes)),
        had_destination: path.exists(),
    };
    write_transaction_marker(&marker_path, &marker)?;
    sync_directory(parent)
        .with_context(|| format!("failed to sync parent directory {}", parent.display()))?;
    let mut temporary = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&source)
        .with_context(|| format!("failed to create temporary file in {}", parent.display()))?;
    if let Ok(metadata) = std::fs::metadata(path) {
        temporary
            .set_permissions(metadata.permissions())
            .with_context(|| format!("failed to preserve permissions for {}", path.display()))?;
    }
    temporary
        .write_all(content.as_bytes())
        .with_context(|| format!("failed to write temporary file for {}", path.display()))?;
    temporary
        .sync_all()
        .with_context(|| format!("failed to sync temporary file for {}", path.display()))?;
    drop(temporary);
    if path.exists() {
        std::fs::hard_link(path, &backup)
            .with_context(|| format!("failed to create recovery backup for {}", path.display()))?;
        sync_directory(parent)
            .with_context(|| format!("failed to sync recovery backup for {}", path.display()))?;
    }
    if let Err(error) = std::fs::rename(&source, path) {
        let recovery = recover_learning_file_transaction(path);
        return match recovery {
            Ok(()) => Err(error).with_context(|| format!("failed to replace {}", path.display())),
            Err(recovery_error) => anyhow::bail!(
                "failed to replace {} and recovery failed: {} (replacement error: {})",
                path.display(),
                recovery_error,
                error
            ),
        };
    }
    let mut warning = sync_directory(parent)
        .with_context(|| format!("failed to sync parent directory {}", parent.display()))
        .err();
    match remove_if_present(&backup) {
        Ok(()) => {
            if let Err(error) = remove_if_present(&marker_path) {
                warning.get_or_insert(error);
            }
        }
        Err(error) => {
            // Keep the destination-bound marker so startup can account for
            // the retained backup instead of leaving an untracked authority
            // copy beside the store.
            warning.get_or_insert(error);
        }
    }
    if let Err(error) = sync_directory(parent)
        .with_context(|| format!("failed to sync transaction cleanup in {}", parent.display()))
    {
        warning.get_or_insert(error);
    }
    Ok(match warning {
        Some(error) => LearningWriteOutcome::CommittedWithWarning(error),
        None => LearningWriteOutcome::Durable,
    })
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
        match std::fs::create_dir(&created) {
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

#[cfg(test)]
fn replace_finalized_learning_file<F>(source: PathBuf, destination: &Path, replace: F) -> Result<()>
where
    F: FnOnce(&Path, &Path) -> std::io::Result<()>,
{
    match replace(&source, destination) {
        Ok(()) => Ok(()),
        Err(replace_error) => match std::fs::remove_file(&source) {
            Ok(()) => Err(replace_error)
                .with_context(|| format!("failed to replace {}", destination.display())),
            Err(cleanup_error) if cleanup_error.kind() == std::io::ErrorKind::NotFound => {
                Err(replace_error)
                    .with_context(|| format!("failed to replace {}", destination.display()))
            }
            Err(cleanup_error) => anyhow::bail!(
                "failed to replace {}; temporary file {} remains after cleanup failed: {} (replacement error: {})",
                destination.display(),
                source.display(),
                cleanup_error,
                replace_error
            ),
        },
    }
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
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let base = format!(
        ".{}.corrupt-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("learning"),
        content_digest(content)
    );
    let preserved = parent.join(format!("{base}.recovery"));
    if preserved.exists() {
        let verified = std::fs::read(&preserved)?;
        if verified == content {
            preserve_recovery_metadata(path, &preserved)?;
            return Ok(preserved);
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
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&preserved)
        .with_context(|| {
            format!(
                "failed to create corrupt-state copy in {}",
                parent.display()
            )
        })?;
    file.write_all(content)
        .with_context(|| format!("failed to preserve corrupt state for {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync corrupt-state copy for {}", path.display()))?;
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
    Ok(preserved)
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> Result<()> {
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn write_learning_file_atomically_windows(
    path: &Path,
    content: &str,
) -> Result<LearningWriteOutcome> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::{
        GetFileSecurityW, GetSecurityDescriptorControl, SetFileSecurityW,
        DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, ReplaceFileW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn security_information() -> u32 {
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
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
            return Err(std::io::Error::last_os_error())
                .context("failed to read the Windows owner, group, and DACL");
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
            return Err(std::io::Error::last_os_error())
                .context("failed to read the Windows owner, group, and DACL");
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
                .context("failed to apply the Windows owner, group, and DACL");
        }
        Ok(())
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

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;
    recover_learning_file_transaction(path)?;
    let destination_exists = path.exists();
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
    let identity = rand::random::<u128>();
    let source = learning_sibling(path, "new", Some(identity));
    let backup = learning_sibling(path, "old", Some(identity));
    let marker_path = learning_sibling(path, "transaction", None);
    let marker = LearningTransactionMarker {
        version: LEARNING_TRANSACTION_VERSION,
        destination: marker_component(path)?,
        source: marker_component(&source)?,
        backup: marker_component(&backup)?,
        content_sha256: content_digest(content.as_bytes()),
        original_sha256: std::fs::read(path).ok().map(|bytes| content_digest(&bytes)),
        had_destination: destination_exists,
    };
    write_transaction_marker(&marker_path, &marker)?;
    let mut temporary = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&source)
        .with_context(|| format!("failed to create temporary file in {}", parent.display()))?;
    temporary
        .write_all(content.as_bytes())
        .with_context(|| format!("failed to write temporary file for {}", path.display()))?;
    temporary
        .sync_all()
        .with_context(|| format!("failed to sync temporary file for {}", path.display()))?;
    if let Some((descriptor, information)) = &expected_security {
        apply_security_descriptor(&source, descriptor, *information).with_context(|| {
            format!(
                "cannot preserve security for learning file {}",
                path.display()
            )
        })?;
    }

    drop(temporary);
    let replacement = if destination_exists {
        // ReplaceFileW preserves the destination ACL and other documented file
        // metadata, including the system ACL when the filesystem supports it.
        // The ordinarily accessible owner, group, and DACL are also copied to
        // the source and verified without requiring ACCESS_SYSTEM_SECURITY.
        let destination_wide = wide(path.as_os_str());
        let source_wide = wide(source.as_os_str());
        let backup_wide = wide(backup.as_os_str());
        if unsafe {
            ReplaceFileW(
                destination_wide.as_ptr(),
                source_wide.as_ptr(),
                backup_wide.as_ptr(),
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
        move_with_write_through(&source, path, false)
    };
    if let Err(replacement_error) = replacement {
        return recover_failed_windows_replacement(
            &source,
            path,
            &backup,
            replacement_error,
            |backup, destination| move_with_write_through(backup, destination, false),
        )
        .map(|()| LearningWriteOutcome::Durable);
    }
    let finalize = (|| -> Result<()> {
        // ReplaceFileW's write-through flag is unsupported. Flushing a newly
        // opened destination handle provides file-level durability. Windows
        // does not expose a portable directory fsync.
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("failed to reopen replaced file {}", path.display()))?
            .sync_all()
            .with_context(|| format!("failed to flush replaced file {}", path.display()))?;
        if let Some((expected, information)) = &expected_security {
            let (actual, _) = read_security_descriptor(path)
                .with_context(|| format!("failed to verify security for {}", path.display()))?;
            if actual != *expected {
                apply_security_descriptor(path, expected, *information).with_context(|| {
                    format!("failed to restore security for {}", path.display())
                })?;
                let (restored, _) = read_security_descriptor(path).with_context(|| {
                    format!("failed to verify restored security for {}", path.display())
                })?;
                if restored != *expected {
                    anyhow::bail!(
                        "replacement changed the Windows security descriptor for {}",
                        path.display()
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
        return Ok(LearningWriteOutcome::CommittedWithWarning(finalize_error));
    }
    let mut warning = None;
    match remove_if_present(&backup) {
        Ok(()) => {
            if let Err(error) = remove_if_present(&marker_path) {
                warning.get_or_insert(error);
            }
        }
        Err(error) => {
            warning.get_or_insert(error);
        }
    }
    Ok(match warning {
        Some(error) => LearningWriteOutcome::CommittedWithWarning(error),
        None => LearningWriteOutcome::Durable,
    })
}

#[cfg(any(windows, test))]
fn recover_failed_windows_replacement<F>(
    source: &Path,
    destination: &Path,
    backup: &Path,
    replacement_error: std::io::Error,
    mut restore: F,
) -> Result<()>
where
    F: FnMut(&Path, &Path) -> std::io::Result<()>,
{
    if backup.exists() {
        if destination.exists() {
            if source.exists() {
                anyhow::bail!(
                    "failed to replace {}; source, destination, and recovery backup all remain for inspection: {}",
                    destination.display(),
                    replacement_error
                );
            }
            restore(destination, source).with_context(|| {
                format!(
                    "failed to preserve replacement data at {} before restoring {} from backup {}: {}",
                    source.display(),
                    destination.display(),
                    backup.display(),
                    replacement_error
                )
            })?;
        }
        restore(backup, destination).with_context(|| {
            format!(
                "failed to restore {} from backup {} after replacement failed; recoverable files remain: {}",
                destination.display(),
                backup.display(),
                replacement_error
            )
        })?;
        if !destination.exists() {
            anyhow::bail!(
                "replacement recovery reported success but {} is still missing; source {} remains",
                destination.display(),
                source.display()
            );
        }
    } else if !destination.exists() {
        if source.exists() {
            anyhow::bail!(
                "failed to replace {}; destination is missing and replacement data remains at {}: {}",
                destination.display(),
                source.display(),
                replacement_error
            );
        }
        anyhow::bail!(
            "failed to replace {}; no destination, source, or backup remains: {}",
            destination.display(),
            replacement_error
        );
    }
    if source.exists() {
        std::fs::remove_file(source).with_context(|| {
            format!(
                "failed to remove replacement source {} after preserving destination {}: {}",
                source.display(),
                destination.display(),
                replacement_error
            )
        })?;
    }
    Err(replacement_error).with_context(|| {
        format!(
            "failed to replace {}; the original destination is preserved",
            destination.display()
        )
    })
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
}

impl LearnedRuleStore {
    pub fn load(config: LearningConfig) -> Result<Self> {
        recover_learning_file_transaction(&config.path)?;
        let mut data = if config.path.exists() {
            let content = std::fs::read_to_string(&config.path)
                .with_context(|| format!("failed to read {}", config.path.display()))?;
            if content.trim().is_empty() {
                LearnedRulesFile::default()
            } else {
                serde_yaml_ng::from_str(&content)
                    .with_context(|| format!("failed to parse {}", config.path.display()))?
            }
        } else {
            LearnedRulesFile::default()
        };

        let original_observations = data.observations.len();
        let original_rules = data.rules.len();
        data.observations
            .retain(|_, observation| !learned_observation_contains_sensitive_literals(observation));
        data.rules
            .retain(|rule| !learned_rule_contains_sensitive_literals(rule));
        let mut changed =
            original_observations != data.observations.len() || original_rules != data.rules.len();
        changed |= sanitize_learned_rules_prose(&mut data);
        let store = Self { config, data };
        if changed {
            let outcome = store.save_data(&store.data)?;
            if let Some(error) = outcome.warning() {
                tracing::warn!(
                    "learning-file cleanup committed with a durability warning: {}",
                    error
                );
            }
        }
        Ok(store)
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
        let mut candidate = self.clone();
        let outcome = candidate.record_approval_in_memory(binary, args, command, risk, reason)?;
        self.commit_candidate(candidate.data)?;
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
        let risk = risk.unwrap_or(5);
        if risk > self.config.max_risk {
            return Ok(Some(LearningOutcome {
                service: binary.to_string(),
                pattern: command.to_string(),
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
                pattern: command.to_string(),
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
                last_command: command.to_string(),
                last_reason: reason.clone(),
                shim: candidate.shim.clone(),
            });

        observation.approvals = observation.approvals.saturating_add(1);
        observation.max_risk_seen = observation.max_risk_seen.max(risk);
        observation.last_seen_unix = now;
        observation.last_command = command.to_string();
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
        self.data = candidate;
        if let Some(error) = outcome.warning() {
            tracing::warn!(
                "learning-file replacement committed with a durability warning: {}",
                error
            );
        }
        Ok(())
    }

    fn save_data(&self, data: &LearnedRulesFile) -> Result<LearningWriteOutcome> {
        let mut data = data.clone();
        sanitize_learned_rules_prose(&mut data);
        let content = serde_yaml_ng::to_string(&data)?;
        write_learning_file_atomically(&self.config.path, &content)
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
        if let Some(shim) = observation.shim.as_mut() {
            changed |= sanitize(&mut shim.description);
        }
    }
    for rule in &mut data.rules {
        changed |= sanitize(&mut rule.last_reason);
        if let Some(shim) = rule.shim.as_mut() {
            changed |= sanitize(&mut shim.description);
        }
    }
    changed
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
    fn from_command(binary: &str, args: &[String], command: &str) -> Self {
        if binary.eq_ignore_ascii_case("ssh") {
            if let Some(ssh) = parse_ssh_command(args) {
                let service = infer_ssh_service(&ssh.host, &ssh.remote_args);
                let pattern = command.to_string();
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
                        vec![parts.join(" ")]
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
        let pattern = command.to_string();
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
    sanitize_name(binary.trim_end_matches(".exe"), "service")
}

fn infer_shim_name(service: &str, remote_tool: &str) -> String {
    if service == "opnsense-api" {
        return "opnsense-api".to_string();
    }
    let tool = sanitize_name(remote_tool.trim_end_matches(".exe"), "tool");
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
    fn atomic_writer_propagates_parent_sync_failure_after_replace() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("learned.yaml");
        std::fs::write(&path, "old").unwrap();
        let mut syncs = 0;
        let outcome = write_learning_file_atomically_with_sync(&path, "new", |_| {
            syncs += 1;
            if syncs == 3 {
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
    fn atomic_writer_durably_creates_each_missing_parent() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("one");
        let second = first.join("two");
        let path = second.join("learned.yaml");
        let mut synced = Vec::new();
        write_learning_file_atomically_with_sync(&path, "safe", |directory| {
            synced.push(directory.to_path_buf());
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
        assert!(synced[4..].iter().all(|directory| directory == &second));
    }

    fn test_marker(
        destination: &Path,
        source: &Path,
        backup: &Path,
        content: &[u8],
        had_destination: bool,
    ) -> PathBuf {
        let marker_path = learning_sibling(destination, "transaction", None);
        let marker = LearningTransactionMarker {
            version: LEARNING_TRANSACTION_VERSION,
            destination: marker_component(destination).unwrap(),
            source: marker_component(source).unwrap(),
            backup: marker_component(backup).unwrap(),
            content_sha256: content_digest(content),
            original_sha256: had_destination
                .then(|| std::fs::read(backup).ok())
                .flatten()
                .map(|bytes| content_digest(&bytes)),
            had_destination,
        };
        write_transaction_marker(&marker_path, &marker).unwrap();
        marker_path
    }

    #[test]
    fn learning_transaction_recovery_resolves_committed_and_interrupted_states() {
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("learned.yaml");
        let source = learning_sibling(&destination, "new", Some(1));
        let backup = learning_sibling(&destination, "old", Some(1));
        std::fs::write(&destination, "candidate").unwrap();
        std::fs::write(&source, "candidate").unwrap();
        std::fs::write(&backup, "original").unwrap();
        let marker = test_marker(&destination, &source, &backup, b"candidate", true);
        recover_learning_file_transaction(&destination).unwrap();
        assert_eq!(std::fs::read_to_string(&destination).unwrap(), "candidate");
        assert!(!source.exists());
        assert!(!backup.exists());
        assert!(!marker.exists());

        let source = learning_sibling(&destination, "new", Some(2));
        let backup = learning_sibling(&destination, "old", Some(2));
        std::fs::write(&source, "candidate-two").unwrap();
        std::fs::write(&backup, "original-two").unwrap();
        std::fs::remove_file(&destination).unwrap();
        let marker = test_marker(&destination, &source, &backup, b"candidate-two", true);
        recover_learning_file_transaction(&destination).unwrap();
        assert_eq!(
            std::fs::read_to_string(&destination).unwrap(),
            "original-two"
        );
        assert!(!source.exists());
        assert!(!marker.exists());
    }

    #[test]
    fn ambiguous_learning_transaction_fails_closed_and_preserves_copies() {
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("learned.yaml");
        let source = learning_sibling(&destination, "new", Some(3));
        let backup = learning_sibling(&destination, "old", Some(3));
        std::fs::write(&destination, "unexpected").unwrap();
        std::fs::write(&source, "candidate").unwrap();
        std::fs::write(&backup, "original").unwrap();
        let marker = test_marker(&destination, &source, &backup, b"candidate", true);

        assert!(recover_learning_file_transaction(&destination).is_err());
        assert!(destination.exists());
        assert!(source.exists());
        assert!(backup.exists());
        assert!(marker.exists());
    }

    #[test]
    fn corrupt_recovery_copy_is_content_addressed_and_preserves_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("learned.yaml");
        let bytes = b"not valid state";
        std::fs::write(&path, bytes).unwrap();
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

    #[test]
    fn windows_replacement_recovery_handles_documented_name_states() {
        let replacement_error = || std::io::Error::from_raw_os_error(1177);

        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        let backup = temp.path().join("backup");
        std::fs::write(&source, "new").unwrap();
        std::fs::write(&backup, "old").unwrap();
        assert!(recover_failed_windows_replacement(
            &source,
            &destination,
            &backup,
            replacement_error(),
            |from, to| std::fs::rename(from, to),
        )
        .is_err());
        assert_eq!(std::fs::read_to_string(&destination).unwrap(), "old");
        assert!(!source.exists());
        assert!(!backup.exists());

        for code in [1175, 1176] {
            let source = temp.path().join(format!("source-unchanged-{code}"));
            let destination = temp.path().join(format!("destination-unchanged-{code}"));
            let backup = temp.path().join(format!("backup-absent-{code}"));
            std::fs::write(&source, "new").unwrap();
            std::fs::write(&destination, "old").unwrap();
            assert!(recover_failed_windows_replacement(
                &source,
                &destination,
                &backup,
                std::io::Error::from_raw_os_error(code),
                |from, to| std::fs::rename(from, to),
            )
            .is_err());
            assert_eq!(std::fs::read_to_string(destination).unwrap(), "old");
            assert!(!source.exists());
        }
    }

    #[test]
    fn windows_replacement_recovery_never_discards_the_only_copies() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        let backup = temp.path().join("backup");
        std::fs::write(&source, "new").unwrap();
        std::fs::write(&backup, "old").unwrap();
        let error = recover_failed_windows_replacement(
            &source,
            &destination,
            &backup,
            std::io::Error::other("replacement failed"),
            |_, _| Err(std::io::Error::other("restore failed")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("recoverable files remain"));
        assert!(!destination.exists());
        assert!(source.exists());
        assert!(backup.exists());
    }

    #[test]
    fn failed_finalized_move_removes_the_temporary_file_and_preserves_destination() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("finalized.tmp");
        let destination = temp.path().join("learned.yaml");
        std::fs::write(&source, "new").unwrap();
        std::fs::write(&destination, "old").unwrap();
        let error = replace_finalized_learning_file(source.clone(), &destination, |_, _| {
            Err(std::io::Error::other("simulated replacement failure"))
        })
        .unwrap_err();
        assert!(error.to_string().contains("failed to replace"));
        assert!(!source.exists());
        assert_eq!(std::fs::read_to_string(destination).unwrap(), "old");
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
            GetFileAttributesW, SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL,
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

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("learned.yaml");
        std::fs::write(&path, "old").unwrap();
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
        let before_attributes = unsafe { GetFileAttributesW(path_wide.as_ptr()) };

        write_learning_file_atomically(&path, "new").unwrap();
        write_learning_file_atomically(&path, "newer").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "newer");
        assert_eq!(security(&path), before_security);
        assert_eq!(
            unsafe { GetFileAttributesW(path_wide.as_ptr()) },
            before_attributes
        );
        assert_ne!(
            unsafe { SetFileAttributesW(path_wide.as_ptr(), FILE_ATTRIBUTE_NORMAL) },
            0
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
        assert_eq!(candidate.pattern, "ssh firewall configctl system status");
        assert_eq!(
            candidate.equivalent_patterns,
            vec!["opnsense-api system status".to_string()]
        );
        assert_eq!(
            candidate.shim.as_ref().map(|shim| shim.name.as_str()),
            Some("opnsense-api")
        );
    }

    #[test]
    fn repeated_low_risk_approval_becomes_a_candidate_not_a_bypass() {
        let temp = tempfile::tempdir().unwrap();
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
        let temp = tempfile::tempdir().unwrap();
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
        std::fs::write(&blocker, "not a directory").unwrap();
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
        let temp = tempfile::tempdir().unwrap();
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
        let sanitized = std::fs::read(&path).unwrap();
        assert!(!sanitized
            .windows(value.len())
            .any(|window| window == value.as_bytes()));
        LearnedRuleStore::load(config).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), sanitized);
    }

    #[test]
    fn learned_rule_prose_is_sanitized_without_changing_safe_authority() {
        let temp = tempfile::tempdir().unwrap();
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
        let temp = tempfile::tempdir().unwrap();
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
        let temp = tempfile::tempdir().unwrap();
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
}
