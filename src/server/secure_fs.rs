//! Private daemon filesystem objects used for transient secret material.

use anyhow::{bail, Context, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Prepare an existing-or-new daemon-only directory and remove leases left by
/// an interrupted daemon. The cleanup walks only the fixed two-level layout it
/// creates and never follows links.
pub(super) fn prepare_private_root(root: &Path) -> Result<()> {
    match fs::symlink_metadata(root) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            create_private_dir(root)
                .with_context(|| format!("create private directory {}", root.display()))?;
        }
        Err(e) => return Err(e).with_context(|| format!("inspect {}", root.display())),
    }
    if !private_path_is_safe(root, true) {
        bail!("private directory {} is not daemon-only", root.display());
    }

    for entry in fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let path = entry?.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() || meta.is_file() {
            fs::remove_file(&path)?;
            continue;
        }
        if !meta.is_dir() || !private_path_is_safe(&path, true) {
            bail!(
                "unsafe stale entry in private directory: {}",
                path.display()
            );
        }
        for child in fs::read_dir(&path)? {
            let child = child?.path();
            let child_meta = fs::symlink_metadata(&child)?;
            if child_meta.is_dir() && !child_meta.file_type().is_symlink() {
                bail!(
                    "unexpected nested directory in private lease: {}",
                    child.display()
                );
            }
            fs::remove_file(&child)?;
        }
        fs::remove_dir(&path)?;
    }
    Ok(())
}

pub(super) fn create_private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)?;
    }
    #[cfg(windows)]
    {
        fs::create_dir(path)?;
        if let Err(e) = win::set_daemon_only_acl(path) {
            let _ = fs::remove_dir(path);
            return Err(e);
        }
    }
    #[cfg(not(any(unix, windows)))]
    fs::create_dir(path)?;

    if !private_path_is_safe(path, true) {
        let _ = fs::remove_dir(path);
        bail!(
            "new private directory {} failed its permission check",
            path.display()
        );
    }
    Ok(())
}

pub(super) fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?
    };
    #[cfg(not(unix))]
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;

    #[cfg(windows)]
    if let Err(e) = win::set_daemon_only_acl(path) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(e);
    }

    if !private_path_is_safe(path, false) {
        drop(file);
        let _ = fs::remove_file(path);
        bail!(
            "new private file {} failed its permission check",
            path.display()
        );
    }
    let result = file.write_all(bytes).and_then(|()| file.flush());
    if let Err(error) = result {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error.into());
    }
    Ok(())
}

pub(super) fn private_path_is_safe(path: &Path, directory: bool) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let Ok(meta) = fs::symlink_metadata(path) else {
            return false;
        };
        !meta.file_type().is_symlink()
            && if directory {
                meta.is_dir()
            } else {
                meta.is_file()
            }
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.permissions().mode() & 0o077 == 0
    }
    #[cfg(windows)]
    {
        win::daemon_only_acl_is_safe(path, directory).unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, directory);
        false
    }
}

#[cfg(windows)]
pub(super) fn harden_existing_private_path(path: &Path, directory: bool) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || if directory {
            !meta.is_dir()
        } else {
            !meta.is_file()
        }
    {
        return false;
    }
    win::set_daemon_only_acl(path).is_ok() && private_path_is_safe(path, directory)
}

/// A child-lifetime collection of secret files. Cleanup removes only the exact
/// paths created by this lease, then its unpredictable directory.
pub(super) struct SecretFileLease {
    directory: PathBuf,
    files: Vec<PathBuf>,
}

impl SecretFileLease {
    pub(super) fn create(
        root: &Path,
        values: &[(String, String)],
    ) -> Result<(Self, Vec<(String, PathBuf)>)> {
        let directory = root.join(format!("lease-{:032x}", rand::random::<u128>()));
        create_private_dir(&directory)?;
        let mut lease = Self {
            directory,
            files: Vec::new(),
        };
        let mut bindings = Vec::with_capacity(values.len());
        for (index, (env_name, value)) in values.iter().enumerate() {
            let path = lease.directory.join(format!("{index}.secret"));
            write_new_private(&path, value.as_bytes())?;
            lease.files.push(path.clone());
            bindings.push((env_name.clone(), path));
        }
        Ok((lease, bindings))
    }
}

impl Drop for SecretFileLease {
    fn drop(&mut self) {
        for path in &self.files {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_dir(&self.directory);
    }
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetAce, GetSecurityDescriptorControl, SetFileSecurityW, ACCESS_ALLOWED_ACE, ACL,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const FILE_ALL_ACCESS: u32 = 0x001f_01ff;

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn set_acl_from_sddl(path: &Path, sddl: &str) -> Result<()> {
        let sddl: Vec<u16> = format!("{sddl}\0").encode_utf16().collect();
        unsafe {
            let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut(),
            ) == 0
            {
                bail!(
                    "create daemon-only security descriptor: {}",
                    std::io::Error::last_os_error()
                );
            }
            let ok = SetFileSecurityW(
                wide(path).as_ptr(),
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor,
            );
            LocalFree(descriptor as _);
            if ok == 0 {
                bail!(
                    "set daemon-only ACL on {}: {}",
                    path.display(),
                    std::io::Error::last_os_error()
                );
            }
        }
        Ok(())
    }

    pub(super) fn set_daemon_only_acl(path: &Path) -> Result<()> {
        let sid = unsafe { crate::server::winplat::process_user_sid() }?;
        set_acl_from_sddl(path, &format!("O:{sid}D:P(A;;GA;;;{sid})"))
    }

    #[cfg(test)]
    pub(super) fn add_authenticated_users_read_for_test(path: &Path) -> Result<()> {
        let sid = unsafe { crate::server::winplat::process_user_sid() }?;
        set_acl_from_sddl(path, &format!("O:{sid}D:P(A;;GA;;;{sid})(A;;GR;;;AU)"))
    }

    pub(super) fn daemon_only_acl_is_safe(path: &Path, directory: bool) -> Result<bool> {
        let meta = fs::symlink_metadata(path)?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || if directory {
                !meta.is_dir()
            } else {
                !meta.is_file()
            }
        {
            return Ok(false);
        }
        let expected_sid = unsafe { crate::server::winplat::process_user_sid() }?;
        unsafe {
            let mut owner = std::ptr::null_mut();
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let status = GetNamedSecurityInfoW(
                wide(path).as_mut_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            );
            if status != 0 {
                bail!("read ACL from {}: OS error {}", path.display(), status);
            }
            let mut control = 0u16;
            let mut revision = 0u32;
            let protected = GetSecurityDescriptorControl(descriptor, &mut control, &mut revision)
                != 0
                && control & SE_DACL_PROTECTED != 0;
            let mut owner_string = std::ptr::null_mut();
            let owner_ok = ConvertSidToStringSidW(owner, &mut owner_string) != 0
                && crate::server::winplat::widestring_to_string(owner_string)
                    .eq_ignore_ascii_case(&expected_sid);
            if !owner_string.is_null() {
                LocalFree(owner_string as _);
            }
            let mut acl_ok = !dacl.is_null() && (*dacl).AceCount == 1;
            if acl_ok {
                let mut ace = std::ptr::null_mut();
                acl_ok = GetAce(dacl, 0, &mut ace) != 0;
                if acl_ok {
                    let allowed = ace as *const ACCESS_ALLOWED_ACE;
                    acl_ok = (*allowed).Header.AceType == ACCESS_ALLOWED_ACE_TYPE;
                    acl_ok = acl_ok
                        && ((*allowed).Mask == GENERIC_ALL
                            || (*allowed).Mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS);
                    let sid_ptr = std::ptr::addr_of!((*allowed).SidStart) as *mut core::ffi::c_void;
                    let mut sid_string = std::ptr::null_mut();
                    acl_ok = acl_ok
                        && ConvertSidToStringSidW(sid_ptr, &mut sid_string) != 0
                        && crate::server::winplat::widestring_to_string(sid_string)
                            .eq_ignore_ascii_case(&expected_sid);
                    if !sid_string.is_null() {
                        LocalFree(sid_string as _);
                    }
                }
            }
            LocalFree(descriptor as _);
            Ok(owner_ok && protected && acl_ok)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_is_private_and_removed_on_drop() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("secret-files");
        prepare_private_root(&root).unwrap();
        let (lease, bindings) = SecretFileLease::create(
            &root,
            &[("TOKEN_FILE".to_string(), "not-logged-secret".to_string())],
        )
        .unwrap();
        let path = bindings[0].1.clone();
        assert!(private_path_is_safe(&root, true));
        assert!(private_path_is_safe(path.parent().unwrap(), true));
        assert!(private_path_is_safe(&path, false));
        assert_eq!(fs::read_to_string(&path).unwrap(), "not-logged-secret");
        drop(lease);
        assert!(!path.exists());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    }

    #[test]
    fn startup_removes_stale_lease_files() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("secret-files");
        prepare_private_root(&root).unwrap();
        let stale = root.join("lease-stale");
        create_private_dir(&stale).unwrap();
        write_new_private(&stale.join("0.secret"), b"stale").unwrap();
        prepare_private_root(&root).unwrap();
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn private_file_creation_refuses_symlink_substitution() {
        use std::os::unix::fs::symlink;
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("target");
        fs::write(&target, "unchanged").unwrap();
        let link = parent.path().join("secret");
        symlink(&target, &link).unwrap();
        assert!(write_new_private(&link, b"replacement").is_err());
        assert_eq!(fs::read_to_string(target).unwrap(), "unchanged");
    }

    #[cfg(unix)]
    #[test]
    fn unix_contract_denies_group_and_other_bits() {
        use std::os::unix::fs::PermissionsExt;
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("secret-files");
        prepare_private_root(&root).unwrap();
        let (lease, bindings) =
            SecretFileLease::create(&root, &[("TOKEN_FILE".to_string(), "value".to_string())])
                .unwrap();
        let path = &bindings[0].1;
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(lease);
    }

    #[cfg(windows)]
    #[test]
    fn windows_contract_has_only_daemon_acl() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("secret-files");
        prepare_private_root(&root).unwrap();
        let (lease, bindings) =
            SecretFileLease::create(&root, &[("TOKEN_FILE".to_string(), "value".to_string())])
                .unwrap();
        assert!(private_path_is_safe(&root, true));
        assert!(private_path_is_safe(&bindings[0].1, false));
        win::add_authenticated_users_read_for_test(&bindings[0].1).unwrap();
        assert!(
            !private_path_is_safe(&bindings[0].1, false),
            "a caller-readable ACE must fail the daemon-only contract"
        );
        drop(lease);
    }
}
