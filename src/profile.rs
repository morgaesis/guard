//! Container hardening profile generation (seccomp, AppArmor) for guard
//! deployments.
//!
//! These are conservative starting points an operator adapts to their host.
//! They confine the daemon without breaking its legitimate operation: guard
//! spawns operator-approved child commands, makes TLS calls to the LLM provider,
//! and reads/writes its own state and credential directory. The profiles bound
//! the filesystem reach and remove syscalls that let a process break out of
//! the container or modify the host without authorization, while leaving
//! that legitimate operation intact.

/// Syscalls a guard container never needs and that would let a process break
/// out of the container, modify the kernel without authorization, or
/// reconfigure the host. Blocking them is safe for the daemon and its child
/// commands while removing the most dangerous primitives. This is
/// intentionally a denylist over a default-allow base, so the daemon and
/// arbitrary approved child binaries keep working; only clearly-dangerous
/// syscalls are refused.
const DENIED_SYSCALLS: &[&str] = &[
    // Mount / namespace / root manipulation (used to break out of a container).
    "mount",
    "umount",
    "umount2",
    "pivot_root",
    "chroot",
    "setns",
    "unshare",
    // Process inspection of other processes (credential theft).
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    // Kernel image / module modification.
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "create_module",
    "get_kernel_syms",
    "query_module",
    // Tracing / instrumentation primitives.
    "bpf",
    "perf_event_open",
    // Host reconfiguration.
    "swapon",
    "swapoff",
    "reboot",
    "settimeofday",
    "clock_settime",
    "clock_adjtime",
    "adjtimex",
    "acct",
    "quotactl",
    "nfsservctl",
    // Kernel keyring.
    "add_key",
    "request_key",
    "keyctl",
    // Filehandle reopen across mounts (sandbox bypass).
    "open_by_handle_at",
    "name_to_handle_at",
];

/// A seccomp profile in the JSON format Docker / containerd / Podman accept via
/// `--security-opt seccomp=<file>`. Default-allow with an `errno` denial for the
/// dangerous syscalls in [`DENIED_SYSCALLS`]. Default-allow keeps the daemon and
/// its approved child processes working; the denials remove the primitives
/// that let a process break out of the container or modify the host without
/// authorization.
pub fn seccomp_json() -> String {
    let names: Vec<serde_json::Value> = DENIED_SYSCALLS
        .iter()
        .map(|s| serde_json::Value::String((*s).to_string()))
        .collect();
    let profile = serde_json::json!({
        "defaultAction": "SCMP_ACT_ALLOW",
        "comment": "guard hardening profile: default-allow with the container-escape and host-tampering syscalls denied. Adapt to your host before use.",
        "syscalls": [
            {
                "names": names,
                "action": "SCMP_ACT_ERRNO",
                "errnoRet": 1,
                "comment": "denied for guard: escape / kernel / host-reconfiguration primitives"
            }
        ]
    });
    serde_json::to_string_pretty(&profile).expect("seccomp profile serializes")
}

/// An AppArmor profile confining the guard daemon to its own binary, its state /
/// credential directory, and the execution of operator-approved child commands
/// from the standard system paths, while denying unauthorized host
/// modification. `name` is the profile name, `exe` the absolute path to the
/// guard binary the profile attaches to, and `data_dir` the directory holding
/// state and brokered credentials.
pub fn apparmor_profile(name: &str, exe: &str, data_dir: &str) -> String {
    format!(
        r#"#include <tunables/global>

# AppArmor profile for the guard daemon. A conservative starting point: confine
# the daemon to its binary, its state/credential directory, and the ability to
# execute operator-approved child commands, while denying host tampering. The
# binary allow-list (--allow-bin) and the verb catalog are the policy layer;
# AppArmor bounds the filesystem and capability reach beneath them.
profile {name} {exe} flags=(attach_disconnected) {{
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/ssl_certs>

  # The daemon binary: read + mmap-execute.
  {exe} mr,

  # State + brokered credentials: read/write only inside the data directory.
  {data_dir}/ rw,
  {data_dir}/** rwkl,

  # Resolve and execute child commands from the standard system paths. `ix`
  # makes children inherit this profile (strongest confinement); switch a
  # specific tool to `Px` (its own profile) or `Ux` (unconfined) if it needs
  # broader access than this profile grants.
  /usr/bin/* rix,
  /usr/local/bin/* rix,
  /bin/* rix,
  /sbin/* rix,
  # Some allowed tools exec helpers from libexec paths (e.g. git runs
  # /usr/lib/git-core/git-*). Grant execute there too; extend per tool as needed.
  /usr/lib/git-core/* rix,
  /usr/libexec/** rix,

  # Read-only system config the children commonly need.
  /etc/** r,
  /usr/lib/** mr,
  /lib/** mr,
  /lib64/** mr,

  # Deny host-tampering capabilities and paths outright.
  deny capability sys_admin,
  deny capability sys_module,
  deny capability sys_ptrace,
  deny capability sys_boot,
  deny @{{PROC}}/*/mem rwklx,
  deny @{{PROC}}/sysrq-trigger rwklx,
  deny /sys/kernel/** wklx,
  deny /boot/** rwklx,
  deny mount,
  deny umount,
  deny ptrace (readby, tracedby),
}}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seccomp_json_is_valid_and_denies_escape_syscalls() {
        let json = seccomp_json();
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(v["defaultAction"], "SCMP_ACT_ALLOW");
        let entry = &v["syscalls"][0];
        assert_eq!(entry["action"], "SCMP_ACT_ERRNO");
        let names = entry["names"].as_array().expect("names array");
        let listed: Vec<&str> = names.iter().filter_map(|n| n.as_str()).collect();
        for must in ["mount", "ptrace", "kexec_load", "bpf", "init_module"] {
            assert!(listed.contains(&must), "seccomp must deny {must}");
        }
    }

    #[test]
    fn apparmor_profile_embeds_paths_and_denies_tampering() {
        let p = apparmor_profile("guard", "/usr/local/bin/guard", "/var/lib/guard");
        assert!(p.contains("profile guard /usr/local/bin/guard"));
        assert!(p.contains("/var/lib/guard/** rwkl"));
        assert!(p.contains("deny mount"));
        assert!(p.contains("deny capability sys_module"));
    }
}
