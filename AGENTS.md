# Repository instructions

Use a dedicated Git worktree for changes. Preserve other worktrees and use signed
commits. The repository quality gate is:

```bash
sfw uvx pre-commit run --all-files --verbose
```

Run focused tests for the changed behavior before that gate, and review the full
final diff. Installer checks use the existing GNU/Linux shell tooling:

```bash
bash -n deployment/systemd/install-guard deployment/systemd/test-install-guard.sh
shellcheck deployment/systemd/install-guard deployment/systemd/test-install-guard.sh
deployment/systemd/test-install-guard.sh --verify-only
```

Full installer fixtures run as root only inside an empty disposable Linux
container with Bash, GNU coreutils, util-linux and shadow account tools. Mount
this checkout read-only at `/source`, disable networking, and run
`bash /source/deployment/systemd/test-install-guard.sh`. The fixture refuses a
host or an existing deployment and retains its evidence. It does not exercise a
live systemd manager. Verify actual service activation separately.

Follow [DEPLOYMENT.md](DEPLOYMENT.md#unix-service) for local installation and
[the upgrade procedure](DEPLOYMENT.md#upgrades) for an existing daemon. Read the
effective unit, drop-ins, identity and socket-group configuration before applying
changes. Preserve existing tokens, configuration, state and account memberships.
Do not install examples over a custom deployment or add passwordless sudoers.

The operator launcher and Guard binary form one versioned package. They require
the automatic-configuration opt-out available from 0.8.8. Keep the root launcher
mode `0700`, the root-held token mode `0400`, and `/etc/guard` root-owned mode
`0700`. Operator commands use `sudo guard-operator`, or direct invocation from an
existing root shell. Ordinary root Guard commands still need operator credentials.

A file installation does not authorize service activation. Before a live upgrade,
retain independent root access, stop all database writers, verify the complete
matching snapshot and arm a rollback action that works without Guard. Preserve
displaced migrated databases and sidecars in a separate archive during rollback;
never delete them or mix them with an older snapshot. Reconcile separately managed
client binaries through their own installation owner. Check the normal command's
version, the daemon status version and running executable digest, operator access,
an approved command and a genuine denial before accepting deployment.
