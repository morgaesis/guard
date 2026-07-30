# Deployment

A durable Guard deployment separates the agent, daemon, credentials, state, and
operator authority. The daemon listens on a local Unix socket or Windows named
pipe, and the agent has no direct route or credential for protected upstreams.

## Operating model

Guard is designed for unattended authority. Policy defines the durable
boundaries, and agents describe missing access in prose. The daemon reduces
approved intent to bounded typed coverage. Saved grants, sessions, and verbs are
operator-owned enforcement state rather than an agent-facing authorization
language. Recoverable changes carry a viable forward, verify, and rollback
chain. Holds are the exception for expired, conflicting, irreversible, or
connectivity-unsafe operations and return a durable escalation handle.

This supports autonomous incident response without requiring an operator to be
available during every session. Notifications can wake or inform an operator,
but notification delivery does not change a gate decision.

The principal split is mandatory:

- The daemon principal owns SSH keys, SSH agent sockets, kubeconfigs, API tokens,
  state, and internal saved authority. Operators own deployed binaries and verb
  catalogs.
- The agent principal can connect to Guard and receives only non-authoritative
  request and session references. Approved command authority remains in daemon
  state and is bound automatically to the authenticated requester.
- The operator principal is the daemon uid on Unix. On Windows, the daemon
  service SID and the kernel-authenticated local SYSTEM SID can perform operator
  RPCs; the installer runs elevated operator actions as SYSTEM.

An agent that can read daemon credentials or reach the same upstream directly
can bypass Guard.

## Unix service

The expanded Linux release archive contains:

```text
deployment/systemd/guard.service
deployment/systemd/guard-exec-as-caller.service
deployment/systemd/guard.env.example
deployment/systemd/guard-operator
deployment/hardening/guard.apparmor.example
deployment/hardening/seccomp-deny-escape.json
```

The standard unprivileged model runs `guard` as a dedicated account and exposes
`/run/guard/guard.sock` to the permitted agent group. Protect the state directory,
environment file, catalogs, SSH material, and secret backend from that group.

Create the dedicated socket group and add only agent accounts that may submit
requests. The daemon creates the socket as `0600`, or `0660` after it
successfully assigns the configured group. It never makes the socket
world-accessible.

```bash
getent group guard >/dev/null || groupadd --system guard
getent group guard-clients >/dev/null || groupadd --system guard-clients
id guard >/dev/null 2>&1 || useradd --system --gid guard --home-dir /var/lib/guard --shell /usr/sbin/nologin guard
usermod --append --groups guard-clients guard-agent
install -m 0755 guard /usr/local/bin/guard
install -o root -g root -m 0755 deployment/systemd/guard-operator /usr/local/sbin/guard-operator
install -m 0644 deployment/systemd/guard.service /etc/systemd/system/
install -m 0600 deployment/systemd/guard.env.example /etc/default/guard
# Edit /etc/default/guard before the first start.
systemctl daemon-reload
systemctl enable --now guard.service
guard status
```

Replace `guard-agent` with each local agent account that may connect. Edit
`/etc/default/guard` before starting the service. Keep API keys and bearer
tokens out of unit command lines. `systemctl cat guard.service` shows the exact
merged hardening and environment configuration.

Use `--users` to restrict submitting Unix uids when the socket group is broader
than the intended agent account. Set `GUARD_ALLOWED_UIDS=1000,1001` in
`/etc/default/guard` when using the packaged service. The unit keeps `--users`
separate from this systemd expansion. Its default value is UID 0, so ordinary
agents fail closed until the list is configured. `NoNewPrivileges=true`
prevents approved children from gaining privilege through setuid helpers; the
wide-access model below relaxes it deliberately.

## Wide host access

A deployment whose agents debug and administer the local host through Guard
gives the daemon deliberately broad reach: the guard account carries
passwordless sudo for brokered children, holds the fleet SSH identity and tool
credentials, and exposes the socket to the agent group. Passwordless sudo
requires a host-local sudoers entry for the guard account and, because the
packaged unit mounts the host filesystem read-only and sets
`NoNewPrivileges=true`, a service drop-in that removes those restrictions:

```ini
[Service]
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false
```

Run `systemctl daemon-reload` and restart `guard.service` after installing the
drop-in. These settings let setuid `sudo` elevate and let approved children
write normal host and home paths. This is the intended shape of a sudo-like
broker, not a hardening gap. The enforcement surface is the evaluator envelope,
operator policy and catalogs, and the audit stream - not a minimized daemon.
Guard alone holding the credentials is what keeps a direct tool invocation
outside Guard inert.

Wide access raises the cost of instruction defects, so pair it with:

- a narrow socket group and a `--users` restriction;
- shipped audit and periodic review of allowed mutations;
- prompt regression coverage for the deployed mode prompt;
- prompt supplements or typed verbs for house tools the evaluator cannot
  otherwise judge;
- saved grants for recurring apply-class work, so denials stay rare and each
  one is meaningful.

Consequence gating adds holds for the irreversible tail once enabled; keep
holds exceptional so each one gets real operator attention.

Administrative RPCs authenticate the daemon uid, not the interactive operator's
uid. Run them through the root-owned wrapper. It uses the `guard` account for
the standard unit and root for the exec-as-caller unit, and refuses to run when
both or neither packaged service is active:

```bash
sudo guard-operator access list
sudo guard-operator access approve <request>
sudo guard-operator access approve <request> --once
sudo guard-operator access approve <request-1> <request-2> --uses 3
sudo guard-operator access deny <request> --reason 'outside the approved task'
sudo guard-operator access extend <session-or-agent> 'Inspect service health.' --once
sudo guard-operator access revoke <session-or-agent>
sudo guard-operator confirm <provisional>
sudo guard-operator revert <provisional>
```

Restrict `sudo` access to `/usr/local/sbin/guard-operator` to human operator
accounts. Access to the wrapper grants the full daemon-principal command surface.
Keep credentials out of command arguments.

`--exec-as-caller` is a Unix-only alternative for a root socket daemon. Approved
children drop to the authenticated caller uid and groups. It is incompatible
with TCP, API proxying, and secret-file injection. The default broker model keeps
the daemon identity because it owns the credentials the agent lacks.

## Windows service

[`deployment/windows/install-guard.ps1`](deployment/windows/install-guard.ps1)
registers Guard under `NT SERVICE\guard`. Administrators own the writable state
root and installer-created directories beneath `C:\ProgramData\Guard`, while
the service SID receives full control and owns files it creates there.
Service-only secret and API-revert subtrees are owned by the service SID.
Administrators and SYSTEM own `C:\Program Files\Guard`,
`C:\ProgramData\GuardConfig`, and `C:\ProgramData\GuardMaintenance`. The
service receives read-execute access to the installed binary, read access to the
catalog, and no access to staging, operator output, or rollback backups.

Run installation and operator decisions from an elevated shell. The installer
uses a transient Task Scheduler task under SYSTEM, whose authenticated named-pipe
SID Guard recognizes as a Windows operator. The interactive agent connects
under its own SID and cannot satisfy this check or read daemon state.
`--exec-as-caller` is unavailable; approved children run as the service account.

The installer maps explicit PowerShell actions to the Guard CLI and runs them as
SYSTEM. Access requests use exact `gr-` plus 32-hex references. Provisionals use
bare 32-hex handles. Access targets use 16-hex `session:` references or Windows
`agent:S-1-...` targets:

```powershell
.\deployment\windows\install-guard.ps1 -Action access-list -Json
.\deployment\windows\install-guard.ps1 -Action access-show -Reference <request>
.\deployment\windows\install-guard.ps1 -Action access-approve -Reference <request>
.\deployment\windows\install-guard.ps1 -Action access-approve -Reference <request> -ApprovalMode once
.\deployment\windows\install-guard.ps1 -Action access-approve -Reference <request-1>,<request-2> -ApprovalMode uses -Uses 3
.\deployment\windows\install-guard.ps1 -Action access-deny -Reference <request> -Reason 'outside the approved task'
.\deployment\windows\install-guard.ps1 -Action access-extend -Reference <session-or-agent> -Intent 'Inspect service health.' -ApprovalMode once
.\deployment\windows\install-guard.ps1 -Action access-revoke -Reference <session-or-agent>
.\deployment\windows\install-guard.ps1 -Action confirm -Reference <provisional>
.\deployment\windows\install-guard.ps1 -Action revert -Reference <provisional>
```

Each task validates the action, reference count, reference grammar, use count,
and bounded prose before constructing the encoded command. It reports Guard's
structured output and the native task status on failure. The executable SYSTEM
task is removed with bounded retries and absence verification on every outcome.
Output is also removed by default. `-PreserveDiagnostics` retains only bounded,
control-character-sanitized output with credential-shaped values redacted. A
cleanup failure is reported as an operator error.

The service registry key has an explicit DACL for the service SID, SYSTEM, and
Administrators before environment values are written. An installer rerun merges
allowlisted evaluator settings into the existing service environment and keeps
unrelated entries without displaying values.

Transient secret files and API rollback snapshots use protected non-inheriting
ACLs for the service SID. Guard rejects reparse points and unsafe ownership or
trustee sets. Unsafe storage disables the affected secret-file or body-bearing
revert path. Installer maintenance and purge traverse these trees one node at a
time without following reparse points; any nested junction or link aborts the
operation before that object is given administrative ownership or access.

The stock named-pipe DACL permits authenticated local users to connect. Guard
keeps those users separate by their kernel-authenticated SIDs and reserves
administrative RPCs for the service SID and SYSTEM, but the installer does not
configure a single-client-SID pipe DACL. This is local principal isolation, not
exclusive pipe reachability. Use the stock installer only on a host where
authenticated local accounts are inside the submission boundary, or isolate the
agent in its own Windows host or VM.

## Upgrades

The daemon and every local client use one coordinated binary version. The
execute envelope carries an explicit protocol version and feature set. The
admin envelope accepts only the current operation and field grammar, so removed
or malformed authority operations fail closed instead of selecting a
compatibility path.

The state database uses schema version 9. Startup migrates an older database in
place. Treat the installed binary, configuration, API-revert body tree, and
complete SQLite file set as one rollback unit. Before the first schema-9
startup, resolve armed provisionals where practical, stop the service, verify
that it is inactive, and create a consistent SQLite backup with the SQLite
backup API. Copying only `state.db` while a process can write it can omit
committed WAL transactions; copying a live WAL/SHM set file by file is also not
an atomic snapshot.

Startup rejects active sessions that lack matching approved access-request
provenance. Before replacing a deployment that contains bearer sessions, revoke
them with its current operator interface and verify that no active sessions
remain. Keep the stopped binary and consistent database backup together for
rollback.

On Unix, the packaged paths use this upgrade sequence:

```bash
release_version=0.6.0
backup_dir="/var/backups/guard-before-v${release_version}"
standard_state="$(systemctl is-active guard.service || true)"
caller_state="$(systemctl is-active guard-exec-as-caller.service || true)"
case "$standard_state:$caller_state" in
  active:active) echo 'both packaged Guard services are active' >&2; exit 1 ;;
  active:*) guard_unit=guard.service ;;
  *:active) guard_unit=guard-exec-as-caller.service ;;
  *) echo 'no packaged Guard service is active' >&2; exit 1 ;;
esac
test ! -e "$backup_dir"
sha256sum --check BINARY-SHA256
expected_binary_hash="$(awk '$2 == "guard" {print $1}' BINARY-SHA256)"
test "${#expected_binary_hash}" -eq 64
install -d -o root -g root -m 0700 "$backup_dir"
systemctl stop "$guard_unit"
test "$(systemctl is-active "$guard_unit" || true)" = inactive
install -o root -g root -m 0755 /usr/local/bin/guard "$backup_dir/guard"
for deployed_file in \
  /usr/local/sbin/guard-operator \
  /etc/systemd/system/guard.service \
  /etc/systemd/system/guard-exec-as-caller.service; do
  backup_name="$(basename "$deployed_file")"
  if test -f "$deployed_file"; then
    cp -a "$deployed_file" "$backup_dir/$backup_name"
  else
    : > "$backup_dir/$backup_name.absent"
  fi
done
sqlite3 /var/lib/guard/state.db ".backup '$backup_dir/state.db'"
test -s "$backup_dir/state.db"
if test -d /etc/guard; then
  cp -a /etc/guard "$backup_dir/config"
else
  : > "$backup_dir/config.absent"
fi
if test -d /var/lib/guard/api-proxy-reverts; then
  cp -a /var/lib/guard/api-proxy-reverts "$backup_dir/api-proxy-reverts"
fi
(cd "$backup_dir" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
(cd "$backup_dir" && sha256sum --check SHA256SUMS)
install -m 0755 guard /usr/local/bin/guard
install -o root -g root -m 0755 deployment/systemd/guard-operator /usr/local/sbin/guard-operator
install -o root -g root -m 0644 deployment/systemd/guard.service /etc/systemd/system/guard.service
install -o root -g root -m 0644 deployment/systemd/guard-exec-as-caller.service /etc/systemd/system/guard-exec-as-caller.service
systemctl daemon-reload
systemctl start "$guard_unit"
daemon_pid="$(systemctl show "$guard_unit" --property MainPID --value)"
test "$daemon_pid" -gt 0
test "$(readlink -f "/proc/$daemon_pid/exe")" = /usr/local/bin/guard
test "$(sha256sum "/proc/$daemon_pid/exe" | cut -d ' ' -f 1)" = "$expected_binary_hash"
guard status --json
```

Rollback stops the service again, verifies the backup manifest, and restores
the matching binary, database, configuration, and API-revert bodies. Remove the
database and every WAL, SHM, or rollback-journal sidecar before installing the
backup so SQLite cannot combine files from different snapshots:

```bash
release_version=0.6.0
backup_dir="/var/backups/guard-before-v${release_version}"
standard_state="$(systemctl is-active guard.service || true)"
caller_state="$(systemctl is-active guard-exec-as-caller.service || true)"
case "$standard_state:$caller_state" in
  active:active) echo 'both packaged Guard services are active' >&2; exit 1 ;;
  active:*) guard_unit=guard.service; state_owner=guard; state_group=guard ;;
  *:active) guard_unit=guard-exec-as-caller.service; state_owner=root; state_group=root ;;
  *) echo 'no packaged Guard service is active' >&2; exit 1 ;;
esac
systemctl stop "$guard_unit"
test "$(systemctl is-active "$guard_unit" || true)" = inactive
(cd "$backup_dir" && sha256sum --check SHA256SUMS)
for database_file in /var/lib/guard/state.db /var/lib/guard/state.db-wal /var/lib/guard/state.db-shm /var/lib/guard/state.db-journal; do
  test ! -e "$database_file" || rm -- "$database_file"
done
install -o root -g root -m 0755 "$backup_dir/guard" /usr/local/bin/guard
restore_packaged_file() {
  backup_name="$1"
  destination="$2"
  mode="$3"
  if test -f "$backup_dir/$backup_name.absent"; then
    rm -f -- "$destination"
  else
    install -o root -g root -m "$mode" "$backup_dir/$backup_name" "$destination"
  fi
}
restore_packaged_file guard-operator /usr/local/sbin/guard-operator 0755
restore_packaged_file guard.service /etc/systemd/system/guard.service 0644
restore_packaged_file guard-exec-as-caller.service /etc/systemd/system/guard-exec-as-caller.service 0644
install -o "$state_owner" -g "$state_group" -m 0600 "$backup_dir/state.db" /var/lib/guard/state.db
rm -rf /etc/guard /var/lib/guard/api-proxy-reverts
if test ! -f "$backup_dir/config.absent"; then
  cp -a "$backup_dir/config" /etc/guard
fi
if test -d "$backup_dir/api-proxy-reverts"; then
  cp -a "$backup_dir/api-proxy-reverts" /var/lib/guard/api-proxy-reverts
  chown -R "$state_owner:$state_group" /var/lib/guard/api-proxy-reverts
fi
systemctl daemon-reload
systemctl start "$guard_unit"
daemon_pid="$(systemctl show "$guard_unit" --property MainPID --value)"
test "$daemon_pid" -gt 0
test "$(readlink -f "/proc/$daemon_pid/exe")" = /usr/local/bin/guard
test "$(sha256sum "/proc/$daemon_pid/exe" | cut -d ' ' -f 1)" = "$(sha256sum "$backup_dir/guard" | cut -d ' ' -f 1)"
guard status --json
```

On Windows, verify the release archive checksum, extract it into an
Administrators-and-SYSTEM only directory, and rerun `install-guard.ps1` from an
elevated PowerShell with `-CandidateExe` and the digest from the archive's
`BINARY-SHA256` file as `-ExpectedSha256`. The installer copies the candidate to
its protected staging directory, verifies the expected digest, and executes only
that staged copy. It stops the service and backs up the installed binary,
catalog, exact service command line, DPAPI-protected service environment,
complete quiesced SQLite file set, and durable API-revert body files. The
installer deletes the entire live SQLite set and API-revert snapshot before a
restore, so files from different snapshots never mix. It verifies file hashes,
the running process path, exact DACLs, and a `guard status --json` client/server
version handshake. A failed install restores the prior files, environment,
service command line, start mode, and running state. A disabled service is
temporarily set to manual for verification, stopped again, and returned to
disabled mode.
Successful backups remain under `C:\ProgramData\GuardMaintenance\backups` and
are inaccessible to the service.

The installer prints a release-version backup name after a successful upgrade.
Use that exact name for a later verified rollback:

```powershell
.\deployment\windows\install-guard.ps1 -Action rollback -Backup <backup-name>
```

Rollback validates the metadata, hashes, fixed installation paths, exact service
executable token, and DPAPI environment backup before stopping the service. It
creates a safety backup, restores the binary, database, API-revert bodies,
catalog, exact service command, start mode, and environment, verifies the real
status/version handshake, and restores the safety backup if verification fails.

A daemon refuses a database written by a newer binary and fails startup. Never
start an older binary against the migrated database. Removing the database
instead of restoring its matching backup discards sessions, internal saved
authority state, holds, and history.

The sweeper re-validates frozen authority after startup; monitor
`guard provisionals` and `guard access list` as described under
[Holds, rollback, and notifications](#holds-rollback-and-notifications).

## TCP

Loopback TCP carries execution and admin bearers but no kernel-authenticated
principal. The daemon requires `GUARD_AUTH_TOKEN`; non-Ping admin RPCs require
`GUARD_ADMIN_TOKEN`. Consequence gating and per-principal secret delivery are
refused.

TCP is appropriate only when local socket or named-pipe identity is unavailable.
Keep it on loopback and protect the client configuration containing bearer
tokens. A bearer shared among agents is one principal for authorization and
audit purposes.

## Brokered files and tools

Guard runs approved commands in the caller's canonical working directory while
retaining the daemon's clean environment, identity, SSH configuration, agent
socket, and secret bindings. It does not stage or copy project files.

On Unix, a brokered command that cannot read one named non-secret file can enter
the transparent read-grant path. The packaged system service grants the daemon
`CAP_FOWNER` and `CAP_DAC_READ_SEARCH` for its ACL operations, then clears
ambient and inheritable capabilities before spawning brokered children. The
child never inherits these capabilities.

The read-grant path requires the operating system ACL utilities, including
`getfacl` and `setfacl`. Install the distribution's `acl` package before
enabling this path.

`ProtectSystem=strict` and `ProtectHome=read-only` also require a host-specific
write carve-out for the tree whose ACL metadata Guard may change:

```ini
[Service]
ReadWritePaths=/home/operator/path/to/operations
```

Place this in a service drop-in, reload systemd, and restart Guard. The carve-out
only permits ACL metadata writes inside the service mount namespace. It grants
no file access by itself. Guard separately rejects credential-shaped paths,
pins the inode, prevents symlink and hardlink retargeting, applies a short TTL,
and persists cleanup state. Windows does not modify caller file ACLs.

Use `--secret-file ENV=NAME` when a child accepts credential material by path.
The value remains in a daemon-owned child-lifetime file and is incompatible with
`--exec-as-caller`.

On Unix, Guard creates private state directories as `0700` and the SQLite
database and sidecars as `0600`. It rejects symlinked or non-regular database
paths and unsafe writable parent directories instead of opening them.

## Remote command credentials

Store the only usable remote credentials under the daemon account. For SSH-based
tools, configure the daemon's SSH config, known-hosts database, and agent socket.
Do not forward the caller's `SSH_AUTH_SOCK` or trust caller SSH configuration.

Use `GUARD_CHILD_ENV` for operator-selected daemon environment values such as a
brokered `KUBECONFIG`. Use per-run or tool-config secret bindings for credential
values. The agent names an entitlement, not the secret value.

Shims are convenience wrappers around `guard run`; they are not security
boundaries. Put them before real tools in the agent `PATH`, and enforce bypass
prevention through credential ownership and network reachability.

## API listeners

API proxies bind loopback and are incompatible with `--exec-as-caller`. The
daemon owns every upstream credential and emits only operator/bootstrap client
material. For Kubernetes, the brokered kubeconfig contains the local CA, never
the upstream token or client key. Public access sessions remain command-only.

Use `--api-endpoints` when one daemon serves multiple protocols or environments.
Each endpoint has a unique name, listener, mode, policy, credential reference,
and output path. Persisted rollback binds that identity and cannot cross to a
different listener.

Protect proxy ports from other local users. A separately integrated API bearer
supplies scope, not network client identity. See [API proxy](docs/api-proxy.md).

## Access authority internals

`guard access` is the supported operational workflow for requesting, approving,
inspecting, extending, and revoking authority. The daemon records prose intent
as principal-bound requests and reduces approved requests to typed enforcement
coverage.

Load internal reusable grant state with `--grants
/etc/guard/saved-grants.yaml` and the operator verb catalog with `--verbs
/etc/guard/verbs.yaml`. Both catalogs are operator-owned. An explicitly
configured missing, malformed, or duplicate catalog fails startup.

Request and manage access per worker or incident:

```bash
guard access request 'Inspect host-a and report drift.'
guard access list
guard access show <request>
guard access approve <request> --uses 3
guard access approve <held-request> --once
guard access deny <request> --reason 'outside the approved task'
guard access revoke <session-or-agent>
```

Prefer short lifetimes and bounded uses for mutation authority. An approved
access session records the applicable internal authority revision. Catalog and
authority edits do not rewrite frozen holds or provisionals, and revision
changes invalidate affected evaluator-cache entries.

A held operation uses its immutable execution snapshot and accepts only
`guard access approve <request> --once`. Use `guard access deny <request>` to
close the held request without execution.

Configure optional rolling behavioral limits for denials, holds, and denial
ratio. A suspended session becomes deny-all until the triggering behavior ages
out or the session is revoked.

## Holds, rollback, and notifications

The daemon needs durable state and continuous supervision while provisionals are
armed. It re-arms a completed forward command only after validating its frozen
principal, session, secret selectors, endpoint, and credential identity. The
sweeper observes a startup grace before processing due rows. An interrupted
rollback, unknown forward outcome, or invalid frozen authority becomes
`needs_operator_decision` and emits a recovery notification. Monitor `guard
provisionals`, `guard access list`, and the service audit stream after restart.

`--notify-cmd` runs an operator-owned command with one bounded, secret-free JSON
event on standard input. The hook has a timeout, concurrency ceiling, and cleared
environment. Delivery credentials, retries, and destinations belong to the
hook. Policy decisions do not depend on notification success.

## Audit and hardening

Ship the dedicated `guard::audit` target through journald, Windows service logs,
or the deployment logging stack. SQLite is durable authorization state and
queryable session history, not the primary audit sink.

Apply defense in depth appropriate to daemon authority:

- filesystem ACLs for state, catalogs, credentials, and logs;
- socket, pipe, and loopback listener restrictions;
- AppArmor or container seccomp examples from `deployment/hardening/`;
- process visibility controls between agent and daemon accounts;
- upstream RBAC, network segmentation, backups, and service supervision;
- binary floors and typed verbs for privileged or opaque tools.

After each deployment change, verify a permitted command, a denied command, an
agent-side attempt to read daemon credentials, session expiry, and one
provisional rollback path before granting unattended authority.
