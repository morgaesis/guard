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
- On Unix, the operator principal holds the admin bearer token from the
  root-held token file. The packaged Windows service instead accepts only
  kernel-authenticated local SYSTEM on its named pipe and rejects an admin
  bearer. The daemon's own uid or Windows service SID never grants operator
  authority, so a brokered child cannot approve its own work.

An agent that can read daemon credentials or reach the same upstream directly
can bypass Guard.

## Unix service

The expanded Linux release archive contains:

```text
deployment/systemd/guard.service
deployment/systemd/guard-exec-as-caller.service
deployment/systemd/guard.env.example
deployment/systemd/guard-operator
deployment/systemd/install-guard
deployment/systemd/PACKAGE-VERSION
deployment/hardening/guard.apparmor.example
deployment/hardening/seccomp-deny-escape.json
```

The standard unprivileged model runs `guard` as a dedicated account and exposes
`/run/guard/guard.sock` to the permitted agent group. Protect the state directory,
environment file, catalogs, SSH material, and secret backend from that group.

The Bash installer uses the same GNU/Linux and systemd tools as the packaged
units. It installs `/usr/local/bin/guard`, a root-owned mode `0700`
`/usr/local/sbin/guard-operator`, both service units, and missing initial
configuration. It creates the dedicated `guard` identity and `guard-clients`
group only when absent. Existing account IDs, group memberships, configuration,
admin token and state stay unchanged. It creates `/etc/guard` as root:root `0700`
and the admin token once as root:root `0400`; an empty or insecure existing
token causes refusal rather than replacement.

Use a verified release expanded into a root-controlled directory. Read its
binary digest from the verified archive's `BINARY-SHA256`, not from an
unverified download. In a root shell, set the archive path and package version:

```bash
set -euo pipefail
archive_root=/path/to/verified/archive
release_version=0.8.8
expected_binary_hash="$(awk '$2 == "guard" {print $1}' "$archive_root/BINARY-SHA256")"
"$archive_root/deployment/systemd/install-guard" --check \
  --binary "$archive_root/guard" --version "$release_version" --sha256 "$expected_binary_hash"
"$archive_root/deployment/systemd/install-guard" --apply \
  --binary "$archive_root/guard" --version "$release_version" --sha256 "$expected_binary_hash"
```

`--check` reports paths, ownership/mode changes and preserved objects without
creating files, users or tokens, reading token contents, or executing the
candidate. Exit 0 means the check succeeded, including when it reports changes;
exit 1 is a refusal or operational failure and exit 2 is invalid usage.
`--apply` verifies the digest again after protected staging, then probes the
actual stable binary version from a protected cwd with an empty inherited
environment. The candidate must match the installer package version and be at
least 0.8.8, which provides the operator's automatic-configuration opt-out.
The version probe is an apply-only check. Prerelease binaries are unsupported.

Initial installation and packaged-unit updates require both services inactive
and refuse custom units or drop-ins. Existing deployments use the explicit
`--update-binaries` mode below. Managed unit updates require unchanged recorded
file digests. File replacements use a staged file and rename in the destination
directory. The group of file updates
is not one transaction: after an interrupted apply, inspect `--check` and keep
the service stopped until every file is reconciled with the reviewed package.

Use `--service guard-exec-as-caller.service` for initial caller-identity mode.
It selects root-owned state and does not convert existing daemon-owned state.
The installer never changes sudoers, adds clients to groups, runs database
migrations, reloads systemd, enables a service or restarts one.

After reviewing the initial configuration, add only authorized agent accounts
to the socket group and set their numeric UIDs in `/etc/default/guard`:

```bash
usermod --append --groups guard-clients guard-agent
# Edit /etc/default/guard through the configuration owner; retain existing keys.
systemctl daemon-reload
systemctl enable --now guard.service
```

Replace `guard-agent` with an authorized local account. Group membership changes
require a new login. The daemon creates the socket as `0600`, or `0660` after
assigning the socket group. Activation is an explicit deployment step and may
migrate the database; use the stopped snapshot procedure below for an existing
service. The installer only updates `/usr/local/bin/guard`. A package-manager,
tool-manager or user-local `guard` elsewhere on PATH remains a separate client
installation. Update it through its existing owner and verify the actual command
from the normal client shell before accepting a coordinated deployment:

```bash
type -a guard
guard --version
/usr/local/bin/guard --version
guard status --json
```

Compare the invoked client's version and the daemon version in the status
response. A replaced file does not prove that the running daemon uses it.

### Existing service updates

Use `--update-binaries --service NAME` to update an existing deployment while
preserving its service contract. The installer replaces only
`/usr/local/bin/guard` and `/usr/local/sbin/guard-operator` from the same verified
package. Units, drop-ins, configuration, tokens, state, identities, group
memberships and ownership records remain unchanged. It creates no missing
installation objects. `packaged-units.sha256` records only unit-file hashes;
it contains no installed binary version or digest and remains unchanged.

The selected unit must be loaded from `/etc/systemd/system` with no pending
unit-file changes. Its effective command must directly start the installed
binary with the canonical socket, database, submitting-UID restriction and
`--admin-token-stdin`. Stdin must reference `/etc/guard/admin.token`, and the
service identity and state ownership must match the selected service model.
Existing service and socket groups and `PrivateTmp=yes/no` are supported.
The installer checks root ownership and safe permissions on the selected unit
and its `/etc/systemd/system` drop-ins. Unit-file continuations and includes,
additional lifecycle commands, alternative credentials or endpoints, dynamic
identities, root images/directories and filesystem remapping are unsupported.
An unsupported configuration is refused before installed files change.

The read-only check may run while services are active. It reports the stop
prerequisite and never runs the candidate. Use the verified archive variables
above and select the deployed unit explicitly:

```bash
"$archive_root/deployment/systemd/install-guard" --check --update-binaries \
  --service guard.service --binary "$archive_root/guard" \
  --version "$release_version" --sha256 "$expected_binary_hash"
```

Complete the [stopped snapshot procedure](#upgrades) and retain independent
recovery access before applying. Both services must be inactive; configuration
and service state are checked again after candidate staging:

```bash
"$archive_root/deployment/systemd/install-guard" --apply --update-binaries \
  --service "$guard_unit" --binary "$archive_root/guard" \
  --version "$release_version" --sha256 "$expected_binary_hash"
```

The installer does not stop, start or reload systemd. Follow the activation and
verification steps below, reconcile separately managed clients, and repeat the
same check to require zero planned changes. A binary-only update preserves
existing unit semantics; it does not apply changes from the packaged unit files.

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

Administrative RPCs authenticate the admin bearer token, never a uid. The
daemon's own uid grants no operator authority: brokered children inherit that
uid and must not inherit its command surface. The token reaches the daemon
only through stdin at startup (`StandardInput=file:` opens the root-held file
as root and hands over the descriptor), so it never enters the daemon's
environment, argv, or any file its children can read.

The installer provisions the admin token only when absent. Preserve an existing
token across updates. The operator launcher requires effective UID 0, normally
through `sudo guard-operator`; an existing root shell can invoke it directly.
Ordinary `sudo guard` still needs the admin bearer and gains no implicit operator
authority from UID 0. No automatic passwordless sudoers entry is installed.

The launcher keeps the caller's working directory, so relative and spaced paths
such as `sudo guard-operator verb add --file 'definitions/service status.yaml'`
remain valid. It uses a clean environment, protected HOME/XDG paths under
`/etc/guard`, and `GUARD_NO_AUTO_CONFIG=1` to prevent dotenv or saved client
configuration from supplying authority. Its fixed socket and root-held token
select the local endpoint; only supported operator leaves are accepted.

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

On a console, `access approve` reviews each request interactively before
deciding; add `--yes` for unattended runs. `GUARD_ADMIN_TOKEN` in the
daemon's own environment is supported for development only: a brokered child
can read the daemon's `/proc/<pid>/environ`, so production daemons must take
the token from stdin.

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
Service mode requires exactly one named-pipe listener and rejects
`GUARD_ADMIN_TOKEN` and `--admin-token-stdin`, so a brokered service child
cannot inherit or recover operator authority.

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
keeps those users separate by their kernel-authenticated SIDs. The packaged
service reserves administrative RPCs for local SYSTEM, and the daemon service
SID is not an operator. Guard clients explicitly request identification-level
pipe security, which exposes their identity to the server without letting the
server impersonate them. The installer does not configure a single-client-SID
pipe DACL. This is local principal isolation, not exclusive pipe reachability.
Use the stock installer only on a host where
authenticated local accounts are inside the submission boundary, or isolate the
agent in its own Windows host or VM.

## Upgrades

The daemon and every local client use one coordinated binary version. The
execute envelope carries an explicit protocol version and feature set. The
admin envelope accepts only the current operation and field grammar, so removed
or malformed authority operations fail closed instead of selecting a
compatibility path.

The state database uses schema version 15. Startup migrates an older database in
place. Treat the installed binary, configuration, API-revert body tree, and
complete SQLite file set as one rollback unit. Schema 15 adds nullable execution-failure
details to session history; rows without these details carry no launch-stage or
start-state evidence. An older reader refuses the migrated database. Rollback
requires the matching stopped binary and its consistent pre-upgrade snapshot,
not an older binary pointed at the migrated database. Before the first schema-15
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

On Unix, inspect the effective service before changing a deployment. Existing
drop-ins, identity, socket-group selection and credential configuration belong
to that deployment and must survive the update. Run these inspections locally;
configuration can contain secrets and must not be pasted into diagnostics:

```bash
systemctl show guard.service guard-exec-as-caller.service \
  --property=ActiveState,FragmentPath,DropInPaths,User,Group,MainPID
sudo guard-operator access list
type -a guard
guard --version
guard status --json
```

Keep an independent root session available. For a running deployment, arm a
host-local delayed rollback with a success sentinel before replacing files or
restarting. Its restore action must use the verified matching snapshot below,
preserve displaced state, and work without Guard. Keep that timer armed until
the actual client, daemon, operator and allowed-command checks succeed.

In a root shell, select the one active packaged unit. Resolve holds and stop
all writers before taking the snapshot. A stopped snapshot includes the entire
state directory and every SQLite sidecar; it is not a copy of one live database
file. The independent SQLite backup provides an additional consistent database
image:

```bash
backup_dir="$(bash <<'GUARD_SNAPSHOT'
set -euo pipefail
umask 077
standard_state="$(systemctl is-active guard.service || true)"
caller_state="$(systemctl is-active guard-exec-as-caller.service || true)"
case "$standard_state:$caller_state" in
  active:inactive|active:unknown) guard_unit=guard.service ;;
  inactive:active|unknown:active) guard_unit=guard-exec-as-caller.service ;;
  *) echo 'select exactly one active packaged service before proceeding' >&2; exit 1 ;;
esac
backup_dir="$(mktemp -d /var/backups/guard-before-upgrade.XXXXXXXX)"
systemctl stop "$guard_unit"
test "$(systemctl is-active "$guard_unit" || true)" = inactive
cp -a /var/lib/guard "$backup_dir/state"
sqlite3 /var/lib/guard/state.db ".backup '$backup_dir/state.db'"
cp -a /usr/local/bin/guard "$backup_dir/guard"
cp -a /usr/local/sbin/guard-operator "$backup_dir/guard-operator"
cp -a /etc/guard "$backup_dir/config"
cp -a /etc/default/guard "$backup_dir/environment"
printf '%s\n' "$guard_unit" > "$backup_dir/service-unit"
mkdir "$backup_dir/units"
for unit in guard.service guard-exec-as-caller.service; do
  for suffix in '' .d; do
    source="/etc/systemd/system/$unit$suffix"
    if test -e "$source" || test -L "$source"; then
      cp -a "$source" "$backup_dir/units/"
    fi
  done
done
(cd "$backup_dir"
checksum_manifest="$(find . -type f -print0 | sort -z | xargs -0 sha256sum)"
printf '%s\n' "$checksum_manifest" > SHA256SUMS)
(cd "$backup_dir" && sha256sum --check --status SHA256SUMS)
printf '%s\n' "$backup_dir"
GUARD_SNAPSHOT
)" || exit 1
guard_unit="$(cat "$backup_dir/service-unit")" || exit 1
printf 'Snapshot: %s\n' "$backup_dir"
```

Preserve this path for the rollback action. Run the existing-service
`--check --update-binaries --service "$guard_unit"` and
`--apply --update-binaries --service "$guard_unit"` commands with the verified
new archive. This keeps the existing environment, token, state, identities,
socket group and drop-ins. An incompatible configuration requires a separate
reviewed deployment procedure; do not remove overrides to pass the check.

After the coordinated client update, reload and start explicitly, then verify
the running executable digest against the verified release manifest:

```bash
systemctl daemon-reload
systemctl start "$guard_unit"
daemon_pid="$(systemctl show "$guard_unit" --property MainPID --value)"
test "$daemon_pid" -gt 0
test "$(sha256sum "/proc/$daemon_pid/exe" | cut -d ' ' -f 1)" = "$expected_binary_hash"
guard --version
guard status --json
sudo guard-operator access list
guard run id
```

Also exercise an approved representative verb and a genuine denial under the
intended agent identity. Verify token and launcher permissions and require an
installer `--check --update-binaries --service "$guard_unit"` with zero planned
changes for the existing deployment. Only then mark the rollback action
successful and disarm its timer.

Rollback requires another stop and a verified matching snapshot. Preserve the
entire displaced migrated state, including WAL, SHM and rollback-journal files,
by renaming the directory into a fresh archive on the same filesystem. Preserve
configuration and packaged files separately before restoration. No unique state
is deleted or overwritten. Each block runs in its own fail-fast Bash process;
a failed prerequisite stops that process even when its caller tests the exit
status in a conditional. A failed archive step leaves the service stopped and
retains any files already moved for recovery:

```bash
bash -s -- "$backup_dir" "$guard_unit" <<'GUARD_ROLLBACK'
set -euo pipefail
backup_dir=${1:?verified matching snapshot path required}
guard_unit=${2:?recorded service required}
case "$guard_unit" in guard.service|guard-exec-as-caller.service) ;; *) exit 1 ;; esac
systemctl stop "$guard_unit"
test "$(systemctl is-active "$guard_unit" || true)" = inactive
(cd "$backup_dir" && sha256sum --check --status SHA256SUMS)
test "$(cat "$backup_dir/service-unit")" = "$guard_unit"
archive_path() {
  [[ ! -e "$2" && ! -L "$2" ]]
  test "$(stat -c %d "$1")" = "$(stat -c %d "$(dirname "$2")")"
  mv -nT -- "$1" "$2"
  [[ ! -e "$1" && ! -L "$1" ]]
}
state_archive="$(mktemp -d /var/lib/guard-displaced.XXXXXXXX)"
config_archive="$(mktemp -d /etc/guard-displaced.XXXXXXXX)"
binary_archive="$(mktemp -d /usr/local/guard-displaced.XXXXXXXX)"
archive_path /var/lib/guard "$state_archive/state"
archive_path /etc/guard "$config_archive/config"
archive_path /etc/default/guard "$config_archive/environment"
archive_path /usr/local/bin/guard "$binary_archive/guard"
archive_path /usr/local/sbin/guard-operator "$binary_archive/guard-operator"
mkdir "$config_archive/units"
for unit in guard.service guard-exec-as-caller.service; do
  for suffix in '' .d; do
    source="/etc/systemd/system/$unit$suffix"
    if test -e "$source" || test -L "$source"; then
      archive_path "$source" "$config_archive/units/$(basename "$source")"
    fi
  done
done
cp -a "$backup_dir/state" /var/lib/guard
cp -a "$backup_dir/config" /etc/guard
cp -a "$backup_dir/environment" /etc/default/guard
cp -a "$backup_dir/guard" /usr/local/bin/guard
cp -a "$backup_dir/guard-operator" /usr/local/sbin/guard-operator
cp -a "$backup_dir/units/." /etc/systemd/system/
systemctl daemon-reload
systemctl start "$guard_unit"
GUARD_ROLLBACK
```

A mount-point rename or failed snapshot verification requires a filesystem-aware
restore plan; leave the service stopped instead of copying over live state.
Restore separately managed clients to the same binary version, repeat the
process-digest and endpoint checks against the snapshot, and retain the displaced
archives. Do not point an older binary at the schema-15 database.

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
The execution identity needs traversal and read access to the project tree.
Tool-native configuration discovery remains rooted in that working directory,
including discovery of files such as `ansible.cfg`.

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
