# Deployment

A durable Guard deployment separates the agent, daemon, state, and operator
authority. Fixed-identity and API-proxy deployments also keep protected upstream
credentials and routes unavailable to the agent. Caller-identity deployments
instead use the authenticated caller's filesystem and credential authority.

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

Every deployment preserves these principal boundaries:

- The daemon principal owns state and internal saved authority. In fixed-identity
  and API-proxy deployments it also owns any brokered kubeconfig or API token.
  Operators own deployed binaries and verb catalogs.
- The agent principal can connect to Guard and receives only non-authoritative
  request and session references. Approved command authority remains in daemon
  state and is bound automatically to the authenticated requester. Under
  `--exec-as-caller`, an approved child also receives that requester's existing
  filesystem and caller-owned credential authority.
- On Unix, the operator principal holds the admin bearer token from the
  root-held token file. The packaged Windows service instead accepts only
  kernel-authenticated local SYSTEM on its named pipe and rejects an admin
  bearer. The daemon's own uid or Windows service SID never grants operator
  authority, so a brokered child cannot approve its own work.

An agent that can read daemon credentials or reach the same protected upstream
directly can bypass the fixed-identity credential boundary. `--exec-as-caller`
does not claim that boundary for caller-owned credentials.

## Unix service

The expanded Linux release archive contains:

```text
deployment/systemd/guard.service
deployment/systemd/guard-exec-as-caller.service
deployment/systemd/guard.env.example
deployment/systemd/guard-operator
deployment/systemd/upgrade-guard
deployment/systemd/test-upgrade-guard.sh
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
getent group guard-exec >/dev/null || groupadd --system guard-exec
id guard-exec >/dev/null 2>&1 || useradd --system --create-home --gid guard-exec --home-dir /var/lib/guard-exec --shell /usr/sbin/nologin guard-exec
install -d -o guard-exec -g guard-exec -m 0700 /var/lib/guard-exec /var/lib/guard-exec/.ssh
usermod --append --groups guard-clients guard-agent
install -m 0755 guard /usr/local/bin/guard
install -o root -g root -m 0755 deployment/systemd/guard-operator /usr/local/sbin/guard-operator
install -m 0644 deployment/systemd/guard.service /etc/systemd/system/
install -m 0600 deployment/systemd/guard.env.example /etc/default/guard
# Provision the admin token (root-held, root:root 0400) before the first start.
install -m 0400 -o root -g root /dev/null /etc/guard/admin.token
openssl rand -hex 32 > /etc/guard/admin.token
# Edit /etc/default/guard before the first start.
systemctl daemon-reload
systemctl enable --now guard.service
guard status
```

Replace `guard-agent` with each local agent account that may connect. Edit
`/etc/default/guard` before starting the service. Keep API keys and bearer
tokens out of unit command lines. `systemctl cat guard.service` shows the exact
merged hardening and environment configuration.

Keep `guard-exec` as a private group containing only the `guard-exec` worker and
the `guard` daemon. The standard unit uses that group solely to deliver a
generated proxy transport bearer through daemon-owned `0640` client files.
Guard enumerates system account membership before each output and refuses the
write when any unrelated account belongs to the group.

The packaged `upgrade-guard` installer validates the `guard-exec` account and
its private home before it interrupts the standard service.
Provision the account with the setup commands above before upgrading. The
upgrader rejects SSH material under the shared execution home because one fixed
UID separates children from daemon state but does not isolate executions from
each other.

Use `--users` to restrict submitting Unix uids when the socket group is broader
than the intended agent account. Set `GUARD_ALLOWED_UIDS=1000,1001` in
`/etc/default/guard` when using the packaged service. The unit keeps `--users`
separate from this systemd expansion. Its default value is UID 0, so ordinary
agents fail closed until the list is configured. `NoNewPrivileges=true`
prevents approved children from gaining privilege through setuid helpers.

## Privileged host operations

The fixed execution account does not receive `sudo` authority. `sudo` has no
closed executable profile, so policy, a catalog entry, or operator approval
cannot authorize it. Keep `NoNewPrivileges=true`, `ProtectSystem=strict`, and
`ProtectHome=true` enabled. Host operations use a built-in profiled executable
whose complete process authority Guard can bind, or a brokered API with an
explicit protocol policy.

Administrative RPCs authenticate the admin bearer token, never a uid. The
daemon's own uid grants no operator authority, independently of the dedicated
child UID boundary. The token reaches the daemon
only through stdin at startup (`StandardInput=file:` opens the root-held file
as root and hands over the descriptor), so it never enters the daemon's
environment, argv, or any file its children can read.

Provision the token file once, as `root:root` mode `0400`:

```bash
install -m 0400 -o root -g root /dev/null /etc/guard/admin.token
openssl rand -hex 32 > /etc/guard/admin.token
```

Run operator RPCs through the root-owned wrapper, which reads the token and
presents it, and refuses to run when both or neither packaged service is
active:

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
deciding; add `--yes` for unattended runs. `GUARD_ADMIN_TOKEN` in the daemon's
own environment is supported for development only. Production daemons take the
token from stdin so it never enters the process environment.

Restrict `sudo` access to `/usr/local/sbin/guard-operator` to human operator
accounts. Access to the wrapper grants the full daemon-principal command surface.
Keep credentials out of command arguments.

`--exec-user` is the standard Unix broker model. Approved children run as a
dedicated account that cannot read the daemon database, authority key, audit
log, or secret storage. `--exec-as-caller` is an alternative for a root socket
daemon; it drops children to the authenticated caller uid and groups and is
incompatible with TCP, API proxying, and secret-file injection. Fixed identity
admits kubectl only through an active Guard proxy and denies Ansible and Helm.
Caller identity denies all three typed profile tools because it has no immutable
profile snapshot.

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
Local process execution and API proxying are unavailable on Windows because the
platform does not provide a distinct worker identity or a race-free,
client-specific authority handoff. Policy decisions, access administration,
and inspection remain available. Service mode requires exactly one named-pipe
listener and rejects
`GUARD_ADMIN_TOKEN` and `--admin-token-stdin`, so operator authority is bound
only to the kernel-authenticated SYSTEM pipe identity.

Windows rejects API proxy configuration, including brokered kubeconfig and
generic API-client output paths.

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

The state database uses schema version 14. Startup migrates an older database in
place. Treat the installed binary, configuration, API-revert body tree, and
complete SQLite file set as one rollback unit. Before the first schema-14
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

On Unix, `/usr/local/sbin/upgrade-guard` performs the tested upgrade and
rollback transaction. Install this root-owned helper from a verified source
before its first use. It accepts only the explicit `install` and `rollback`
actions, authenticates the complete release archive against an externally
verified SHA256 digest, verifies the exact installed-artifact manifest in
root-owned staging, and records the selected service unit and state ownership
with each backup.

```bash
sudo install -o root -g root -m 0755 \
  /path/to/verified-source/deployment/systemd/upgrade-guard \
  /usr/local/sbin/upgrade-guard

sudo /usr/local/sbin/upgrade-guard install \
  --release-archive /path/to/guard-release-x86_64-unknown-linux-gnu.tar.gz \
  --expected-sha256 '<digest from the verified release SHA256SUMS>'
```

The command retains a host-wide transaction lock, copies the archive into a
root-only staging directory, rejects inherited archive-tool options, and
validates every member name, type, and required release layout before
extraction. The staged candidate validates the active database with `state-db
check --json` before the service stops. A root-owned transaction journal then records the active service
identity before the daemon is stopped. The stopped daemon supplies a coherent
backup of the installed binary, operator wrapper, upgrade helper, both unit
files, configuration tree, API-revert tree, service metadata, installation HMAC
key, SQLite database, and SHA256 manifest. The API-revert tree and HMAC key are
derived from the recorded state-database parent.

The journal is beneath the root-owned, mode-`0700`
`/var/lib/guard-upgrade` directory. Recovery validates the journal directory and
records for type, ownership, and mode before reading them. A failed snapshot
restarts and verifies the unchanged deployment. A failed restore, replacement,
daemon start, or verification retains the journal for automatic recovery on the
next non-dry-run invocation. Replacement files use atomic same-directory
renames.

The helper reads the selected active unit's effective `ExecStart` setting and
requires exactly one canonical absolute `--state-db` path and `--socket` path.
It records both settings with the backup and keeps the adjacent `authority.hmac`
key and `api-proxy-reverts` tree with the matching SQLite snapshot. Missing,
repeated, escaped, or malformed settings stop the transaction before the
service is stopped. After unit replacement or restore, the helper verifies the
effective database and socket settings plus the daemon-reported status fields;
an effective drop-in or customized unit cannot silently redirect the deployment.

Run `guard state-db check --file /path/to/state.db` with the candidate binary
to simulate its schema migrations against a private SQLite snapshot. The
source database remains unchanged. `--json` reports `compatible`,
`simulated_open`, and one sanitized `rejected_rows` list. Each row identifies
its durable category, reason, and whether it blocks startup or requires
retirement before upgrade; serialized row content and session credentials are
never returned.

With the daemon stopped, retire one reported grant-request row through the same
candidate binary:

```bash
guard state-db retire-rejected-grant-request \
  --file /path/to/state.db '<handle reported by state-db check>'
```

The command acquires the daemon lease and deletes the row only when the current
binary still classifies that exact handle as rejected. Missing and accepted
rows are unchanged.

Use `--dry-run` with either action to validate its release or backup without
changing the host.

A failed install, verification, or handled signal restores the verified backup
and checks the restarted daemon's binary digest, effective `ExecStart`
`--state-db` and `--socket`, plus server-reported `state_db_path` and
`socket_path`. The helper requires `jq` for the structured status check. A stop
failure also recovers a unit that enters the `failed` state. The command prints
the backup path after a successful install.

```bash
sudo /usr/local/sbin/upgrade-guard rollback --backup-dir /var/backups/guard-install-<identifier>
```

Rollback validates that the absolute backup path is under `/var/backups` and
uses a `guard-` name containing only letters, digits, `.`, `_`, and `-`. It
creates a safety backup of the pre-rollback deployment, stages the selected
backup, swaps it into place, and restores the safety backup if a replacement or
handshake fails. The fault-injection test is
`deployment/systemd/test-upgrade-guard.sh`.

On Windows, verify the release archive checksum, extract it into an
Administrators-and-SYSTEM only directory, and rerun `install-guard.ps1` from an
elevated PowerShell with `-CandidateExe` and the digest from the archive's
`BINARY-SHA256` file as `-ExpectedSha256`. The installer copies the candidate to
protected staging, verifies the expected digest, and executes only that copy.
Before stopping the service, the staged candidate runs `state-db check --json`
against the active database and refuses incompatible durable state. The service
command line must contain exactly one canonical absolute `--state-db` and one
canonical local `--socket`. Custom values survive install, rollback, recovery,
status, and ACL validation.

An ACL-protected transaction journal records quiescing, backup, mutation, and
verification. Every install, rollback, or uninstall invocation recovers an
interrupted transaction before taking a new action. The stopped service backup
contains the installed binary, catalog, exact command line, DPAPI-protected
environment, matching HMAC key, complete SQLite file set, and durable API-revert
bodies. Replacement files are staged beside their destination for same-volume
atomic replacement. Restore removes the complete live SQLite and API-revert
sets before installing one coherent snapshot. The `authority.hmac` file grants
only the service SID access during normal operation and receives bounded
administrative access only while backup maintenance is active.

The installer verifies file hashes, the running process path, reported state
and socket paths, exact DACLs, and a `guard status --json` client/server version
handshake. A failed install restores the prior files, environment, command
line, start mode, and running state. A disabled service is temporarily set to
manual for verification, stopped again, and returned to disabled mode.
Successful backups remain under `C:\ProgramData\GuardMaintenance\backups` and
are inaccessible to the service.

The installer prints a release-version backup name after a successful upgrade.
Use that exact name for a later verified rollback:

```powershell
.\deployment\windows\install-guard.ps1 -Action rollback -Backup <backup-name>
```

Rollback validates the metadata, hashes, fixed installation paths, exact service
executable token, recorded state authority paths, and DPAPI environment backup before stopping the service. It
creates a safety backup, restores the binary, database, API-revert bodies,
installation HMAC key, catalog, exact service command, start mode, and
environment, verifies the real status/version handshake, and restores the safety backup if verification fails.

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

Guard uses a caller working directory only when typed authority binds its
canonical tree, while selecting either the fixed child identity or the
authenticated caller, a clean environment, operator-owned tool settings, and
mode-appropriate secret bindings. Every command without an explicit working
directory starts from the fixed operating-system root. Guard does not stage or
copy project files. The execution identity needs
traversal and read access to an authorized project tree. A working directory
does not enable mutable tool-profile discovery across an identity boundary.

On Unix, a brokered command running with `--exec-as-caller` that cannot read one
named non-secret file can enter the transparent read-grant path. Fixed-identity
mode refuses temporary read grants because the shared child UID would let a
concurrent execution consume another request's ACL. The standard packaged
service therefore grants only `CAP_SETUID` and `CAP_SETGID` for the fixed
identity switch and clears both before spawning brokered children.

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

Per-run plain environment, secret, and secret-file bindings are unavailable in
fixed-identity mode because a shared child UID can inspect another process with
the same credentials. `--exec-as-caller` permits plain environment and scalar
secret bindings for the authenticated caller, but refuses daemon-created secret
files.

On Unix, Guard creates private state directories as `0700` and the SQLite
database, sidecars, and installation HMAC key as `0600`. It rejects symlinked or
non-regular state files and unsafe writable parent directories instead of
opening them. Keep `authority.hmac` with its matching SQLite backup. Replacing
either half invalidates frozen command and secret authority.

## Remote command credentials

Do not place SSH keys, agent sockets, bearer files, or other durable credentials
under the fixed child account. A shared child UID is a daemon-state boundary,
not an execution sandbox, so any approved command under that UID could consume
child-readable authority. The standard upgrader requires
`/var/lib/guard-exec/.ssh` to remain empty.

Use the API proxy for daemon-held upstream credentials, or use
`--exec-as-caller` when caller-owned credentials and filesystem identity are the
intended boundary. Do not forward one caller's `SSH_AUTH_SOCK` into a shared
fixed child.

Use `GUARD_CHILD_ENV` for operator-selected daemon environment values such as a
validated broker-only `KUBECONFIG` with a generated proxy transport bearer.
Fixed-identity
mode rejects every environment name outside its small inert-variable schema.
Kubectl also requires the brokered `KUBECONFIG` and an active Guard proxy. Guard
disables kuberc and command shadowing. Fixed identity rejects Ansible and Helm
because their mutable profile state cannot safely cross identities. Caller
identity rejects Ansible, Helm, and kubectl because it has no immutable typed
profile snapshot. Caller-specific scalar secrets remain available to admitted
profiled commands under `--exec-as-caller`; the agent names an entitlement,
not the secret value.

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

Every proxy request authenticates with either the generated transport bearer or
a live Guard session bearer. Keep the brokered client file inside the fixed
worker's private group. See [API proxy](docs/api-proxy.md).

## Access authority internals

`guard access` is the supported operational workflow for requesting, approving,
inspecting, extending, and revoking authority. The daemon records prose intent
as principal-bound requests and reduces approved requests to typed enforcement
coverage.

Load internal reusable grant state with `--grants
/etc/guard/saved-grants.yaml` and the operator verb catalog with `--verbs
/etc/guard/verbs.yaml`. Both catalogs are operator-owned. An explicitly
configured missing, malformed, or duplicate catalog fails startup.

Operators of packaged Linux services can set
`GUARD_VERBS=/etc/guard/verbs.yaml` together with
`GUARD_IMMUTABLE_VERBS_LOCK=/run/guard/verbs.lock` in `/etc/default/guard`.
This mode loads the operator-owned catalog once, verifies the runtime lock, and
disables automatic verb promotion. Keep the catalog under `/etc/guard` and the
lock under the service-owned `/run/guard` runtime directory.

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
process-start and salted secret bindings captured for each command-shaped
confirmation check and rollback are also required. A row without those bindings
cannot execute its persisted command. The sweeper observes a startup grace
before processing due rows. An interrupted
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
