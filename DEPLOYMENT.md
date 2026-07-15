# Deployment

A durable Guard deployment separates the agent, daemon, credentials, state, and
operator authority. The daemon listens on a local Unix socket or Windows named
pipe, and the agent has no direct route or credential for protected upstreams.

## Operating model

Guard is designed for deploy-and-forget authority. Routine work fits saved
grants and typed verbs. Recoverable changes carry a viable forward, verify, and
rollback chain. Holds are the exception for expired, conflicting, irreversible,
or connectivity-unsafe operations and return a durable escalation handle.

This supports autonomous incident response without requiring an operator to be
available during every session. Notifications can wake or inform an operator,
but notification delivery does not change a gate decision.

The principal split is mandatory:

- The daemon principal owns SSH keys, SSH agent sockets, kubeconfigs, API tokens,
  state, verb catalogs, and saved grants.
- The agent principal can connect to Guard and holds only short-lived session
  bearers.
- The operator principal is the daemon uid on Unix or daemon SID on Windows for
  approval and authorization changes.

An agent that can read daemon credentials or reach the same upstream directly
can bypass Guard.

## Unix service

The packaged files are:

```text
deployment/systemd/guard.service
deployment/systemd/guard.socket
deployment/systemd/guard.env.example
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
groupadd --system guard-clients
usermod --append --groups guard-clients agent-account
install -m 0755 target/release/guard /usr/local/bin/guard
install -m 0644 deployment/systemd/guard.service /etc/systemd/system/
install -m 0644 deployment/systemd/guard.socket /etc/systemd/system/
install -m 0600 deployment/systemd/guard.env.example /etc/default/guard
systemctl daemon-reload
systemctl enable --now guard.socket guard.service
guard status
```

Edit `/etc/default/guard` before starting the service. Keep API keys and bearer
tokens out of unit command lines. `systemctl cat guard.service` shows the exact
merged hardening and environment configuration.

Use `--users` to restrict submitting Unix uids when the socket group is broader
than the intended agent account. Set
`GUARD_ALLOWED_USERS="--users 1000,1001"` in `/etc/default/guard` when using the
packaged service. `NoNewPrivileges=true` prevents approved
children from gaining privilege through setuid helpers. A daemon that must act
as root is a sudo-like trust boundary and needs narrow callers, binary floors,
short grants, consequence gating, audit shipping, and separate agent identity.

`--exec-as-caller` is a Unix-only alternative for a root socket daemon. Approved
children drop to the authenticated caller uid and groups. It is incompatible
with TCP, API proxying, and secret-file injection. The default broker model keeps
the daemon identity because it owns the credentials the agent lacks.

## Windows service

[`deployment/windows/install-guard.ps1`](deployment/windows/install-guard.ps1)
registers Guard under `NT SERVICE\guard`. The service SID owns the named pipe,
state database, catalogs, and credential directory. Its NTFS ACL permits the
service SID, SYSTEM, and Administrators while excluding the interactive agent.

Run installation and operator decisions from an elevated shell. The interactive
agent connects under its own SID, so it cannot satisfy the daemon-principal admin
check or read daemon state. `--exec-as-caller` is unavailable; approved children
run as the service account.

Transient secret files and API rollback snapshots use protected non-inheriting
ACLs for the service SID. Guard rejects reparse points and unsafe ownership or
trustee sets. Unsafe storage disables the affected secret-file or body-bearing
revert path.

Named-pipe connect permission is not command authorization. On a multi-user
host, isolate the agent account or restrict the pipe ACL to the intended SID.

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
daemon owns every upstream credential and emits only brokered client material.
For Kubernetes, the brokered kubeconfig contains the local CA and optional Guard
session bearer, never the upstream token or client key.

Use `--api-endpoints` when one daemon serves multiple protocols or environments.
Each endpoint has a unique name, listener, mode, policy, credential reference,
and output path. Persisted rollback binds that identity and cannot cross to a
different listener.

Protect proxy ports from other local users. A Guard session bearer supplies
scope, not network client identity. See [API proxy](docs/api-proxy.md).

## Saved authority

Load reusable grants with `--grants /etc/guard/saved-grants.yaml` and verbs with
`--verbs /etc/guard/verbs.yaml`. Both catalogs are operator-owned. An explicitly
configured missing, malformed, or duplicate catalog fails startup.

Issue a session per worker or incident:

```bash
eval "$(guard grant issue host-a-maintenance --label incident-42)"
```

Prefer short TTLs for mutation authority. An issued session records its saved
grant revision. Grant edits do not rewrite frozen holds or provisionals, and
revision changes invalidate affected evaluator-cache entries.

Configure optional rolling behavioral limits for denials, holds, and denial
ratio. A suspended session becomes deny-all until the triggering behavior ages
out or the session is revoked.

## Holds, rollback, and notifications

The daemon needs durable state and continuous supervision while provisionals are
armed. It persists holds and rollback plans, but never fires an overdue rollback
blindly during startup. Monitor `guard provisionals`, `guard approvals`, and the
service audit stream after restart.

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
