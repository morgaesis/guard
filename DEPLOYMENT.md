# Deployment

Long-running `guard` server deployment as a system service.

## Scope

Use this when `guard` should listen on a local UNIX socket and serve local clients (AI agents, shims) through a system service.

On Windows, guard's native local transport is a named pipe with SID-based peer
authentication, selected with `--socket <name>` (the same flag that selects a
UNIX domain socket on Unix; the name maps to `\\.\pipe\<name>`). Point clients at
it with `guard config set-server <name>`. The named-pipe SID is the caller's
cross-platform principal, with exact parity to a Unix peer uid, so consequence
gating, per-principal secret/`--env` injection, and daemon-principal admin all
work over the pipe. The operator is whoever runs as the daemon's own principal
(its SID on Windows, its uid on Unix). Connect access is governed by the pipe
ACL — Administrators/SYSTEM/Authenticated Users by default; tighten it to a
specific agent SID on a multi-user host.

A TCP loopback transport is also available with `--tcp-port` (default
`127.0.0.1:8123`) and a shared `GUARD_AUTH_TOKEN`. A TCP caller carries only
a bearer token and no local principal, so over TCP consequence gating is refused,
secret/`--env` injection is refused, and non-Ping admin RPCs such as `guard grant`
require the separate `GUARD_ADMIN_TOKEN`. `--exec-as-caller` (setuid-style
identity drop) is Unix-only; on Windows the daemon always executes approved
commands as its own service account, and containment rests on that account
isolation rather than an identity swap.

The installer [`deployment/windows/install-guard.ps1`](deployment/windows/install-guard.ps1)
provisions the bypass-resistant Windows service model: it registers guard as a
Windows service running under the virtual service account `NT SERVICE\guard`,
which owns the named pipe, the state database (`C:\ProgramData\guard\state.db`),
the verb catalog, and any brokered credentials under an NTFS ACL that grants only
the guard SID, SYSTEM, and Administrators and removes Users/Authenticated
Users/Everyone. Because the interactive agent runs as a different, non-admin SID,
it cannot satisfy the daemon's admin check to approve its own held commands and
cannot read the brokered credentials or state. Run install/uninstall and the
operator actions (`approve`, `deny`, `confirm`, `revert`) from an elevated
PowerShell; `status`, `provisionals`, and `approvals` are read-only. Pass
`-EnvFile` to supply an LLM API key; with no key the service runs `--no-llm`
(static/verb policy only).

## Orchestrated workers with operator approval

Consequence gating and session grants compose into a foreman/worker pattern for
autonomous fleets. An orchestrator (the foreman) holds the operator role; the
daemon runs as a separate principal (a dedicated uid on Unix, the service
account on Windows); workers are agents that reach the system only through
`guard run` and `guard verb`.

1. The foreman mints a scoped session grant for each worker —
   `guard session new --allow '<glob>' --prompt '<intent>' --ttl <secs>`, or
   `guard grant` with a prose description — and hands the worker the resulting
   `GUARD_SESSION` token. The grant narrows what the worker may attempt without
   relaxing the global mode.

2. The foreman loads a gated verb catalog with `--verbs`
   ([`examples/verbs-kubectl.yaml`](examples/verbs-kubectl.yaml) is a reference).
   Each verb pins a binary and an anchored, pattern-validated argv template, and
   declares a consequence class. The catalog's `context` parameter is an explicit
   allowlist of non-production clusters; a production context is not in the
   alternation, so every verb rejects it and a worker cannot target production
   through any verb.

3. Workers call `guard verb run <name> --param k=v` or `guard run <cmd>` through
   the daemon. With `--gate consequence`, reversible operations (read-only
   inspection) run immediately, recoverable operations run behind an auto-revert
   envelope, and irreversible operations are held for operator approval and not
   executed.

4. The foreman reviews held work with `guard approvals` / `guard provisionals`
   and decides with `guard approve|deny|confirm|revert <handle>`. These control
   RPCs are accepted only from the daemon's own principal, so a worker can never
   approve its own held command — the irreversible steps stay with the operator.

The trust boundary is the principal split: workers run as a different principal
than the daemon, so the gate, the secret namespace, and the approval RPCs are all
beyond their reach. This holds identically on Unix (uid separation) and Windows
(service-account isolation with ACL'd state and credential directories).

## Recommended deployment

Choose the deployment model based on what authority the daemon should have.

### Policy gate / secret broker

Use this model when `guard` should mediate commands the daemon user can already
run, inject configured secrets, redact output, or broker SSH commands to remote
hosts.

- Run guard as a dedicated unprivileged user (e.g., `guard`).
- Enable systemd hardening directives (`NoNewPrivileges`, `ProtectSystem`, `PrivateTmp`).
- The service cannot act like `sudo`: local commands execute as the daemon user,
  and `NoNewPrivileges` prevents setuid helpers such as `sudo` from elevating.
- This model is useful for read-only inspection, SSH proxying, and secret
  injection where local privilege escalation is not required.

### Privileged command broker

Use this model only when `guard` is intentionally trusted to run privileged local
commands after policy approval.

- The agent process should run as a separate unprivileged user, restricted to connecting to the guard socket.
- Use `--users` to restrict which UIDs can submit requests.
- Provide the LLM API key via the environment file (`/etc/default/guard`), not CLI arguments.
- Do not use `User=guard` or `NoNewPrivileges=true` if the daemon must execute
  commands with root authority or invoke setuid helpers such as `sudo`.
- Treat the daemon as a sudo-like trust boundary. If policy approves a command,
  it executes with the daemon's privileges.
- The agent should not have access to the guard process's `/proc/*/environ` or `/proc/*/cmdline` (ensured by running as a different user with standard procfs hidepid or systemd's `ProtectProc`).
- For containers, use `env_clear` (enabled by default) so child processes never see the API key. Output redaction (also default) catches secrets in command output.

By default the server validates caller UIDs but executes commands as its own
service identity, so a root service is a privileged broker, not per-user
impersonation. A Unix root daemon started with `--exec-as-caller` over a
Unix-socket-only listener instead drops each child to the calling uid before
exec, making it a per-user secret broker. `--exec-as-caller` is Unix-only.

## OS-level sandboxing profiles

`guard profile seccomp` emits a default-allow seccomp profile (use via
`--security-opt seccomp=<file>` on Docker/Podman) that denies
container-escape and host-tampering syscalls (`mount`, `pivot_root`,
`ptrace`, kernel module load, etc.) while leaving the daemon's legitimate
operation -- spawning approved child commands, TLS calls to the LLM
provider, reading/writing its state directory -- intact.

`guard profile apparmor --exe <path-to-binary> --data-dir <state-dir>`
emits an AppArmor profile confining the daemon to its binary, data
directory, and child-command execution. Apply it alongside the systemd
hardening directives below; it is a complementary, OS-level layer, not a
replacement for `NoNewPrivileges`/`User=guard`/`--users`.

## Auto-learned deny shapes

Auto-learned deny shapes (`--learn-deny`, on by default) write a state file,
`learned-deny.yaml`, alongside `learned-rules.yaml` and `state.db` in the
daemon's state directory. It's a deny-only fast path the daemon populates
itself from repeated LLM denials -- it never grants a bypass, so it needs no
operator review step, and upgrading an existing deployment enables it
automatically. Check `guard status` for `learn_deny enabled=... shapes=N` to
see whether it's active and how many shapes it has learned; disable with
`--no-learn-deny` / `GUARD_LEARN_DENY=false` if you want to fully opt out
(this stops new learning; it does not retroactively remove shapes already on
disk -- delete or edit `learned-deny.yaml` for that). A caller can force a
fresh LLM look past a specific auto-learned deny with `guard run --reevaluate`.

## Files

Example systemd files:

- [`deployment/systemd/guard.service`](deployment/systemd/guard.service)
- [`deployment/systemd/guard.env.example`](deployment/systemd/guard.env.example)

These examples are intentionally generic. Adjust user, group, socket path, allowed UIDs, mode, and hardening directives for the target host.

## Suggested layout

- Binary: `/usr/local/bin/guard`
- Service unit: `/etc/systemd/system/guard.service`
- Environment file: `/etc/default/guard`
- UNIX socket: `/run/guard/guard.sock`

## Example flow

Install the binary:

```bash
install -m 0755 guard /usr/local/bin/guard
```

Create the service user:

```bash
useradd --system --home-dir /var/lib/guard --create-home --shell /usr/sbin/nologin guard
```

Install the environment file:

```bash
install -m 0600 deployment/systemd/guard.env.example /etc/default/guard
# Edit /etc/default/guard and set GUARD_LLM_API_KEY
```

Install the unit:

```bash
install -m 0644 deployment/systemd/guard.service /etc/systemd/system/guard.service
```

By default, any local UNIX-socket caller can submit requests. To restrict
access to specific client UIDs, add a comma-separated `--users` list to
`ExecStart`, for example `--users 1000,1001`.

Reload and start:

```bash
systemctl daemon-reload
systemctl enable --now guard
```

Verify:

```bash
systemctl status guard
ls -l /run/guard/guard.sock
```

## Notes

- The service runs in server mode over a UNIX socket.
- On Windows, run `deployment/windows/install-guard.ps1` to register the
  service-account model over a named pipe; this is required for consequence
  gating and credential brokering, since both authorize on the named-pipe SID.
  For a no-gating deployment, run `guard server start --tcp-port 8123
  --learn-rules` from a service manager or scheduled task, set
  `GUARD_LLM_API_KEY` / `OPENROUTER_API_KEY` in that service environment, and
  use `guard config set-port 8123` for clients on the same host.
- The socket can be world-connectable at the filesystem layer because authorization is enforced by peer UID in the server.
- Omit `--users` to allow any local UNIX-socket caller. Add `--users` only when the daemon should reject all callers outside a specific UID list.
- The packaged unit stores persistent session state at `/var/lib/guard/state.db`, which remains writable under the default systemd sandbox profile.
- For LLM-backed evaluation, provide credentials through the environment file rather than command-line arguments.
- For static-policy-only deployments, use `--no-llm` and provide a `--policy` file.
- For latency-sensitive service APIs, enable learned static allows with
  `--learn-rules`; use `--learn-shims suggest` or `--learn-shims create` to
  surface shorter wrappers for repeated SSH/API prefixes.
- Pre-LLM executable validation and credential-pattern deny are off by default. Enable with `--preflight` or `GUARD_PREFLIGHT=true`. These checks are coarse and over-match (they deny any command containing the `env` token); prefer them only on hosts where LLM cost or latency dominates over false positives.
- For prompt and policy testing, run a separate `--dry-run` server on its own
  socket so approved commands are evaluated but not executed.
- Audit logs are emitted via `tracing` to stderr (captured by systemd journal). Set `RUST_LOG=info` in the environment file for standard logging.
