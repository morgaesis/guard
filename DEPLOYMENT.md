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
ACL - Administrators/SYSTEM/Authenticated Users by default; tighten it to a
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

1. The foreman mints a scoped session grant for each worker:
   `guard session new --allow '<glob>' --prompt '<intent>' --ttl <secs>`, or
   `guard grant` with a prose description, and hands the worker the resulting
   `GUARD_SESSION` token. The grant narrows what the worker may attempt without
   relaxing the global mode. The token is bearer access to that scoped session.
   Generated static-grant notes are stored separately from prompt context and
   appear in `session list` / `session show`.

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
   approve its own held command. The irreversible steps stay with the operator.

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

Static hardening profile examples live under `deployment/hardening/`.
`seccomp-deny-escape.json` is a default-allow seccomp profile for
Docker/Podman `--security-opt seccomp=<file>` deployments. It denies
container-escape and host-tampering syscalls such as `mount`, `pivot_root`,
`ptrace`, kernel module load, keyring manipulation, and host clock changes
while leaving normal daemon operation intact.

`guard.apparmor.example` confines the daemon to its binary, state directory,
system libraries, certificates, and child-command execution paths. Set the
executable path and data directory to match the deployment before loading it.
Use these files alongside the systemd hardening directives below; they are an
OS-level layer, not a replacement for `NoNewPrivileges`, `User=guard`, or
`--users`.

## Auto-learned deny shapes

Auto-learned deny shapes (`--learn-deny`, on by default) write a state file,
`learned-deny.yaml`, alongside `learned-rules.yaml` and `state.db` in the
daemon's state directory. It is a deny-only fast path the daemon populates
itself from repeated LLM denials. It never grants a bypass, so it needs no
operator review step. Check `guard status` for `learn_deny enabled=... shapes=N` to
see whether it is active and how many shapes it has learned; disable with
`--no-learn-deny` / `GUARD_LEARN_DENY=false` if you want to fully opt out
(this stops new learning; it does not retroactively remove shapes already on
disk, delete or edit `learned-deny.yaml` for that). A caller can force a
fresh LLM look past a specific auto-learned deny with `guard run --reevaluate`.

## Auto-verb-promotion

Auto-verb-promotion (`--learn-allow`, on by default, requires `--gate
consequence`) writes a bookkeeping state file, `learned-allow.yaml`, alongside
the other state files above, and -- once a repeated shape qualifies --
appends an actual verb to the catalog (`--verbs`; a default `verbs.yaml` is
created in the state directory if `--verbs` was not given). Unlike learned-rule
candidate detection, this needs no operator step at all: most real deployments
are unattended, so a design that depends on an operator reading a notice and
running `guard verb create` does not fire in practice. It is deliberately far
more conservative than an operator-driven verb, on several axes explained in
`gating::allow_promotion`'s module docs -- in short, every parameter's allowed
values are pinned to the exact, regex-escaped values actually observed (never
a model-authored pattern), an irreversible shape is never eligible, and a
recoverable shape is promoted only with a validated revert. A promoted verb is
stamped to the model + prompts that justified it, so a model or prompt change
silently stops trusting verbs promoted under the old judgment rather than
carrying that trust forward.

Check `guard status` for `learn_allow enabled=... observations=N` (the
observation count, not the number of verbs promoted). `guard verb list` is the
actual, human-readable record of what has been auto-promoted -- entries carry
`auto_promoted: true` and the evidence that justified them, and the reported
`trusted` state already accounts for a stale promotion (see above), so a verb
the daemon has silently stopped honoring shows as untrusted here too. `guard
verb list` is also the revocation mechanism: edit or delete an entry in the
verb catalog file like any other verb. Disable with `--no-learn-allow` /
`GUARD_LEARN_ALLOW=false` if you want to fully opt out (this stops new
promotions; it does not retroactively remove verbs already in the catalog).
Distributing or synchronizing a verb catalog across a multi-host deployment is
an operator concern; each daemon promotes independently into its own
`--verbs` file.

**Upgrading an existing deployment.** `--learn-allow` is on by default, same
as `--learn-deny`, but unlike deny-shape learning it needs `--gate consequence`
to do anything at all (with gating off there is no reversibility
classification to key eligibility on, so the store stays inert). If you
already run `--gate consequence` without `--verbs`, upgrading in place will,
for the first time, create a live verb catalog under the default state
directory and start populating it with `trusted: true` verbs from ordinary
traffic - a real change in what "no `--verbs` flag" means for that
deployment. If you'd rather opt in deliberately, either add `--no-learn-allow`
or configure `--verbs` explicitly and review `guard verb list` periodically.

**Pin state paths explicitly under a hardened systemd unit.** The default
paths for `--verbs`, `--learn-allow-state`, `--deny-shapes`, and
`--learned-rules` all resolve through the same XDG state-dir lookup as
`--state-db`'s default (`dirs::state_dir()`, typically `$HOME/.local/state`)
-- but the packaged unit (`deployment/systemd/guard.service`) only pins
`--state-db` explicitly, to `/var/lib/guard/state.db`. Left unpinned, the
other files land under `/var/lib/guard/.local/state/guard/` -- covered by
`ReadWritePaths=/var/lib/guard` and so not a startup failure, but a nested,
non-obvious location an operator inspecting `/var/lib/guard/` won't find. If
you enable `--gate consequence` on the packaged unit, also pass `--verbs
/var/lib/guard/verbs.yaml` (after seeding it: `echo 'verbs: []' >
/var/lib/guard/verbs.yaml`, since an explicitly-named `--verbs` path must
already exist) to keep the catalog in the conventional location; the
bookkeeping files (`--learn-allow-state`, `--deny-shapes`, `--learned-rules`)
tolerate a missing path and can be pinned the same way without a seed step.

**Auto-promotion rewrites your whole catalog file on every append.** Appending
a verb (auto-promoted or via `guard verb create`) re-serializes the entire
`--verbs` YAML document rather than appending a line, so a hand-authored
catalog under version control will show its whole file reformatted/reordered
-- not just one new entry -- the first time a promotion lands, and any
inline comments are not preserved across that rewrite.

**Promotion failures are log-only.** A promotion attempt that the model
declines, or that fails validation, or that fails to append (e.g. a verb-name
collision with an existing catalog entry) is visible only via
`tracing::warn!`/`tracing::debug!` log lines (`grep -i "verb-promotion\|verb
auto_promoted" ` your journal), not in `guard status` or `guard verb list`.
A definitive failure (validation or append) permanently stops retrying that
shape; check the logs if a shape you expected to see promoted never appears
in `guard verb list`.

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
