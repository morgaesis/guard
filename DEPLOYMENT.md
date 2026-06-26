# Deployment

Long-running `guard` server deployment as a system service.

## Scope

Use this when `guard` should listen on a local UNIX socket and serve local clients (AI agents, shims) through a system service.

On Windows, guard runs with the TCP loopback transport instead of Unix sockets.
Start it with `--tcp-port` (or use the Windows default `127.0.0.1:8123`) and
configure clients with `guard config set-port 8123`. TCP callers do not carry a
trusted Unix UID, so UID-scoped secret injection, `--exec-as-caller`, and
daemon-UID admin are unavailable. TCP admin RPCs such as `guard grant` require a
separate `SSH_GUARD_ADMIN_TOKEN`; the ordinary TCP exec token is not sufficient.

The helper script [`deployment/windows/guard-launch.ps1`](deployment/windows/guard-launch.ps1)
starts the Windows daemon with loopback TCP, optional learned rules, and logs
under `%LOCALAPPDATA%\guard`. Pass `-EnvFile` when credentials live outside the
repository, for example in a WSL home directory. If Windows does not have a
kubeconfig, the launcher attempts a one-time copy from Ubuntu WSL's
`$KUBECONFIG` or `~/.kube/config` into `%USERPROFILE%\.kube\config` before
starting the native Windows daemon; pass `-NoCopyKubeconfig` to disable that
bootstrap. The launcher also generates and stores separate TCP exec/admin tokens
with `guard config set-token` and `guard config set-admin-token` when they are
missing.

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

The current server validates caller UIDs but does not drop privileges to the
caller before execution. It executes commands as the service identity. A root
service is therefore a privileged broker, not per-user impersonation.

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
# Edit /etc/default/guard and set SSH_GUARD_LLM_API_KEY
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
- On Windows, run `guard server start --tcp-port 8123 --learn-rules` from a
  service manager or scheduled task and set `SSH_GUARD_LLM_API_KEY` /
  `OPENROUTER_API_KEY` in that service environment. Use `guard config set-port
  8123` for clients on the same host.
- The socket can be world-connectable at the filesystem layer because authorization is enforced by peer UID in the server.
- Omit `--users` to allow any local UNIX-socket caller. Add `--users` only when the daemon should reject all callers outside a specific UID list.
- The packaged unit stores persistent session state at `/var/lib/guard/state.db`, which remains writable under the default systemd sandbox profile.
- For LLM-backed evaluation, provide credentials through the environment file rather than command-line arguments.
- For static-policy-only deployments, use `--no-llm` and provide a `--policy` file.
- For latency-sensitive service APIs, enable learned static allows with
  `--learn-rules`; use `--learn-shims suggest` or `--learn-shims create` to
  surface shorter wrappers for repeated SSH/API prefixes.
- Pre-LLM executable validation and credential-pattern deny are off by default. Enable with `--preflight` or `SSH_GUARD_PREFLIGHT=true`. These checks are coarse and over-match (they deny any command containing the `env` token); prefer them only on hosts where LLM cost or latency dominates over false positives.
- For prompt and policy testing, run a separate `--dry-run` server on its own
  socket so approved commands are evaluated but not executed.
- Audit logs are emitted via `tracing` to stderr (captured by systemd journal). Set `RUST_LOG=info` in the environment file for standard logging.
