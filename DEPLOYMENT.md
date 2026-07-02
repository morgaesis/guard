# Deployment

Long-running `guard` server deployment as a system service.

## Scope

Use this when `guard` should listen on a local UNIX socket and serve local clients (AI agents, shims) through a system service.

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

### Execute as caller

Use this model when approved commands must run with the connecting local user's
filesystem access rather than the daemon user's state.

- Start the daemon as root with `--exec-as-caller`.
- Use only a UNIX socket. TCP listeners are incompatible because they do not
  provide trusted local peer credentials.
- Use `--users` to restrict which UIDs can submit requests.
- Approved child processes drop to the connecting peer UID before exec.
- Adjust `ReadWritePaths` in the example unit if callers have homes outside
  `/home`.

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

Without `--exec-as-caller`, the server validates caller UIDs but does not drop
privileges to the caller before execution. It executes commands as the service
identity. A root service without `--exec-as-caller` is therefore a privileged
broker, not per-user impersonation.

## Files

Example systemd files:

- [`deployment/systemd/guard.service`](deployment/systemd/guard.service)
- [`deployment/systemd/guard-exec-as-caller.service`](deployment/systemd/guard-exec-as-caller.service)
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

Install the environment file:

```bash
install -m 0600 deployment/systemd/guard.env.example /etc/default/guard
# Edit /etc/default/guard and set SSH_GUARD_LLM_API_KEY
```

Install the unit:

```bash
install -m 0644 deployment/systemd/guard.service /etc/systemd/system/guard.service
```

For caller-identity execution, install the alternate unit instead:

```bash
install -m 0644 deployment/systemd/guard-exec-as-caller.service /etc/systemd/system/guard.service
```

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
- The socket can be world-connectable at the filesystem layer because authorization is enforced by peer UID in the server.
- Restrict access with `--users` to the client UIDs that should be able to submit requests.
- For LLM-backed evaluation, provide credentials through the environment file rather than command-line arguments.
- For static-policy-only deployments, use `--no-llm` and provide a `--policy` file.
- The systemd examples use `StateDirectory=guard` and create
  `/var/lib/guard/.ssh` before startup. In daemon-identity mode, this is where
  `--hostkey accept-new` persists SSH known-hosts state. In caller-identity
  mode, known-hosts persistence follows the caller's home directory after the
  daemon drops privileges.
- Systemd units do not install shell shims or profile hooks. Users who want
  command interposition should run `guard shim ssh,scp,sftp,sudo` or
  `guard shim --default-tools` and add the printed shim directory to PATH
  intentionally.
- Pre-LLM executable validation and credential-pattern deny are off by default. Enable with `--preflight` or `SSH_GUARD_PREFLIGHT=true`. These checks are coarse and over-match (they deny any command containing the `env` token); prefer them only on hosts where LLM cost or latency dominates over false positives.
- For prompt and policy testing, run a separate `--dry-run` server on its own
  socket so approved commands are evaluated but not executed.
- Audit logs are emitted via `tracing` to stderr (captured by systemd journal).
  Use `guard -v server start` / `guard -vv server start` for foreground runs,
  or set `RUST_LOG=info` in the environment file for systemd. `RUST_LOG` takes
  precedence over `-v`, then `GUARD_LOG_LEVEL` / `SSH_GUARD_LOG_LEVEL`.
