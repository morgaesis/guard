# guard

LLM-evaluated command gate for AI agents. Every command gets evaluated by a fast LLM call before execution. Approved commands run normally. Denied commands return an explanation.

```
$ guard run ls -la /etc/nginx/
drwxr-xr-x 8 root root 4096 Mar 10 14:22 .
-rw-r--r-- 1 root root 1482 Mar 10 14:22 nginx.conf

$ guard run rm -rf /etc/nginx/
DENIED: Recursive deletion of system config directory.
```

## Why

AI agents (Claude Code, Codex, Aider, OpenHands, CrewAI, etc.) increasingly need command execution access for debugging, log analysis, and ops tasks. A single hallucinated `rm -rf` or `kubectl delete namespace` can take down production.

Guard sits between the agent and the shell. Every command gets evaluated by an LLM (`openai/gpt-5.4-nano` via OpenRouter by default) before it reaches the system. The LLM analyzes intent and risk, not just pattern matching, so it catches obfuscated attacks and novel command chains that static policies miss.

Cost is negligible: each evaluation uses roughly 3600 prompt + 45 completion tokens, costing about $0.0005 per decision with `openai/gpt-5.4-nano`. A full 45-case CTF adversarial benchmark runs for about $0.02 total.

## Install

```bash
cargo install --path .
```

Or download a release artifact and install the binary manually.

See [INSTALL.md](INSTALL.md) for install options and [DEPLOYMENT.md](DEPLOYMENT.md) for service deployment.

## Quick start

```bash
# Set your API key (OpenRouter, or any OpenAI-compatible endpoint)
export SSH_GUARD_LLM_API_KEY="your-key-here"

# Start the server
guard server start &

# Execute commands through the guard
guard run uptime
guard run cat /var/log/syslog
guard run ps aux

# These will be denied:
guard run rm -rf /tmp/*
guard run sudo su
```

To test policy decisions without executing approved commands, start a separate
dry-run server:

```bash
guard server start --dry-run --socket .cache/guard-dry-run.sock
guard server connect --socket .cache/guard-dry-run.sock bash -- -c 'sudo id'
```

## Modes

Set via `SSH_GUARD_MODE`:

| Mode | Description |
|---|---|
| `readonly` | Read-only evaluation. Blocks file writes, system or service state changes, package changes, privilege escalation, reverse shells, and obfuscated payloads. Allows routine inspection commands like `ls`, `ps`, `cat`, `grep`, `df`. |
| `safe` | Permissive administrative evaluation. Allows visible, bounded troubleshooting and admin work, but blocks credential-material reads, destructive operations, privilege escalation, unauthorized network pivots, and hidden payloads. |
| `paranoid` | Restrictive. Blocks writes, sensitive file reads, network connections, shells, interpreters, side-channel execution, and chained commands. Only allows basic non-sensitive inspection (`id`, `hostname`, `pwd`, `ls`, `ps`, `df`, limited `git status`). |

Use `readonly` when agents should investigate production state without changing
it. Use `safe` when an operator is supervising real sysadmin work and wants
bounded writes, targeted restarts, and ordinary maintenance to be possible while
still blocking destructive or credential-seeking commands. Use `paranoid` for
untrusted agents, adversarial testing, or first contact with an unfamiliar
workspace where even broad reads and network access should be treated as risky.

```bash
SSH_GUARD_MODE=safe guard run sudo systemctl status ssh --no-pager  # allowed
SSH_GUARD_MODE=paranoid guard run sudo systemctl status ssh --no-pager  # denied
```

All modes evaluate `sudo` by the underlying command:

```bash
guard run sudo ls /etc/nginx/        # readonly: allowed (read operation)
guard run sudo rm -rf /etc/nginx/    # readonly: denied  (destructive)
guard run sudo systemctl restart app # safe: allowed     (targeted restart)
```

## Configuration

### Defaults vs. opt-ins

Guard ships with an LLM-only evaluation pipeline: a single call to
`openai/gpt-5.4-nano` via OpenRouter, function-calling based, with two retries
before failing closed. No static allow or deny lists are loaded. No fallback
model chain is active. This default is production-ready for the common case.

Two opt-in features exist for deployments with specific constraints:

- **Static allow/deny lists** via `--policy <yaml>`. Short-circuits the LLM
  for deterministic safe or unsafe patterns. See
  [`examples/`](examples/README.md) for `allow-policy.yaml`,
  `deny-policy.yaml`, and `hybrid-policy.yaml`.
- **Fallback model chain** via `SSH_GUARD_LLM_MODELS`. Fails over to
  alternate providers after the primary exhausts its retries. See
  [`examples/fallback-models.env`](examples/fallback-models.env).
- **Learned static rules** via `--learn-rules`. Repeated low-risk LLM
  approvals can promote conservative exact static allow rules so repeated
  calls return immediately. Misses and risky commands still fall through to
  the LLM.

Enable either only when a concrete latency or uptime constraint forces it.

### Environment variables

All configuration via environment variables, CLI flags, or `.env` files.

Guard walks up from your current directory to `/` looking for `.env` files (closest wins), so you can scope config per project.

| Variable | Default | Description |
|---|---|---|
| `SSH_GUARD_LLM_API_KEY` / `OPENROUTER_API_KEY` | (none) | LLM API key (required). `OPENROUTER_API_KEY` is the conventional name and is accepted for compatibility. |
| `SSH_GUARD_LLM_API_URL` / `SSH_GUARD_API_URL` | `https://openrouter.ai/api/v1/chat/completions` | Any OpenAI-compatible endpoint |
| `SSH_GUARD_LLM_MODELS` | (unset) | Optional comma-separated fallback chain (e.g. `openai/gpt-5.4-nano,meta-llama/llama-4-maverick`). When set, overrides `--llm-model` and is tried in order, each with its own retry budget. Primary model when unset: `openai/gpt-5.4-nano`. |
| `SSH_GUARD_LLM_RETRIES` | `2` | Retries per model on transient failures (429, timeouts, parse errors). 1-2. |
| `SSH_GUARD_LLM_TIMEOUT` / `SSH_GUARD_TIMEOUT` | `30` | LLM call timeout in seconds. |
| `SSH_GUARD_AUTH_TOKEN` | (none) | Shared token for TCP clients. Use this for loopback TCP daemons instead of passing `--auth-token` on the command line. |
| `SSH_GUARD_ADMIN_TOKEN` | (none) | Separate token for TCP admin RPCs such as `guard grant`, `guard session show`, and the full `guard status`. The Windows launcher generates and stores one automatically. |
| `SSH_GUARD_MODE` | `readonly` | `readonly`, `safe`, or `paranoid` |
| `SSH_GUARD_DRY_RUN` | `false` | Evaluate policy but do not execute approved commands. Useful for prompt and policy testing. |
| `SSH_GUARD_LEARN_RULES` | `false` | Learn static allows from repeated low-risk LLM approvals. |
| `SSH_GUARD_LEARN_MIN_APPROVALS` | `2` | Approvals required before promotion. |
| `SSH_GUARD_LEARN_MAX_RISK` | `2` | Highest LLM risk score eligible for promotion. |
| `SSH_GUARD_LEARN_SHIMS` | `suggest` | `off`, `suggest`, or `create` service shims for learned SSH/API wrappers. |
| `SSH_GUARD_PROMPT_APPEND` | (none) | Path to additive prompt file (appended to base prompt) |
| `SSH_GUARD_GPG_RECIPIENT` | (none) | GPG recipient for the `local` secret backend |
| `SSH_GUARD_BACKEND` | (auto) | Secret backend (`pass`, `env`, `local`). Auto prefers `pass`; otherwise it falls back to non-persistent `env` and logs a warning. |

The primary model is `openai/gpt-5.4-nano` via OpenRouter by default. Set it
per-invocation with `--llm-model <slug>`. To configure a true fallback chain
across providers, use `SSH_GUARD_LLM_MODELS` (comma-separated) or
`--llm-models`. `--llm-timeout <seconds>` controls the per-call HTTP timeout.

See [`.env.example`](.env.example) for a copyable template.

## Examples

### Basic server with readonly mode

Start the guard server and execute commands through it:

```bash
export SSH_GUARD_LLM_API_KEY="sk-or-v1-..."

guard server start --socket .cache/guard.sock &
guard config set-server .cache/guard.sock

# Allowed: routine inspection
guard run hostname
# guard-host

guard run ps aux
# USER  PID %CPU %MEM    VSZ   RSS TTY STAT START   TIME COMMAND
# root    1  0.0  0.0   4624  3456 ?   Ss   10:00   0:00 /sbin/init

# Denied: destructive
guard run rm -rf /
# DENIED: Recursive deletion of root filesystem

# Denied: obfuscated attack
guard run bash -c 'eval $(echo cm0gLXJmIC8= | base64 -d)'
# DENIED: Base64-decoded payload piped through eval
```

When using `guard server connect` directly (rather than `guard run`), target
arguments are forwarded after the target binary:
`guard server connect --socket .cache/guard.sock df -h`.

### Safe mode

Safe mode allows visible, bounded administration while still blocking direct
credential-material reads and obvious escalation paths:

```bash
SSH_GUARD_MODE=safe guard server start --socket .cache/guard.sock &

# Allowed: ordinary inspection and work files
guard run cat /etc/hosts
# 127.0.0.1 localhost

guard run cp README.md .cache/readme-copy
# copied

# Denied: credential material
guard run cat /app/.env
# DENIED: Credential material read

# Still denied: privilege escalation
guard run sudo su
# DENIED: Escalation to root shell
```

### Paranoid mode for untrusted agents

Paranoid mode locks down to basic read-only inspection:

```bash
SSH_GUARD_MODE=paranoid guard server start --socket .cache/guard.sock &

# Allowed: basic system state
guard run id
# uid=1000(agent) gid=1000(agent) groups=1000(agent)

guard run df -h
# Filesystem      Size  Used Avail Use% Mounted on
# /dev/sda1       100G   45G   55G  45% /

# Denied: file reading
guard run cat /etc/passwd
# DENIED: File reading blocked in paranoid mode

# Denied: environment inspection
guard run env
# DENIED: Environment variable dump blocked in paranoid mode
```

### Static deny policy

For fast-reject of known-bad patterns without an LLM call, add a static deny policy:

```bash
guard server start --policy examples/deny-policy.yaml --socket .cache/guard.sock &
```

Static patterns are checked first. If a command matches a deny pattern, it is rejected immediately without an LLM call. Commands that pass static policy are then evaluated by the LLM.

See [`examples/deny-policy.yaml`](examples/deny-policy.yaml) for a reference policy with documented limitations of static glob matching.

### Learned static rules

For services with repetitive low-risk calls, enable learned rules:

```bash
guard server start \
  --learn-rules \
  --learn-min-approvals 2 \
  --learn-max-risk 2 \
  --learn-shims suggest \
  --socket .cache/guard.sock &
```

When the LLM repeatedly approves the same low-risk command shape, guard writes
a learned allow rule to the state directory and future identical calls bypass
the LLM. Learned rules never deny or wildcard over service verbs; misses,
session-prompted calls, and commands with destructive shell-control tokens fall
back to normal evaluation. For SSH API wrappers, guard may also mention a
shorter service shim such as `opnsense-api`; with `--learn-shims create`,
promoted rules create that wrapper in the configured shim directory, and the
same approved operation is covered through the shim name.

### Custom system prompt

Replace the built-in prompt entirely for a specific deployment:

```bash
guard server start --system-prompt /etc/guard/my-prompt.txt --socket .cache/guard.sock &
```

Or place a prompt file at `~/.config/guard/system-prompt.txt` to override automatically.

### Additive prompt

Append environment-specific instructions to the built-in prompt without replacing it:

```bash
# Via CLI flag
guard server start --system-prompt-append /etc/guard/extra-rules.txt &

# Or via environment variable
SSH_GUARD_PROMPT_APPEND=/etc/guard/extra-rules.txt guard server start &
```

Example additive prompt (`extra-rules.txt`):

```
Additional rules for this environment:

- This server runs a PostgreSQL database. Allow SELECT queries via psql but deny DROP, DELETE, or TRUNCATE.
- The /opt/app directory contains the application. Allow reads but deny writes.
- Allow docker ps and docker logs but deny docker exec, docker run, and docker rm.
```

The additive prompt is appended to whichever base prompt is active (readonly, safe, paranoid, or custom), letting operators customize behavior without maintaining a full prompt fork.

## Session grants

Session grants hand a specific agent narrow extra permissions for a specific run, without relaxing the global mode. The agent identifies its session by the `GUARD_SESSION` env var; every `guard run` (and `guard server connect`) reads that env var and forwards it as the session token in the request. Operators attach allow/deny patterns, prose intent, and prompt context to that token.

The simplest flow is `guard session new`, which mints a token and (optionally) grants it in one round trip, printing an eval-friendly export line:

```bash
# Operator: mint a session, grant it, capture the token in the current shell
eval "$(guard session new \
  --allow 'mkdir /tmp/job-42*' \
  --allow 'rm /tmp/job-42/scratch*' \
  --prompt 'This session is preparing /tmp/job-42 as scratch space.' \
  --ttl 3600)"

# Now any agent launched from this shell inherits GUARD_SESSION
claude
# or
GUARD_SESSION="$GUARD_SESSION" my-agent
```

Inside the agent's process tree, every `guard run` call automatically picks up `GUARD_SESSION` from the inherited environment, so the model itself does not need to know or pass the token explicitly — it is bound to the shell that launched the agent.

To grant rules to an existing token (e.g. one the agent already has):

```bash
guard session grant <token> --allow '<glob>' --deny '<glob>' [--ttl N] [--prompt TEXT] [--auto-amend]
```

There is also a top-level shorthand. With a quoted prose description it mints and
grants a fresh session, again printing an eval-friendly export line:

```bash
eval "$(guard grant --ttl 3600 --static-only 'readonly access to nextcloud resources in the morgaesis-dev kube cluster, not secrets, with write access for scaling replicas and editing ingresses')"
```

For an existing token, pass the token first:

```bash
guard grant <token> "readonly access to nextcloud resources in the morgaesis-dev kube cluster, not secrets, with write access for scaling replicas and editing ingresses"
```

Prose grants are compiled at grant time into conservative static rules when guard recognizes the domain. The first compiler handles Kubernetes: it infers namespaces such as `nextcloud`, optional contexts such as `morgaesis-dev`, adds hard denies for shell-control, secret access, token creation, raw kubeconfig reads, `exec`, `cp`, `port-forward`, and deletes, then adds namespace-scoped read, scale, and ingress/reverse-proxy rules implied by the prose. Safe command examples in backticks are added as exact static allows. Unrecognized prose is still stored as session LLM context, but does not create broad static globs.

Session allow/deny patterns use guard's shell-style glob matcher, not regex. `*`, `?`, and bracket classes are supported, but the match is against the flat reconstructed command line; it does not understand shell quoting, Kubernetes resource schemas, or argument semantics. Generated rules therefore use broad globs sparingly: for example, Kubernetes prose grants may add namespace-bounded `get * -n nextcloud` and `describe * -n nextcloud` read globs, backed by explicit secret and mutating-resource denies. Automatic amendments do not add globs at all; they add exact `binary + argv` rules, so literal `*` or `[` characters in an appealed command do not become wildcards.

Matching deny patterns win over allow patterns, and by default everything that does not match a session rule falls through to the normal evaluator with the session prose/prompt appended. Prose grants enable `auto_amend` by default so fresh low-risk LLM fallback approvals can add exact session allows, and fresh high-risk LLM denials can add exact session denies. Use `--no-auto-amend` to keep fallback non-mutating, or `--auto-amend` to opt a manual `--allow`/`--deny` grant into the same behavior. Cache hits, static policy hits, and learned-rule hits never amend a session; session fallback also does not promote global learned rules. Add `--static-only` (alias `--no-llm-fallback`) to `guard grant`, `guard session grant`, or `guard session new` to deny any session-rule miss instead of falling through to the LLM; static-only grants disable auto-amend.

To ask for a one-off amendment without executing the command, appeal it:

```bash
guard appeal --session <token> kubectl get httproute -n nextcloud
# or, when GUARD_SESSION is already set:
guard appeal kubectl get httproute -n nextcloud
# equivalent explicit session subcommand:
guard session appeal <token> kubectl get httproute -n nextcloud
```

An appeal runs the evaluator with the session context and then either amends an exact allow, amends an exact deny for a high-risk denial, or refuses to amend. It exits nonzero when the appealed command remains denied. Appeals are admin RPCs, like grant/revoke/show, because they can change durable authorization state.

Session grants are persisted in the daemon state database and survive daemon restarts by default. The default path is the XDG state dir (`$XDG_STATE_HOME/guard/state.db` or `~/.local/state/guard/state.db`); override it with `--state-db` or `SSH_GUARD_STATE_DB`. `guard session revoke <token>` is daemon-UID-only; `guard session list` is visible over the Unix socket to exec-allowed local users, but it redacts the bearer token, rule bodies, and prompt text unless the caller is the daemon UID.

For operator forensics, `guard session show <token>` is daemon-UID-only and prints the full prompt, aggregate allow/deny and exec outcome counts, source breakdown (`llm`, `cache`, `static_policy`, `session_allow`, `session_deny`, `session_static_only`, `validation`), a risk histogram for LLM-evaluated calls, and a bounded recent interaction log. Those summaries are loaded from the state database, so they remain available after a service restart within the configured retention window.

## Per-run secret injection

`guard run` can request stored secrets for one approved command without requiring a shim or persistent tool config. The daemon resolves the secret values immediately before exec, injects them into the child environment, and includes those values in exact-match output redaction.

`guard secrets add/list/remove` are Unix-socket-only, per-user operations. Any exec-allowed local user can manage their own secret namespace; TCP clients cannot use secret storage or `--secret`, because the namespace is keyed from Unix peer credentials. When the daemon UID runs `guard secrets list`, it gets an aggregate names-only view across every UID namespace; duplicate key names can appear more than once and are intentionally not annotated with ownership in the default list output.

For daemon-side migration and cleanup, use `guard secrets list --detailed` as the daemon UID. That view includes `uid=` for namespaced entries and `origin=legacy` for pre-namespace flat secrets that still need operator migration.

Upgrade note: pre-namespace flat secrets are no longer served through normal per-user `guard secrets list` / `guard run --secret` paths. Migrate them before rollout:

- `pass`: move `guard/<key>` to `guard/u<uid>/<key>`
- `env`: rename `GUARD_SECRET_<KEY>` to `GUARD_SECRET_U<uid>_<KEY>`
- `local`: rewrite the flat YAML `{ KEY: value }` into `{ <uid>: { KEY: value } }`

After migration, verify with `guard secrets list` as the target user and `guard run --secret KEY ...`.

For a stored secret with a shell-safe name, `--secret NAME` injects `$NAME`:

```bash
guard run \
  --secret OPNSENSE_API_KEY \
  --secret OPNSENSE_API_SECRET \
  --secret OPNSENSE_USERNAME \
  ssh opnsense-host 'configctl system status'
```

For a stored secret with dashes, slashes, or lowercase names, bare `--secret` derives an uppercase env var by replacing separators with underscores:

```bash
guard run --secret opnsense-apikey-secret \
  sh -c 'opnsense-tool --key "$OPNSENSE_APIKEY_SECRET"'
```

Map a different environment variable name to a stored secret key with `ENV_VAR=secret-name`:

```bash
guard run --secret OPNSENSE_API_KEY=atlas/opnsense-apikey ssh opnsense-host uptime
```

Plain per-run environment values are also supported for non-secret settings:

```bash
guard run --env OPNSENSE_HOST=opnsense-host --secret OPNSENSE_API_KEY \
  sh -c 'ssh "$OPNSENSE_HOST" uptime'
```

## Admin authorization

Session admin RPCs (`session new` / `grant` / `revoke`, plus the privileged subset of `status`) are restricted to **the daemon's own UID** on Unix sockets. `session list` is the Unix-socket exception: exec-allowed local callers may see that grants exist, when they were granted, and when they expire, but the daemon redacts the session token, allow/deny patterns, and prompt text unless the caller is the daemon UID. On TCP transports, non-Ping admin RPCs require the separate `SSH_GUARD_ADMIN_TOKEN`; the ordinary TCP exec `SSH_GUARD_AUTH_TOKEN` is not enough to mint grants.

The non-privileged `guard status` (run as your normal user or any other exec-allowed UID, or over TCP without the admin token) returns only client + server version, uptime, evaluation mode, and dry-run state. It is a liveness probe — enough to confirm the connection works and what mode the evaluator is in, but nothing that would help fingerprint the deployment or escalate privilege.

The `--prompt` / `--prompt-file` flags attach a free-form context fragment that is appended to the LLM system prompt under a `Session context:` heading for evaluator calls made under that token. Prose grants use the same context path after static rule synthesis. Use prompt/prose for guidance the static glob patterns cannot express. The decision cache is bypassed when a session prompt is in play, because cached verdicts were made under the base prompt and may not hold under the extended context.

Because grants are now durable, broad sessions deserve the same care as any other persistent authorization state. Prefer explicit TTLs for elevated sessions, and treat `allow=["*"]` as an operator override that must be revoked intentionally rather than something a daemon restart will clear for you. Generated prose rules intentionally stay narrow; if guard cannot infer a safe static rule, it relies on LLM fallback or denies under `--static-only`.

## Execution identity

By default the daemon executes approved commands as its own service identity. If you want guard to act as a local secret broker and redactor for per-user files such as `~/.aws/config` or `~/.cmk/config`, start a root-owned daemon with `--exec-as-caller` and only a Unix socket listener. In that mode guard authenticates the caller by Unix peer credentials and drops the child process to that UID before exec, so the command runs with the caller's filesystem access instead of the daemon's or root's. TCP listeners are intentionally incompatible with this mode because a token is not a trustworthy local UID.

## Agent integration

Point your agent's command execution at `guard run` instead of direct execution.

### MCP server

Guard can run as a stdio MCP server so agents call a tool instead of shelling out:

```bash
guard config set-server ~/.guard/guard.sock
guard mcp serve
```

The server exposes a `guard_run` tool:

```json
{
  "binary": "ps",
  "args": ["aux"]
}
```

Optional per-call environment and secret references mirror `guard run`:

```json
{
  "binary": "sh",
  "args": ["-lc", "[ -n \"$OPNSENSE_APIKEY_SECRET\" ] && echo set"],
  "secrets": ["opnsense-apikey-secret"],
  "secretEnv": {
    "OPNSENSE_API_KEY": "atlas/opnsense-apikey"
  },
  "env": {
    "TARGET_HOST": "opnsense-prod"
  }
}
```

Response:

```json
{
  "allowed": true,
  "reason": "Read-only process listing",
  "exit_code": 0,
  "stdout": "USER  PID ...",
  "stderr": null
}
```

Denied commands return a normal MCP tool result with `allowed: false` and the denial reason. Transport or daemon failures still use `isError: true`.

<details>
<summary><b>Claude Code (CLAUDE.md)</b></summary>

```markdown
# Command Execution

Use the guard MCP server for all command execution.
Never use interactive sessions.
```

</details>

<details>
<summary><b>OpenHands / SWE-Agent</b></summary>

```bash
export SSH_GUARD_LLM_API_KEY="..."
export SSH_GUARD_MODE=readonly
alias ssh='guard run ssh'
```

</details>

<details>
<summary><b>LangChain / CrewAI tool definition</b></summary>

```python
import subprocess

def guarded_command(command: str, args: list[str]) -> str:
    """Execute a command through the guard."""
    result = subprocess.run(
        ["guard", "run", command] + args,
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        return f"DENIED: {result.stderr.strip()}"
    return result.stdout
```

</details>

## Security model

Guard provides defense in depth through three layers:

1. **Environment isolation** (`env_clear`): Child processes inherit only safe environment variables (`PATH`, `HOME`, `USER`, `LANG`, `TERM`, etc.) plus any per-run or tool-configured variables the caller explicitly requested.

2. **Output redaction**: Known secret values (API keys, auth tokens, tool secrets, per-run injected secrets) are exact-match redacted from stdout/stderr before returning to the agent. Regex patterns catch `*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD`, PEM blocks, and JWTs.

3. **LLM evaluation**: Each command is analyzed for destructive intent, privilege escalation, reverse shells, obfuscated payloads, tool side-channel abuse, and prompt injection. The LLM evaluates the full command including all chained parts.

## Audit logging

Guard logs all decisions via `tracing`. Configure log level with `RUST_LOG`:

```bash
RUST_LOG=info guard server start    # decisions + token usage
RUST_LOG=debug guard server start   # verbose request/response logging
```

LLM token usage is logged per evaluation:

```
[LLM_USAGE] model=openai/gpt-5.4-nano attempt=1 prompt_tokens=3594 completion_tokens=47 total_tokens=3641 status=ok
```

For this local deployment model, the audit source of truth is the daemon's structured `tracing` output, typically collected by journald. The SQLite state database is for session state and queryable session history, not for replacing your log pipeline. `guard session show` is an operator view over that persisted session history; it should complement journald, not replace it.

## Limitations

- **Not a sandbox.** Guard is a policy gate, not an isolation boundary. Defense-in-depth (seccomp, read-only FS, restricted users, network segmentation) is still needed for adversarial environments.
- **No interactive sessions.** Agents get command execution only.
- **LLM latency.** Each command adds ~0.5-2s for the LLM call.
- **Fail-closed.** If the LLM call fails or returns unparseable output, the command is denied.

## License

MIT
