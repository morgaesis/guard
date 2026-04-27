# Architecture

Source of truth hierarchy:

1. `src/server.rs` -- privileged guard daemon: request protocol, policy evaluation, command execution, environment isolation, and output redaction.
2. `src/evaluate.rs` -- LLM evaluator: prompt selection, OpenAI-compatible API calls, response parsing, token usage tracking.
3. `src/main.rs` -- operator-facing CLI: server start, client commands, shim management, MCP server, secret management.
4. `src/session.rs` and `src/session_store.rs` -- session grant model, retention rules, and SQLite-backed persistence for grants and session interaction history.
5. `src/mcp.rs` -- stdio MCP facade: exposes `guard_run` tool for agent clients, backed by the daemon protocol.

## Execution flow

```
Agent -> guard run <cmd> -> Client -> Server -> Evaluator -> LLM API
                                                    |
                                              Static Policy (optional)
                                                    |
                                              Execute command
                                                    |
                                              env_clear + allowlist
                                                    |
                                              Per-run/tool secret injection
                                                    |
                                              Output redaction
                                                    |
                                              Stream/output response to agent
```

## Security layers

1. **Environment isolation**: `cmd.env_clear()` strips all environment variables from child processes. Only safe variables are re-injected (`PATH`, `HOME`, `USER`, `LANG`, `TERM`, `TZ`, `SHELL`, `LOGNAME`, `XDG_RUNTIME_DIR`, `SSH_AUTH_SOCK`), followed by explicit per-run or tool-configured env/secret injections.

2. **Preflight** (optional, opt-in via `--preflight`): Two deterministic pre-LLM checks. Executable validation rejects binaries not present on the daemon `PATH`, so natural-language first tokens such as `Give` or `Please` never reach the model as prose. Credential preflight rejects known credential-disclosure patterns (private key paths, guard environment files, kubeconfig raw output, Kubernetes Secret access, token minting, process environment reads). These are coarse by design and can over-match (e.g. they block any command containing the `env` token). Enable on hosts where LLM cost or latency dominates over false positives; leave off where the LLM is the authoritative decision maker.

   Invariant checks still run regardless of `--preflight`: binary names containing `/`, `..`, or NUL are rejected, and recursion depth is capped.

3. **Output redaction**: Known secret values (API key, auth token, tool-injected secrets, per-run injected secrets) are exact-match redacted from stdout/stderr. Regex patterns catch common secret formats (`*_TOKEN=`, `*_KEY=`, PEM blocks, JWTs, `sk-*` strings).

4. **LLM evaluation**: Commands are sent to an LLM with a mode-specific system prompt. The LLM analyzes intent, chained operations, obfuscation, tool side-channels, and prompt injection attempts. Returns `APPROVE`/`DENY` with risk score.

5. **Decision cache**: An in-memory LRU-style cache of evaluator decisions, keyed on the exact command line. Cache hits return the stored `Allow`/`Deny` without another LLM call. The cache is owned by a single `Evaluator` instance, so restarting the daemon or changing the prompt gives a fresh cache. Both approve and deny decisions are cached; transient evaluator errors are not. Size and TTL are configurable (`--cache-capacity`, `--cache-ttl`, `SSH_GUARD_CACHE_*`); disable with `--no-cache` / `SSH_GUARD_CACHE=false`.

6. **Session grants** (optional, opt-in per request): The caller may include a `session_token` in `ExecuteRequest`. Operators grant sessions extra allow/deny glob patterns via the admin protocol (`guard session grant`). Matching session deny patterns short-circuit to DENY before the evaluator. Matching session allow patterns short-circuit to ALLOW and skip the evaluator. A grant may also carry an additive prompt (`--prompt` / `--prompt-file`) that the evaluator appends to the system prompt for that session's calls, giving the LLM context the static glob patterns cannot express; the decision cache is bypassed for these calls so cached base-prompt verdicts do not leak across the extended context. Non-matching sessions fall through to the evaluator so the usual rules still apply. Grants, historical grant transitions, and bounded interaction history are persisted in the state database, so `session list` and `session show` survive daemon restart. Session history retention remains bounded; older interactions and expired history are purged opportunistically on write and read paths.

7. **Static policy** (optional, opt-in): Glob-pattern allow and deny lists for fast decisions on deterministically safe or unsafe commands. Allow matches skip the LLM; deny matches reject without an LLM call. Everything else falls through to the LLM evaluator. Disabled by default. Documented limitation: static patterns cannot parse shell operators, quoting, or semantics. See `examples/` for reference policies.

## Admin authorization

Admin RPCs (session grant/revoke/show/list and the full `status` snapshot) are gated separately from exec. Without this separation, an exec-allowed UID could mint a session whose `--prompt` overrides the LLM policy. The model is intentionally simple:

- **Admin = the daemon's own UID.** That process can already control the daemon by signals, /proc, or restarting the service. The socket boundary adds nothing against it.
- **There is no client-side admin token.** A token-based path would have to live somewhere — env var, config file — and any agent process running as the same user could read it. The admin/agent split is enforced by UID separation only.

The non-privileged `Ping` admin RPC is always permitted to UIDs that can already exec, and returns version, uptime, mode, and dry-run state. That is enough for a `guard status` liveness check without fingerprinting the deployment (no LLM model identity, no redaction posture, no session counts). The privileged `Status` RPC additionally reveals the resolved state database path so the daemon owner can inspect where durable session state is stored.

## Execution authority

The server executes approved commands as the daemon process identity by
default. It authenticates local clients by peer UID (`--users`) but only
impersonates that UID when explicitly started with `--exec-as-caller`. That
mode requires a root daemon and a Unix-socket-only deployment; the server uses
peer credentials to identify the caller, resolves the caller's passwd entry,
initializes supplementary groups, and drops the child process to that UID/GID
before exec. An unprivileged, hardened service is a policy gate and secret
broker for commands that service identity can already run. A root service
without `--exec-as-caller` is a privileged command broker: approved local
commands run with root authority, similar to a sudo policy boundary.

Systemd hardening changes what approved commands can do. In particular,
`NoNewPrivileges=true` prevents setuid helpers such as `sudo` from elevating,
and user-service sandboxing may place the daemon in a user namespace where
root-owned files appear unmapped. Operators who need sudo-like local execution
must choose a privileged system-service deployment deliberately and compensate
with strict caller restrictions, environment isolation, output redaction, and
audit logging.

## Prompt architecture

System prompts live in `config/*.md` files and are compiled into the binary via `include_str!()`. Three prompts ship by default:

- `config/system-prompt-readonly.md` -- read-only inspection mode
- `config/system-prompt-safe.md` -- permissive administrative mode
- `config/system-prompt-paranoid.md` -- restrictive paranoid mode

Override priority: `--system-prompt` flag > `~/.config/guard/system-prompt.txt` > mode-specific compiled prompt.

Additive prompts (`--system-prompt-append` or `SSH_GUARD_PROMPT_APPEND`) append text to whichever base prompt is active, letting operators customize behavior without maintaining a prompt fork.

The default evaluator is a single LLM call per command with bounded retries before failing closed. A multi-model fallback chain (`SSH_GUARD_LLM_MODELS`) is available as an opt-in for deployments that need to survive provider-specific outages; when unset, guard uses a single model with retries. See `examples/fallback-models.env`.

Dry-run mode (`--dry-run` or `SSH_GUARD_DRY_RUN=true`) keeps the same evaluator
and audit path but stops after an allow decision. Approved commands return a
successful dry-run response and are not spawned. Denied commands behave the same
as normal mode.

The daemon protocol has two response modes. Non-streaming clients receive a
single JSON response after the approved command exits. `guard run` and
`guard server connect` opt into streaming mode, where stdout/stderr line events
are redacted server-side and sent as they arrive, followed by a final result
message carrying the policy reason and exit code.

Execution requests carry `binary`, `args`, optional session token, optional
plain env injections, and optional secret env mappings. Secret values are never
sent by execution clients; the daemon resolves them from its configured secret
backend immediately before exec. Before the LLM or static policy runs, the
daemon rejects malformed injected env names, invalid secret keys, missing
secret references, and shell references that point at the secret key instead of
the injected env var. Secret management (`guard secrets add/list/remove`) is
also daemon-side via admin RPCs, so the client does not select or write a
secret backend. Requests do not carry the client's current working directory as
structured metadata. Relative paths therefore resolve in the daemon process
working directory when a command is actually executed, and the evaluator only
sees the relative path text supplied in the command.

## Design constraints

- Policy evaluation and command execution exist in one place (the server). New agent integrations wrap the daemon rather than reimplementing approval logic.
- Audit truth lives in the daemon's structured `tracing` output. The SQLite state database exists for persistent session state and queryable session history, not as a replacement for journald or remote log shipping.
- MCP transport is stdio only. Network MCP transport adds a second auth surface and should be introduced only with a clear deployment requirement.
- Tool responses preserve both raw command output and structured fields so clients can use either text-only or schema-aware handling.
- The guard binary name is `guard`. Environment variables retain the `SSH_GUARD_*` prefix for backwards compatibility.
