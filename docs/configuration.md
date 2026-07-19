# Configuration

Guard reads daemon settings from CLI flags, `GUARD_*` environment variables,
and a `.env` file. At startup it searches from the daemon working directory
toward `/` and loads the nearest `.env` file whole; there is no per-key merging
across files, and variables already set in the process environment take
precedence over file values. Unless stated otherwise, the daemon reads a
setting at startup and a client cannot override it.

Use [`.env.example`](../.env.example) as the copyable reference. Service
deployments keep credentials in a protected environment file or secret backend,
not in command-line arguments.

## Evaluator and policy

| Variable | Default | Meaning |
|---|---|---|
| `GUARD_LLM_API_KEY` | none | Evaluator API key. `OPENROUTER_API_KEY` is also accepted. |
| `GUARD_LLM_API_URL` | OpenRouter chat completions | OpenAI-compatible evaluator endpoint. |
| `GUARD_LLM_MODEL` | `openai/gpt-5.4-mini` | Primary model. |
| `GUARD_LLM_MODELS` | unset | Comma-separated fallback chain that supersedes the single model. |
| `GUARD_LLM_RETRIES` | `2` | Transient retries per model, from 0 to 2; larger values are capped at 2. |
| `GUARD_LLM_TIMEOUT` | `30` | Per-call timeout in seconds. |
| `GUARD_MODE` | `readonly` | `readonly`, `safe`, or `paranoid`. |
| `GUARD_DRY_RUN` | `false` | Evaluate approved work without spawning it. |
| `GUARD_PROMPT_APPEND` | unset | Additive evaluator prompt path. |
| `GUARD_PREFLIGHT` | `false` | Deterministic executable and credential-disclosure checks. |
| `GUARD_ALLOW_BIN` | unset | Comma-separated hard binary floor. |
| `GUARD_GATE` | `off` | `off` or `consequence`; requires a local authenticated listener. |
| `GUARD_APPROVAL_TTL` | `3600` | Held-command lifetime in seconds, or `unbounded`. |
| `GUARD_NOTIFY_CMD` | unset | Operator command receiving one JSON gate-lifecycle event on stdin. |
| `GUARD_NOTIFY_TIMEOUT_SECS` | `10` | Notify command timeout in seconds, from 1 to 60. |
| `GUARD_VERBS` | state directory when promotion needs it | Typed verb catalog. |
| `GUARD_GRANTS` | unset | Reusable saved-grant catalog. |

`--system-prompt <path>` replaces the compiled mode prompt.
`--system-prompt-append <path>` and `GUARD_PROMPT_APPEND` add local context
without replacing the base prompt.

The append file is the operator's channel for tool knowledge the evaluator
lacks. The safe-mode prompt judges unfamiliar tools unevaluable and denies
their mutations (the readonly prompt instead leans toward allowing ambiguous
read-only work), so a host that runs in-house or niche tooling under safe mode
describes each such tool there: what its mutation surface is, which invocations
are inspection, and which argument shapes are out of bounds. Typed verbs are
the deterministic alternative for tools whose semantics should not depend on
evaluator judgment at all.

`--policy <yaml>` is an optional pre-evaluator deny path. With the evaluator
enabled, policy allow patterns do not skip evaluation. `--no-evaluator` makes
static policy the decision source. Typed verbs are the deterministic allow
interface. Legacy profile and unambiguous command-pattern inputs migrate to
saved grants and verb coverage; new authorization should use policy, verbs, and
grants.

## Endpoints and authentication

| Variable | Default | Meaning |
|---|---|---|
| `GUARD_SOCKET` | platform default | Client Unix socket path or Windows named-pipe name. |
| `GUARD_TCP_PORT` | unset | Loopback TCP port for daemon or client. |
| `GUARD_AUTH_TOKEN` | none | Execution bearer required for TCP. |
| `GUARD_ADMIN_TOKEN` | none | Separate bearer for TCP admin RPCs. |
| `GUARD_MCP_TOKEN` | none | Bearer required by HTTP MCP. |

The client endpoint order is an explicit command option, environment, saved
client configuration, then the default local endpoint. Use `guard config show`
to inspect the client selection and `guard config set-server <path>` or
`guard config set-port <port>` to change it.

A local Unix socket or Windows named pipe supplies a kernel-authenticated
principal. TCP supplies only bearer identity, so consequence gating and
per-principal secret injection are unavailable there. A TCP listener requires
an execution token; admin RPCs require the separate admin token.

`--socket-group <group>` (flag only, no environment variable) assigns the Unix
socket to a group. The daemon creates the socket as `0600` and widens it to
`0660` only after the group assignment succeeds; a failed assignment removes
the socket and aborts startup. `--users` restricts submitting uids inside the
group.

## State, cache, and behavioral limits

| Variable | Default | Meaning |
|---|---|---|
| `GUARD_STATE_DB` | XDG state directory | SQLite sessions, saved grants, requests, holds, provisionals, and history. |
| `GUARD_HISTORY_RETENTION_SECS` | `86400` | Retention for ended sessions and interactions. |
| `GUARD_CACHE` | `true` | Evaluator decision cache. |
| `GUARD_CACHE_CAPACITY` | `1024` | Maximum cached decisions. |
| `GUARD_CACHE_TTL` | `3600` | Cache lifetime in seconds. |
| `GUARD_SESSION_BEHAVIOR_WINDOW_SECS` | `300` | Rolling behavioral window. |
| `GUARD_SESSION_MAX_DENIALS` | unset | Denials that suspend a session. |
| `GUARD_SESSION_MAX_HOLDS` | unset | Holds that suspend a session. |
| `GUARD_SESSION_MAX_DENY_RATIO` | unset | Denial percentage that suspends a session. |
| `GUARD_SESSION_DENY_RATIO_MIN_COMMANDS` | `10` | Minimum sample for the ratio limit. |

Session suspension is deny-all while the triggering history remains inside the
rolling window. It does not ration evaluator calls or infer intent beyond
observable decisions and holds.

The evaluator cache is revision-aware for saved grants, sessions, verb coverage,
override markers, and policy regime. Grant edits, suspension, expiry, revocation,
or coverage changes invalidate affected authority.

## Generated coverage

| Variable | Default | Meaning |
|---|---|---|
| `GUARD_LEARN_DENY` | `true` | Promote repeated evaluator denials to deny fast paths. |
| `GUARD_LEARN_DENY_MIN_DENIALS` | `3` | Evidence required before deny promotion. |
| `GUARD_DENY_SHAPES` | state directory | Learned deny-shape file. |
| `GUARD_LEARN_ALLOW` | `true` | Promote eligible approvals to trusted verbs under consequence gating. |
| `GUARD_LEARN_ALLOW_MIN_APPROVALS` | `5` | Evidence required before verb promotion. |
| `GUARD_LEARN_ALLOW_STATE` | state directory | Allow-promotion observations. |
| `GUARD_API_VERB_COVERAGE` | `true` | Generate exact API verb coverage from evaluated traffic. |
| `GUARD_API_VERB_COVERAGE_MIN_APPROVALS` | `5` | Evidence required for API allow coverage. |
| `GUARD_API_VERB_COVERAGE_MIN_DENIALS` | `3` | Evidence required for API deny coverage. |
| `GUARD_API_VERB_COVERAGE_STATE` | state directory | Generated API coverage state. |

`guard run --reevaluate` skips only a generated deny-shape match. It never
bypasses operator-authored policy. Automatically promoted allows remain subject
to the consequence floor, regime stamps, and declared coverage boundaries.

## Child execution and secrets

| Variable | Default | Meaning |
|---|---|---|
| `GUARD_BACKEND` | automatic | `pass` (Unix only), `env`, `local`, `vault`, or `infisical`. |
| `GUARD_GPG_RECIPIENT` | none | GPG recipient for the local backend. |
| `GUARD_SERVER_UID` | daemon principal | Owner namespace for the daemon's backend `LLM_API_KEY`. |
| `GUARD_CHILD_ENV` | unset | Daemon environment names copied into approved children. |
| `GUARD_EXEC_AS_CALLER` | `false` | Unix-only identity drop to the authenticated caller. |

The child starts from a clean environment. Built-in safe variables and
operator-selected `GUARD_CHILD_ENV` values come from the daemon, not the caller.
`guard run --secret NAME` injects a stored value as an environment variable;
`--secret-file ENV=NAME` creates a daemon-only child-lifetime file and exposes
only its path. The file mode is incompatible with `--exec-as-caller`.

Caller-requested `--env`, `--secret`, and `--secret-file` bindings are part of
the evaluator subject and cache authority. Raw environment values stay out of
prompts and audit; Guard binds them with a value digest. Secret bindings expose
only environment and store names to policy, while resolved values remain inside
the daemon.

## API proxy

| Variable | Default | Meaning |
|---|---|---|
| `GUARD_API_PROXY` | unset | Single generic loopback proxy listener. |
| `GUARD_API_ENDPOINTS` | unset | YAML catalog of named concurrent listeners. |
| `GUARD_API_PROTOCOL` | `kubernetes` | `kubernetes`, `github`, or `vercel`. |
| `GUARD_API_UPSTREAM` | none | Generic upstream base URL. |
| `GUARD_API_TOKEN_ENV` | none | Daemon environment name containing the upstream bearer. |
| `GUARD_API_TOKEN_FILE` | none | Daemon-readable upstream bearer file. |
| `GUARD_API_CA_OUT` | none | Output path for the local proxy CA. |
| `GUARD_KUBE_PROXY` | unset | Kubernetes listener shorthand. |
| `GUARD_KUBE_PROXY_KUBECONFIG` | none | Daemon-owned upstream kubeconfig. |
| `GUARD_KUBE_CONTEXT` | kubeconfig current context | Upstream Kubernetes context. |
| `GUARD_API_POLICY` | none | Hot-reloaded API policy; absence is default deny. |
| `GUARD_BROKERED_KUBECONFIG_OUT` | none | Operator/bootstrap kubeconfig output; agents use `guard api kubeconfig`. |
| `GUARD_API_RARITY_ESCALATION` | `0` | Observation threshold for evaluator or hold escalation. |

API evaluator concurrency, rate, burst, error circuit, and cooldown controls use
the `GUARD_API_JUDGE_*` variables shown by `guard server start --help`.
Admission is partitioned by endpoint and session, with reserved concurrency for
attributed sessions. Rejected evaluator work fails closed.

Command handling uses `GUARD_COMMAND_MAX_CONCURRENCY` and
`GUARD_COMMAND_PRINCIPAL_CONCURRENCY`. Command evaluator admission uses
`GUARD_COMMAND_EVALUATOR_MAX_CONCURRENCY`,
`GUARD_COMMAND_EVALUATOR_PRINCIPAL_CONCURRENCY`,
`GUARD_COMMAND_EVALUATOR_RATE_PER_MINUTE`, `GUARD_COMMAND_EVALUATOR_BURST`,
`GUARD_COMMAND_EVALUATOR_ERROR_THRESHOLD`, and
`GUARD_COMMAND_EVALUATOR_CIRCUIT_COOLDOWN`. Matching `guard server start`
options override the environment. Overload, rate exhaustion, and an open error
circuit fail closed and appear in `guard status` and the audit stream.

See [API proxy](api-proxy.md) for listener and policy examples.

## Logging

`GUARD_LOG_LEVEL` sets the daemon log filter (default `warn`); a set `RUST_LOG`
takes precedence. Audit events use the dedicated `guard::audit` target and are
not gated by this filter.

## SSH host keys

`guard run --hostkey <mode>` changes only a brokered `ssh` command:

- `only-existing` preserves strict checking and is the default.
- `accept-new` trusts a new key but rejects a changed key.
- `accept-all` disables host authentication and always returns to the evaluator.

Guard injects host-key arguments before evaluation, audit, and spawn, so all
three surfaces see the same argv.
