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

Guard sits between the agent and the shell. Every command gets evaluated by an LLM (`openai/gpt-5.4-mini` via OpenRouter by default) before it reaches the system. The LLM analyzes intent and risk, not just pattern matching, so it catches obfuscated attacks and novel command chains that static policies miss.

Cost is negligible: each evaluation uses roughly 3600 prompt + 45 completion tokens, costing about $0.0005 per decision with `openai/gpt-5.4-mini`. A full 45-case CTF adversarial benchmark runs for about $0.02 total.

## Install

```bash
cargo install --path .
```

Or download a release artifact and install the binary manually.

See [INSTALL.md](INSTALL.md) for install options and [DEPLOYMENT.md](DEPLOYMENT.md) for service deployment.

## Quick start

```bash
# Set your API key (OpenRouter, or any OpenAI-compatible endpoint)
export GUARD_LLM_API_KEY="your-key-here"

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

Set via `GUARD_MODE`:

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

The policy mode is a daemon-side setting: the server reads `GUARD_MODE` once at
startup, and the execute request carries no mode. Setting `GUARD_MODE` in the
client's environment has no effect. Set the mode where the server starts:

```bash
# With a daemon started as:
GUARD_MODE=safe guard server start &
guard run sudo systemctl status ssh --no-pager   # allowed

# With a daemon started as:
GUARD_MODE=paranoid guard server start &
guard run sudo systemctl status ssh --no-pager   # denied
```

All modes evaluate `sudo` by the underlying command:

```bash
guard run sudo ls /etc/nginx/        # readonly: allowed (read operation)
guard run sudo rm -rf /etc/nginx/    # readonly: denied  (destructive)
guard run sudo systemctl restart app # safe: allowed     (targeted restart)
```

## Consequence-gated execution

By default an approved command runs immediately. That is one gate for every
action, regardless of whether the action is a read, a reversible change, or an
irreversible destruction. Consequence gating (opt-in, `--gate consequence`) makes
the gate depend on the *consequence* of the command, turning the binary
allow/deny into a graduated trust ladder:

| class | when | gate |
|---|---|---|
| `reversible` | read-only / idempotent / trivially undone, low risk | runs immediately |
| `recoverable` | a mutation with a known inverse | runs behind an **auto-revert envelope**: applied, then reverted unless an operator confirms in time |
| `irreversible` | destruction or no clean inverse (or high risk, or uncertain) | **held for operator approval**; not executed until approved |

With gating on, the LLM keeps deciding APPROVE/DENY exactly as before (the deny
rules are unchanged) and additionally classifies the reversibility of commands it
approves. The daemon routes on that class. Classification is **fail-safe**:
reversibility can only *raise* the gate, never lower it, and a missing or
uncertain class is held, never run. LLM approvals route on the evaluator's
class, trusted verbs route on their declared class, and session allows without a
matched verb are unclassified and held. Static policy in the `--no-llm` fallback
mode is the deterministic direct-exec path.

Gating is meaningful only where the daemon's principal differs from the agent's
(so the agent cannot approve its own held command). The principal is a Unix uid
over a Unix-domain socket and a Windows SID over a named pipe; either way it is a
kernel-verified local peer, so gating works on both platforms. It requires a
local listener (`--socket`) and is refused with a TCP listener, which carries
only a bearer token and no peer identity. Approval, denial, confirmation, and
manual revert are restricted to **the daemon's own principal** - the operator
decides the irreversible steps, never the agent.

```bash
guard server start --gate consequence --exec-as-caller \
  --socket /run/guard/guard.sock --verbs /etc/guard/verbs.yaml

# Reversible: runs now.
guard run ls -la /etc/nginx/

# Recoverable: executes inside an auto-revert envelope.
guard run --revert "systemctl stop app" --confirm-within 900 \
  systemctl restart app
# PROVISIONAL containment envelope: ... handle: 3f9c...
# result: executed, auto-reverts unless confirmed
#   confirm: guard confirm 3f9c...   (else auto-reverts)
guard confirm 3f9c...     # operator: keep it

# Irreversible: held for operator approval, not executed.
guard run rm -rf /var/data
# HELD for daemon-principal approval: ... handle: a1b2...
# result: not executed until approved
#   approve: guard approve a1b2...
guard approvals                 # operator: review the queue
guard approve a1b2...           # operator: execute the exact held command
guard deny a1b2...              # operator: reject it
```

A free-form `--revert` is assessed by the evaluator at arm time, with the forward
command as context, for both policy compliance and whether it is a sensible
inverse of the forward action. The daemon may run it unattended, so it is gated
as the consequential action it is. Only an explicit approval arms the envelope;
any other verdict escalates the command to operator review (it is held, not armed
with an unverified rollback and not silently denied), so an agent cannot smuggle
an arbitrary or off-target command into the rollback slot. An operator-authored
verb revert is the slow clock and is not re-evaluated. A recoverable command with
no usable revert is held, not run unconfined. Held commands fail closed: an
unattended queue denies on a TTL rather than stalling. Held and provisional state
survives a daemon restart, and a revert never runs unattended at boot. A
past-deadline provisional becomes `needs_operator_decision` for explicit
handling. `DENIED` means the command did not execute. Evaluator errors, invalid
revert commands, missing approval snapshots, and unsafe replay checks fail closed
and return an explicit denial or hold reason. Inspect state with `guard
provisionals` and `guard approvals`.

### Verbs: the typed interface

`guard run <anything>` is a single, all-powerful entry point. For high-value
operations, expose **verbs** instead: named, typed operations the operator
defines in a catalog (`--verbs <yaml>`), each with a fixed binary, an argument
template with pattern-validated parameters, a declared consequence class, and a
rollback. The agent calls the verb; it never composes raw shell.

```bash
guard verb list
# restart-service [recoverable] trusted revertable - Restart a systemd unit
#     --param unit=<^[a-zA-Z0-9@._-]+$>

guard verb run restart-service --param unit=nginx
```

Each `{param}` renders as exactly one argument (no shell, no word-splitting), and
a value may not begin with `-` unless the parameter opts in, so parameter and
flag injection are structurally impossible. The catalog is operator-only and
hot-reloaded on change; agents cannot add or alter verbs. A `trusted` verb skips
the LLM (a deterministic allow path); its declared class still drives the gate.
See [`examples/verbs.yaml`](examples/verbs.yaml).

#### Generating a verb from prose

Hand-writing verb YAML is optional. `guard verb create --prompt "<description>"`
asks the daemon's evaluator LLM to synthesize one typed verb from a plain-language
description, validates it exactly like a hand-authored verb, and appends it to the
catalog with the original prose and a short rationale recorded inline
(`source_prose`, `evidence`). Use `--preview` to see the synthesized verb without
writing it, and `--binary <name>` to hint the target tool.

```bash
guard verb create --binary cmk --prompt \
  "read-only: list CloudStack VMs for the atlas-debug profile, only the VM with id <uuid>"
```

Creating a verb is operator-only (it mutates the catalog). The synthesis is held
to a safety gate the model cannot talk its way past: a synthesized verb is never
`trusted` (so the LLM still evaluates the rendered command at run time), its binary
may not be a shell or interpreter, its parameter patterns may not admit whitespace
or shell metacharacters, and its name must be kebab-case. This lets an operator add
narrow, least-privilege verbs - including per-resource limits a tool's own RBAC
cannot express - without writing YAML by hand.

A caller does not have to name a verb to benefit from one: a raw command
(`guard run kubectl get pods -n foo`) reverse-matches any catalog verb whose
template it satisfies, hand-authored or auto-promoted, picking up its class
and trust the same way `guard verb run` would.

#### Auto-verb-promotion

`--learn-allow` (on by default, requires `--gate consequence`) is the
allow-side counterpart to `GUARD_LEARN_DENY`, for deployments too unattended
for an operator to act on learned-rule notices. Repeated low-risk approvals of
the same command shape are appended to the catalog automatically as a
`trusted` verb - restricted to reversible shapes, or recoverable shapes with a
validated revert; irreversible shapes are never eligible, since they hold for
operator approval regardless of `trusted`. Every parameter's allowed values
are pinned to the exact values actually observed, never a model-authored
pattern. `guard verb list` shows what has been promoted (`auto_promoted: true`);
edit or delete the catalog file to revoke. See [DEPLOYMENT.md](DEPLOYMENT.md#auto-verb-promotion)
for the full design rationale.

## API proxy

The command gate sees a command's argv, but tools that drive an HTTP API
in-process never spawn a gated command: `helm upgrade` renders templates locally
then performs many create/update/delete calls against the apiserver via client-go,
and terraform providers, k9s, client libraries, and SDK calls are the same. The
gate sees one opaque invocation.

`--api-proxy` moves the gate to the API boundary. The daemon fronts the upstream
API with a TLS-terminating proxy, parses each request into a typed operation
through a protocol plug-in, matches it against an operator policy, and
re-originates allowed requests to the real upstream with the credentials only
the daemon holds. Kubernetes is the reference protocol (`--kube-proxy ADDR` is
shorthand for it); GitHub and Vercel ship as example protocols:

```bash
# Kubernetes: credentials come from the operator kubeconfig.
guard server start --gate consequence --socket /run/guard/guard.sock \
    --kube-proxy 127.0.0.1:8443 \
    --kubeconfig /etc/guard/kubeconfig \
    --api-policy /etc/guard/api-policy.yaml \
    --brokered-kubeconfig-out /run/guard/brokered.kubeconfig

# The agent uses the brokered config, which carries no credential:
KUBECONFIG=/run/guard/brokered.kubeconfig helm upgrade --install app ./chart

# GitHub: the daemon reads the token from its own environment; the agent
# talks to the proxy and never sees it.
guard server start --gate consequence --socket /run/guard/guard.sock \
    --api-proxy 127.0.0.1:8444 --api-protocol github \
    --api-upstream https://api.github.com \
    --api-token-env GH_BROKER_TOKEN \
    --api-policy /etc/guard/github-policy.yaml \
    --api-ca-out /run/guard/api-proxy-ca.pem
```

For Kubernetes the daemon reads the real bearer token or client certificate from
its kubeconfig (`exec`/`auth-provider` plugins are rejected) and emits a brokered
kubeconfig that points only at the proxy and is validated to carry no credential,
so the proxy is the sole path to the cluster. For other protocols the bearer
token comes from an environment variable (`--api-token-env`) or a file
(`--api-token-file`), never a command-line value, and `--api-ca-out` writes the
proxy CA so generic HTTP clients can trust the TLS termination. `--api-proxy`
refuses to start with `--exec-as-caller` and binds loopback addresses only, since
the proxy authenticates nothing itself. Policy actions are `allow`, `deny`,
`hold`, and `evaluate`; an allowed read of secret-bearing material is redacted
by the protocol's own classification (Kubernetes Secret `data`/`stringData`,
GitHub secret stores, Vercel env-var values), something upstream admission
control cannot do. A `hold` parks the request in the same operator queue as held
commands: the client blocks while `guard approvals` shows the operation, `guard
approve` releases it, and `guard deny` or TTL expiry fails it closed (holds
require `--gate consequence`; without it they deny). An `evaluate` rule (or
`default: evaluate`) sends the request to the LLM evaluator, which judges it
against the policy's `intent` prose using a redacted summary of the operation
(body values never leave the proxy, only a key skeleton) and whether an
auto-revert is constructible for it: a constructible revert can make a
borderline recoverable operation approvable, and the verdict still routes
through the deterministic consequence gate, so recoverable verdicts forward
only inside the auto-revert envelope and irreversible or uncertain ones are
held. A policy that routes to `evaluate` without a configured LLM holds those
requests fail-closed. Uninspectable streams are denied outright per protocol:
Kubernetes `exec`/`attach`/`portforward`/`proxy` and `pods/ephemeralcontainers`
(they tunnel code execution or an arbitrary request into a running workload),
Secret `watch`es, GitHub repository archives, Vercel deployment log streams.
Under `--gate consequence`, a recoverable write is wrapped in the auto-revert
envelope: the proxy snapshots the prior object and plans a plain HTTP revert
(restore the prior object, delete the created one, or recreate a faithfully
snapshottable deleted one), armed in the provisional registry; `guard confirm`
keeps the change and the sweeper otherwise executes the revert through the
proxy's own upstream credential. `--api-rarity-escalation N` fails a broad allow
rule toward scrutiny on a rare or first-seen shape (verb, resource, and
namespace, ignoring the object name) that has been seen fewer than N times this
run: with the evaluator attached the rare request is judged rather than
fast-pathed, and otherwise it is held for the operator. See
[`examples/api-policy.yaml`](examples/api-policy.yaml),
[`examples/github-policy.yaml`](examples/github-policy.yaml), and
[`examples/vercel-policy.yaml`](examples/vercel-policy.yaml).

API request-shape learning is evidence-only and exact-tuple based: repeated
evaluator allows or denies for the same `(protocol, verb, group, version,
resource, subresource, namespace, body-shape)` tuple, with the object name
excluded and the body reduced to a value-free key skeleton, populate a bounded
YAML store, so a learned rule matches only requests structurally identical to
the ones the evaluator judged. Dry-run requests never feed it, an over-risk or
irreversible allow permanently disqualifies its shape, and each learned verdict
is invalidated when the evaluator model or the policy intent changes. Learned
denies reject the same tuple before another evaluator call; learned allows reuse
the stored risk and reversibility, skip only non-rare requests, and still route
through `decide_gate`, so the consequence floor is unchanged. Promotion and
fast-path hits are operator-audit-only, and a learned deny reads to the client
exactly like a fresh evaluator denial. Command denials may include the caller's
own repeated-denial count once the deny-shape
threshold is reached, but clients never receive promotion state or a signal
that an API shape skipped evaluation.

## Configuration

### Defaults vs. opt-ins

Guard ships with an LLM-only evaluation pipeline: a single call to
`openai/gpt-5.4-mini` via OpenRouter, function-calling based, with two retries
before failing closed. No static allow or deny lists are loaded. No fallback
model chain is active. This default is production-ready for the common case.

Two opt-in features exist for deployments with specific constraints:

- **Static deny list** via `--policy <yaml>`. Fast-rejects deterministically
  unsafe patterns before the LLM is called. See
  [`examples/`](examples/README.md) for `deny-policy.yaml` and
  `hybrid-policy.yaml`. `commands.allow` is also parsed (for the
  `--no-llm` fallback mode and backward compatibility) but, while the LLM is
  enabled, an allow pattern never skips it. Static and session policy patterns
  are shell-style globs over a flat reconstructed command line. They remain for
  compatibility, while typed verbs are the structured path: verb parameters are
  anchored regexes rendered as single argv elements, and reverse matching lets
  normal tool invocations pick up a verb's consequence class. Use `guard verb`
  for a deterministic, LLM-skipping allow.
- **Fallback model chain** via `GUARD_LLM_MODELS`. Fails over to
  alternate providers after the primary exhausts its retries. See
  [`examples/fallback-models.env`](examples/fallback-models.env).
- **Learned-rule candidates** via `--learn-rules`. Repeated low-risk LLM
  approvals surface as a candidate in the policy reason text, with a
  ready-to-run `guard verb create --prompt` suggestion. Candidates do not
  grant themselves a bypass. Only an operator running that command can,
  through the same synthesis safety gate as any other verb.

Enable either only when a concrete latency or uptime constraint forces it.

### Environment variables

All configuration via environment variables, CLI flags, or `.env` files.

Guard walks up from your current directory to `/` looking for `.env` files (closest wins), so you can scope config per project.

Unless marked "(client)", a variable is read by the daemon at startup; setting it in a client's environment has no effect.

| Variable | Default | Description |
|---|---|---|
| `GUARD_LLM_API_KEY` / `OPENROUTER_API_KEY` | (none) | LLM API key (required). `OPENROUTER_API_KEY` is the conventional name and is accepted for compatibility. |
| `GUARD_LLM_API_URL` | `https://openrouter.ai/api/v1/chat/completions` | Any OpenAI-compatible endpoint |
| `GUARD_LLM_MODEL` | `openai/gpt-5.4-mini` | Primary evaluation model. `--llm-model` takes precedence; a non-empty `GUARD_LLM_MODELS` chain supersedes both. |
| `GUARD_LLM_MODELS` | (unset) | Optional comma-separated fallback chain (e.g. `openai/gpt-5.4-mini,meta-llama/llama-4-maverick`). When set, overrides `--llm-model` and is tried in order, each with its own retry budget. Primary model when unset: `openai/gpt-5.4-mini`. |
| `GUARD_LLM_RETRIES` | `2` | Retries per model on transient failures (429, timeouts, parse errors). 1-2. |
| `GUARD_LLM_TIMEOUT` | `30` | LLM call timeout in seconds. |
| `GUARD_AUTH_TOKEN` | (none) | Shared token for TCP clients. Use this for loopback TCP daemons instead of passing `--auth-token` on the command line. |
| `GUARD_ADMIN_TOKEN` | (none) | Separate token for TCP admin RPCs such as `guard grant`, session mutation, detailed secret ownership inspection, and the full `guard status`. The Windows launcher generates and stores one automatically. |
| `GUARD_TCP_PORT` | (none) | Daemon: TCP listen port on 127.0.0.1 (same as `--tcp-port`). Client: endpoint override, connect to 127.0.0.1:`<port>` instead of a socket. |
| `GUARD_SOCKET` | (none) | (client) Endpoint override: Unix-domain socket path (Unix) or named-pipe name (Windows) to connect to. |
| `GUARD_MODE` | `readonly` | `readonly`, `safe`, or `paranoid` |
| `GUARD_DRY_RUN` | `false` | Evaluate policy but do not execute approved commands. Useful for prompt and policy testing. |
| `GUARD_LEARN_RULES` | `false` | Learn static allows from repeated low-risk LLM approvals. |
| `GUARD_LEARNED_RULES` | `<state dir>/learned-rules.yaml` | Path to the learned static rules YAML (used with `GUARD_LEARN_RULES`). |
| `GUARD_LEARN_MIN_APPROVALS` | `2` | Approvals required before promotion. |
| `GUARD_LEARN_MAX_RISK` | `2` | Highest LLM risk score eligible for promotion. |
| `GUARD_LEARN_SHIMS` | `suggest` | `off`, `suggest`, or `create` service shims for learned SSH/API wrappers. |
| `GUARD_LEARN_DENY` | `true` | Auto-learn deny shapes from repeated LLM denials and fast-reject matching commands without another LLM call. On by default -- unlike `GUARD_LEARN_RULES`, this never grants anything, so it needs no operator promotion step. |
| `GUARD_DENY_SHAPES` | `<state dir>/learned-deny.yaml` | Path to the auto-learned deny-shape state YAML. |
| `GUARD_LEARN_DENY_MIN_DENIALS` | `3` | LLM denials of the same shape required before attempting to synthesize an auto-learned deny fast path. |
| `GUARD_LEARN_ALLOW` | `true` | Auto-promote trusted verbs from repeated low-risk LLM approvals (requires `--gate consequence`). On by default; needs no operator step, unlike `GUARD_LEARN_RULES` -- restricted to reversible/recoverable-with-a-validated-revert shapes, never irreversible. |
| `GUARD_LEARN_ALLOW_STATE` | `<state dir>/learned-allow.yaml` | Path to the auto-verb-promotion observation state YAML (bookkeeping only; promoted verbs land in `GUARD_VERBS`). |
| `GUARD_LEARN_ALLOW_MIN_APPROVALS` | `5` | LLM approvals of the same shape required before attempting to promote a trusted verb. |
| `GUARD_API_PROMOTION` | `true` | Auto-learn exact API request shapes from repeated evaluator allows and denies on proxied `evaluate` traffic. |
| `GUARD_API_PROMOTION_STATE` | `<state dir>/learned-api.yaml` | Path to the API request-shape learning state YAML. |
| `GUARD_API_PROMOTION_MIN_APPROVALS` | `5` | Evaluator approvals of the same API tuple required before a learned allow is active. |
| `GUARD_API_PROMOTION_MIN_DENIALS` | `3` | Evaluator denials of the same API tuple required before a learned deny is active. |
| `GUARD_PROMPT_APPEND` | (none) | Path to additive prompt file (appended to base prompt) |
| `GUARD_GPG_RECIPIENT` | (none) | GPG recipient for the `local` secret backend |
| `GUARD_BACKEND` | (auto) | Secret backend: `pass`, `env`, `local`, `vault`, or `infisical`. Auto prefers `pass`; otherwise it falls back to non-persistent `env` and logs a warning. `vault` uses `VAULT_ADDR` with `VAULT_TOKEN` or `VAULT_ROLE_ID`+`VAULT_SECRET_ID` (KV v2, mount `VAULT_KV_MOUNT`, default `secret`); `infisical` uses `INFISICAL_CLIENT_ID`/`INFISICAL_CLIENT_SECRET`/`INFISICAL_PROJECT_ID` (Universal Auth, env `INFISICAL_ENVIRONMENT`). |
| `GUARD_SERVER_UID` | (daemon principal) | Owner principal the daemon reads its own `LLM_API_KEY` secret under when no key is supplied by flag or env. Lets the daemon source its key from the configured backend instead of an external `vault agent` / `infisical run` wrapper. |
| `GUARD_ALLOW_BIN` | (none) | Comma-separated binary allow-list. When set, only these binaries may execute, on every route, regardless of the LLM decision. Bare names match by command name via the daemon PATH; path-qualified entries must match exactly. |
| `GUARD_GATE` | `off` | Consequence gating: `off` or `consequence`. Requires a local listener (`--socket`: a Unix-domain socket on Unix, a named pipe on Windows); refused over TCP. |
| `GUARD_VERBS` | (none) | Path to the verb catalog YAML. Hot-reloaded on change. |
| `GUARD_PROFILES` | (none) | Path to the session-profile YAML (named `{ttl, allow, deny, prompt}` bundles for `guard session new --profile <name>`; see `examples/session-profiles.yaml`). |
| `GUARD_PREFLIGHT` | `false` | Deterministic pre-LLM checks: reject binaries not on the daemon `PATH` and known credential-disclosure patterns before any LLM call. Coarse by design; enable where LLM cost/latency dominates over false positives. Flag: `--preflight`. |
| `GUARD_CACHE` | `true` | In-memory cache of LLM decisions keyed on the exact command line. Disable with `--no-cache` or `GUARD_CACHE=false`. |
| `GUARD_CACHE_CAPACITY` | `1024` | Maximum cached decisions (`--cache-capacity`). |
| `GUARD_CACHE_TTL` | `3600` | Cache entry TTL in seconds (`--cache-ttl`). |
| `GUARD_STATE_DB` | XDG state dir | Path to the SQLite state database (sessions, holds, provisionals, read grants). |
| `GUARD_HISTORY_RETENTION_SECS` | `86400` | Retention window for ended grants and session interactions. Flag: `--history-retention`. Scheduled maintenance prunes expired rows and compacts the database after substantial free space accumulates. |
| `GUARD_CHILD_ENV` | (none) | Comma-separated daemon env vars forwarded to brokered children (e.g. a `KUBECONFIG` only the daemon can read). Values come from the daemon's environment, never the caller's. |
| `GUARD_EXEC_AS_CALLER` | `false` | Run brokered children as the calling uid instead of the daemon account (Unix). |
| `GUARD_API_PROXY` | (none) | API proxy listen address (loopback only); see the API proxy section. Companions: `GUARD_API_PROTOCOL`, `GUARD_API_UPSTREAM`, `GUARD_API_TOKEN_ENV`, `GUARD_API_TOKEN_FILE`, `GUARD_API_CA_OUT`, `GUARD_API_POLICY`. |
| `GUARD_KUBE_PROXY` | (none) | Kubernetes API proxy listen address, shorthand for the kubernetes protocol. Companions: `GUARD_KUBE_PROXY_KUBECONFIG`, `GUARD_KUBE_CONTEXT`, `GUARD_API_POLICY`, `GUARD_BROKERED_KUBECONFIG_OUT`. |
| `GUARD_API_RARITY_ESCALATION` | `0` | Escalate a policy-allowed proxy request whose shape (verb x resource x namespace) has been seen fewer than N times this run: to the evaluator when one is attached, otherwise to the operator hold queue. 0 disables it; requires `--gate consequence`. Flag: `--api-rarity-escalation`. |
| `GUARD_LOG_LEVEL` | `warn` | Log level (`error`, `warn`, `info`, `debug`, `trace`) when `RUST_LOG` is unset. Read by every guard process, daemon and client alike. |
| `GUARD_MCP_TOKEN` | (none) | (client) Bearer token required by the HTTP MCP transport (`guard mcp serve --http`); `--http-token` overrides it. |

The primary model is `openai/gpt-5.4-mini` via OpenRouter by default. Set it
per-invocation with `--llm-model <slug>`. To configure a true fallback chain
across providers, use `GUARD_LLM_MODELS` (comma-separated) or
`--llm-models`. `--llm-timeout <seconds>` controls the per-call HTTP timeout.

See [`.env.example`](.env.example) for a copyable template.

### Endpoint resolution

The client resolves the daemon endpoint in order: the `--socket` flag, then the
`GUARD_TCP_PORT` and `GUARD_SOCKET` environment variables, then the client
config (`~/.config/guard/client.yaml`, written by `guard config set-server` /
`set-port`), then a default socket: `/run/guard/guard.sock` when it exists (the
systemd layout), otherwise `~/.guard/guard.sock`.

The daemon shares part of that chain: started without `--socket`, it reads
`server_socket` from the same client config and binds there when set, otherwise
it binds `~/.guard/guard.sock`. `guard config set-server` therefore points the
client and any flagless daemon on the same host at the same endpoint, and a bare
`guard server start` followed by `guard run ...` works with no configuration.

### SSH host keys

`guard run --hostkey <mode>` controls how a brokered `ssh` treats the remote
host key. `only-existing` (default) injects nothing, preserving ssh's own
configured behavior. `accept-new` injects `StrictHostKeyChecking=accept-new`
and `UpdateHostKeys=yes` for first-contact key learning while still refusing
a changed key. `accept-all` injects `StrictHostKeyChecking=no` with a null
known-hosts file, giving up host authentication entirely; it exists for
disposable lab targets and never rides any deterministic fast path, so the
evaluator always sees it. Injected options are folded into the argv before
policy evaluation, so the decision, the audit record, and the spawned
process all see the same command.

## Examples

### Basic server with readonly mode

Start the guard server and execute commands through it:

```bash
export GUARD_LLM_API_KEY="sk-or-v1-..."

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
GUARD_MODE=safe guard server start --socket .cache/guard.sock &

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
GUARD_MODE=paranoid guard server start --socket .cache/guard.sock &

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

### Command access summary

`guard help-tree` prints a categorized access summary. The user section covers
execution, liveness, per-user secret add/remove/list, redacted session reads,
known-token session show, token-only session minting, verb use, and local hold
inspection. The local setup section covers client-side shim and config files.
`guard help-tree --admin` adds daemon-principal and TCP admin-token commands
such as session grant/revoke/appeal, grant-installing session creation, gate
decisions, detailed secret ownership inspection, verb creation, and full daemon
status.

`guard shim ssh,kubectl,helm,ansible,ansible-playbook` installs generic command
wrappers that call `guard run <tool> "$@"`. The wrappers preserve argv and the
client cwd; the daemon canonicalizes that cwd, includes it in evaluation and
audit, and executes approved commands there. Shims are convenience entry points,
not separate policy commands. Tools such as Ansible discover `ansible.cfg` and
inventory from that cwd. Guard does not inherit caller credential/configuration
environment such as `SSH_AUTH_SOCK` or `ANSIBLE_CONFIG`; use cwd discovery or an
explicit approved argv flag such as `-i`/`--inventory` for a non-default path.
A broker-owned socket can be supplied through Guard tool configuration or daemon
`--child-env SSH_AUTH_SOCK`; caller `--env SSH_AUTH_SOCK=...` is rejected.

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

When the LLM repeatedly approves the same low-risk command shape, guard
records the observation to the state directory; once it crosses
`--learn-min-approvals`, the policy reason returned to the caller includes a
candidate notice with a ready-to-run `guard verb create --prompt "..."`
command. Crossing the threshold does NOT bypass the LLM by itself -- every
future identical call is still evaluated normally, because granting that
bypass automatically would let an agent promote itself past the evaluator
just by repeating a borderline command. Only an operator running the
suggested `guard verb create` command (or hand-authoring a verb) can turn a
candidate into an actual LLM-skipping allow, through the same synthesis
safety gate as any other verb. For SSH API wrappers, guard may also mention a
shorter service shim such as `opnsense-api`; with `--learn-shims create`, a
candidate creates that wrapper in the configured shim directory (a command
alias, not a bypass -- it still runs through normal evaluation) once it
reaches the approval threshold.

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
GUARD_PROMPT_APPEND=/etc/guard/extra-rules.txt guard server start &
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

Session grants hand a specific agent narrow extra permissions for a specific run, without relaxing the global mode. The agent identifies its session by the `GUARD_SESSION` env var; every `guard run` (and `guard server connect`) reads that env var and forwards it as the session token in the request. Operators can attach legacy allow/deny patterns, prose intent, and optional evaluator context to that token. The token is a bearer credential; treat it like access to the scoped session itself.

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

Inside the agent's process tree, every `guard run` call automatically picks up `GUARD_SESSION` from the inherited environment, so the model itself does not need to know or pass the token explicitly. The scope is bound to the shell that launched the agent.

To grant rules to an existing token (e.g. one the agent already has):

```bash
guard session grant <token> --allow '<glob>' --deny '<glob>' [--ttl N] [--prompt TEXT] [--auto-amend]
```

There is also a top-level shorthand. With a quoted prose description it mints and
grants a fresh session, again printing an eval-friendly export line:

```bash
eval "$(guard grant --ttl 3600 --static-only 'readonly access to grafana resources in the staging kube cluster, not secrets, with write access for scaling replicas and editing ingresses')"
```

For an existing token, pass the token first:

```bash
guard grant <token> "readonly access to grafana resources in the staging kube cluster, not secrets, with write access for scaling replicas and editing ingresses"
```

Prose grants are compiled at grant time into conservative static rules when guard recognizes the domain. The first compiler handles Kubernetes: it infers namespaces such as `grafana`, optional contexts such as `staging`, adds hard denies for shell-control, secret access, token creation, raw kubeconfig reads, `exec`, `cp`, `port-forward`, and deletes, then adds namespace-scoped read, scale, and ingress/reverse-proxy rules implied by the prose. Safe command examples in backticks are added as exact static allows. Unrecognized prose is still stored as session LLM context, but does not create broad static globs. Generated static-grant notes are stored and displayed separately from the evaluator prompt so operators can audit which compiler output explains the generated rules without expanding the model context.

Session allow/deny patterns use guard's shell-style glob matcher, not regex. `*`, `?`, and bracket classes are supported, but the match is against the flat reconstructed command line; it does not understand shell quoting, Kubernetes resource schemas, or argument semantics. Generated rules therefore use broad globs sparingly: for example, Kubernetes prose grants may add namespace-bounded `get * -n grafana` and `describe * -n grafana` read globs, backed by explicit secret and mutating-resource denies. Automatic amendments do not add globs at all; they add exact `binary + argv` rules, so literal `*` or `[` characters in an appealed command do not become wildcards. New structured constraints belong on typed verbs and capability coverage, with sessions or named profiles selecting those capabilities rather than growing another glob language.

Matching deny patterns win over allow patterns, and by default everything that does not match a session rule falls through to the normal evaluator with the session prose and optional `--prompt` context appended. A matching session allow skips the evaluator only; it still stays inside the server binary allow-list, consequence routing, held-command snapshot binding, read-grant retry path, audit log, and session history. Legacy allow globs do not short-circuit cwd-bearing requests, because relative files and tool discovery can change meaning by directory; use a typed verb or a cwd-bound exact session allow for those commands. Prose grants enable `auto_amend` by default so fresh low-risk LLM fallback approvals can add exact session allows bound to the canonical cwd when one is present, and fresh high-risk LLM denials can add exact session denies. Use `--no-auto-amend` to keep fallback non-mutating, or `--auto-amend` to opt a manual `--allow`/`--deny` grant into the same behavior. Cache hits, static policy hits, and learned-rule hits never amend a session; session fallback also does not promote global learned rules. Add `--static-only` (alias `--no-llm-fallback`) to `guard grant`, `guard session grant`, or `guard session new` to deny any session-rule miss instead of falling through to the LLM; static-only grants disable auto-amend.

To ask for a one-off amendment without executing the command, appeal it:

```bash
guard appeal --session <token> kubectl get httproute -n grafana
# or, when GUARD_SESSION is already set:
guard appeal kubectl get httproute -n grafana
# equivalent explicit session subcommand:
guard session appeal <token> kubectl get httproute -n grafana
```

An appeal runs the evaluator with the session context and then either amends an exact allow, amends an exact deny for a high-risk denial, or refuses to amend. It exits nonzero when the appealed command remains denied. Appeals are admin RPCs, like grant and revoke, because they can change durable authorization state.

Session grants are persisted in the daemon state database and survive daemon restarts by default. The default path is the XDG state dir (`$XDG_STATE_HOME/guard/state.db` or `~/.local/state/guard/state.db`); override it with `--state-db` or `GUARD_STATE_DB`. `guard session revoke <token>` is restricted to the daemon principal. `guard session list` is visible over a local listener to exec-allowed callers: non-admin callers see redacted tokens, hidden rule bodies, hidden generated notes, and hidden prompt text for other sessions. If `GUARD_SESSION` matches an active or historical grant, that row is shown as `token=(current)` with its own rules, prompt context, and generated notes visible, but the raw token is still not printed.

For forensics, `guard session show <token>` prints prompt context, generated notes, aggregate allow/deny and exec outcome counts, source breakdown (`llm`, `cache`, `static_policy`, `session_allow`, `session_deny`, `session_static_only`, `validation`), a risk histogram for LLM-evaluated calls, and a bounded recent interaction log. Each interaction includes an optional child exit code and the names, never values, of secrets that reached a successfully spawned child. Daemon-principal and TCP admin-token callers see the raw token. Non-admin local callers may show a session only by presenting its token and receive the same session details with tokens rendered as `(provided)`. Those summaries are loaded from the state database, so they remain available after a service restart within the configured retention window.

## Scoped file read grants

Brokered tools routinely need to read operator-owned files (ansible vars,
helm values) that guard's low-privilege service account cannot open. A read
grant adds a time-boxed POSIX ACL for exactly one file (Unix only) through the
transparent retry path.

When a brokered command fails naming a file it could not read, the daemon runs
the read-grant pipeline on that path automatically. The pipeline applies a hard
credential-path deny-list (key material, kubeconfigs, env files) before the
evaluator sees the request, then session allow/deny rules, then the LLM. On an
allow, guard applies a short-TTL ACL grant to its brokering account (or the
caller account under `--exec-as-caller`) and retries the original command.

Ancestor directories get traverse-only entries, never above the file owner's
home. The apply is pinned to the inode vetted at evaluation time (multi-hardlink
targets are refused, and a path swapped for a symlink in between aborts the
grant), grants persist in the state database, and the sweeper revokes them at
TTL or on startup if the daemon was down when one expired. A denied path
(credential file, session deny, evaluator deny) returns the command's own
failure unchanged, and every grant and retry is audited.

## Per-run secret injection

`guard run` can request stored secrets for one approved command without requiring a shim or persistent tool config. The daemon resolves the secret values immediately before exec, injects them into the child environment, and includes those values in exact-match output redaction.

`guard secrets add/list/remove` and `--secret`/`--env` injection are local-caller operations on both platforms. They require an authenticated local peer - a Unix-socket uid or a Windows named-pipe SID - and the secret namespace is keyed from that principal. A bearer-token TCP caller is refused, because a token is not a trustworthy local identity. Any local caller can manage its own secret namespace. When the daemon principal runs `guard secrets list`, it gets an aggregate names-only view across every principal's namespace; duplicate key names can appear more than once and are intentionally not annotated with ownership in the default list output.

Per-run `--env` and `--secret` values cannot replace Guard-owned execution
context. If a requested env var collides with tool configuration or daemon
`--child-env`, the command fails before exec instead of silently overriding a
brokered endpoint or credential.

For daemon-side migration and cleanup, use `guard secrets list --detailed` as the daemon principal. That view annotates the owning principal for namespaced entries and `origin=legacy` for pre-namespace flat secrets that still need operator migration.

Pre-namespace flat secrets are excluded from normal per-user `guard secrets list` / `guard run --secret` paths. Migrate them before rollout:

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

Session mutating RPCs (`grant`, grant-installing `session new`, `appeal`, and `revoke`, plus the privileged subset of `status`) are restricted to **the daemon's own principal** over a local listener: its uid over a Unix-domain socket, its SID over a Windows named pipe. Token-only `session new` runs locally and does not contact the daemon. `session list` is visible to exec-allowed local callers with redaction. Non-admin callers see that grants exist, when they were granted, and when they expire, but tokens, rule bodies, generated notes, and prompt text are hidden for other sessions. If `GUARD_SESSION` names a session the caller already has, that row is shown as `token=(current)` and includes its own rules, generated notes, and prompt context without printing the raw token. `session show <token>` accepts a known token from an exec-allowed local caller and prints details with token output hidden as `(provided)`. On TCP transports, non-Ping admin RPCs require the separate `GUARD_ADMIN_TOKEN`; the ordinary TCP exec `GUARD_AUTH_TOKEN` is not enough to mint grants.

The non-privileged `guard status` (run as your normal user or any other exec-allowed UID, or over TCP without the admin token) returns only client + server version, uptime, evaluation mode, and dry-run state. It is a liveness probe, enough to confirm the connection works and what mode the evaluator is in without exposing deployment detail. The daemon principal also sees queue depths, learned-store counts, the verb-catalog content hash and change time, and the resolved server configuration. A client/server version mismatch is reported explicitly.

The `--prompt` / `--prompt-file` flags attach a free-form context fragment that is appended to the LLM system prompt under a `Session context:` heading for evaluator calls made under that token. Prose grants use the same context path after static rule synthesis. Use prompt/prose for guidance the static glob patterns cannot express. The decision cache is bypassed when a session prompt is in play, because cached verdicts were made under the base prompt and may not hold under the extended context.

Durable grants deserve the same care as any other persistent authorization state. Prefer explicit TTLs for elevated sessions, and treat `allow=["*"]` as a legacy operator override that must be revoked intentionally rather than something a daemon restart clears. Generated prose rules intentionally stay narrow; if guard cannot infer a safe static rule, it relies on LLM fallback or denies under `--static-only`.

## Execution identity

By default the daemon executes approved commands as its own service identity, on both platforms. That service identity is the containment boundary: an agent calling through the daemon runs commands with the daemon's authority, not its own, and approval of held commands rests on the daemon's principal being distinct from the agent's.

`--exec-as-caller` (Unix only) extends this into a per-user secret broker and redactor for files such as `~/.aws/config` or `~/.cmk/config`. Start a root-owned daemon with `--exec-as-caller` and only a Unix socket listener; guard authenticates the caller by Unix peer credentials and drops the child process to that uid before exec, so the command runs with the caller's filesystem access instead of root's. TCP listeners are incompatible with this mode because a token is not a trustworthy local uid. Windows has no setuid-style identity drop, so containment there rests on running the daemon as a dedicated Windows service account: the daemon owns the named pipe, the state database, and any brokered credentials under an NTFS ACL that excludes the interactive agent's account. The agent connects to the pipe under its own SID - distinct from the daemon's - so it cannot approve its own held commands or read the daemon's state and credentials. See [`deployment/windows/install-guard.ps1`](deployment/windows/install-guard.ps1).

## Agent integration

Point your agent's command execution at `guard run` instead of direct execution.

Human output streams child stdout and stderr as they arrive. `guard run --json`
and `guard verb run <name> --json` instead wait for completion and emit one JSON
object containing the command, decision, reason, handle, coverage, child output,
and child exit code. Read commands support the same flag: `status`,
`provisionals`, `approvals`, `verb list`, `session list`, `session show`,
`secrets list`, `config show`, and shim listing. JSON data goes to stdout;
diagnostics go to stderr. Every envelope carries `schema_version: 1`.

Exit codes for scripted callers are stable. An executed command propagates the
child process's exit code, including `1` and `75`. Guard uses `125` for its own
operational errors, `126` for policy denial, and `127` for a command held for
operator approval. Invalid CLI usage follows the conventional exit code `2`.
The structured response retains the exact child status and the hold or
provisional handle.

### MCP server

Guard can run as a stdio MCP server so agents call a tool instead of shelling out:

```bash
guard config set-server ~/.guard/guard.sock
guard mcp serve
```

The server exposes three tools: `guard_run`, `guard_verbs`, and
`guard_approvals`. `guard_run` executes a command through the daemon:

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

The other two tools take no arguments and are read-only. `guard_verbs` lists
the operator-defined verb catalog: each verb names a binary, its consequence
class, and its validated parameters; invoke a verb through `guard_run`.
`guard_approvals` lists the caller's held approvals and provisional
(auto-revert) executions, scoped to the caller by the daemon; it is how an
agent polls whether an operator has approved a held command or which
provisionals are still inside their revert window.

`guard mcp serve` defaults to stdio and the configured daemon endpoint;
`--socket`, `--tcp-port`, and `--token` override the endpoint. `--tool-name`
renames the execute tool (default `guard_run`). `--http <addr>` serves
Streamable-HTTP on a local address instead of stdio and requires a bearer
token via `--http-token` or `GUARD_MCP_TOKEN`.

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
# Where the daemon starts (the API key and policy mode are daemon-side settings):
export GUARD_LLM_API_KEY="..."
GUARD_MODE=readonly guard server start &

# In the agent's environment:
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

2. **Output redaction**: Known secret values (API keys, auth tokens, tool secrets, per-run injected secrets) are exact-match redacted from stdout/stderr before returning to the agent. Pattern-based redaction catches secrets guard has never seen: secret-bearing key names (`*_TOKEN`, `*_KEY`, `apikey`, `secretkey`, `*_PASSWORD`, ...) in env, YAML, and quoted-JSON form, single-line flow-style `name`/`value` env pairs, PEM blocks, JWTs, `Bearer`/`Basic` header tokens, `sk-*`/`AKIA*` keys, and bare high-entropy key material. Quoted JSON/YAML values stay quoted after replacement, so redacted structured output remains parseable. The same engine redacts all text sent to the LLM evaluator, so a credential embedded in a command or session context never reaches the model. Output redaction is on by default; `--no-redact` disables output redaction only - LLM-bound text is always pre-redacted regardless of the flag.

3. **LLM evaluation**: Each command is analyzed for destructive intent, privilege escalation, reverse shells, obfuscated payloads, tool side-channel abuse, and prompt injection. The LLM evaluates the full command including all chained parts.

## Audit logging

Guard logs audit events through the dedicated `guard::audit` tracing target. The audit sink remains active when `RUST_LOG` or `GUARD_LOG_LEVEL` suppresses ordinary diagnostics. Configure ordinary diagnostic and evaluator-usage verbosity with `RUST_LOG`:

```bash
RUST_LOG=info guard server start    # diagnostics + token usage
RUST_LOG=debug guard server start   # verbose request/response logging
```

LLM token usage is logged per evaluation:

```
[LLM_USAGE] model=openai/gpt-5.4-mini attempt=1 prompt_tokens=3594 completion_tokens=47 total_tokens=3641 status=ok
```

Per-command audit records use stable 128-bit SHA-256 session fingerprints, so events correlate without exposing bearer token bytes. `SECRET_EXPOSED` records are emitted only after a child starts and contain the secret name, session fingerprint, and masked command, never the value. Exposure means the value entered the child environment; it does not prove the child read or consumed it.

For this local deployment model, the audit source of truth is the daemon's structured `tracing` output, typically collected by journald. The SQLite state database is for session state and queryable session history, not for replacing your log pipeline. `guard session show` is an operator view over that persisted session history; it complements journald.

## Limitations

- **Not a sandbox.** Guard is a policy gate, not an isolation boundary. Defense-in-depth (seccomp, read-only FS, restricted users, network segmentation) is still needed for adversarial environments.
- **No interactive sessions.** Agents get command execution only.
- **LLM latency.** Each command adds ~0.5-2s for the LLM call.
- **Fail-closed.** If the LLM call fails or returns unparseable output, the command is denied.

## License

MIT
