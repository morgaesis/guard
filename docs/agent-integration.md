# Agent integration

Guard keeps the agent-facing surface close to ordinary shell and API tooling.
The daemon remains the only policy and credential boundary; integrations do not
reimplement evaluation.

## Generic shims

Install wrappers for tools an agent already knows:

```bash
guard shim kubectl systemctl
guard shim --list
guard shim --remove systemctl
```

A shim preserves argv and the caller's working directory, then invokes
`guard run`. Any executable name can be shimmed, but installing a shim does not
add an executable profile or make the command admissible. Guard avoids
re-entering the top-level shim while leaving nested shims available to child
processes.

Local execution uses a versioned wire envelope. The client declares the local
working-directory feature and must include `cwd`; the daemon rejects legacy,
missing, or unsupported contracts with an upgrade error before evaluation.
TCP clients declare that caller filesystem context is unavailable instead of
silently inheriting the daemon's working directory.

Protocol-v1 response `status` values remain a closed compatibility vocabulary.
A containment failure uses `allowed: false`, an absent `status`, no confirmation
deadline fields, and an optional typed `containment_failure` object. Its
`command_may_have_run` and `forward_exit_code` fields are authoritative for new
clients. Older clients ignore the optional object and still fail closed without
claiming an armed timer. A recovery `handle` is present only when the daemon can
resolve its live or durable record; the sanitized `reason` repeats the valid
operator action for clients that do not understand the typed field.

Add the shim directory ahead of the real tools in the agent's `PATH`. The agent
cannot bypass Guard if it also lacks remote credentials and direct upstream
reachability.

## Guard-owned execution context

An authenticated caller controls the command argv and a canonicalized working
directory. The daemon executes approved work with:

- the dedicated `--exec-user` identity, or the authenticated Unix caller when
  `--exec-as-caller` is set;
- a clean environment plus built-in safe values;
- operator-selected non-credential `GUARD_CHILD_ENV` values;
- a daemon-resolved primary executable and server-owned executable search path;
- no Guard-managed SSH credential in fixed-identity mode;
- caller-specific scalar secret bindings only with `--exec-as-caller`.

Caller-controlled `SSH_AUTH_SOCK`, SSH configuration, or credential environment
does not replace this context. Daemon-held remote credentials stay behind the
API proxy instead of entering a local child process.

The standard fixed child UID is shared across executions. It isolates daemon
state, but it cannot isolate same-UID processes from each other. Guard therefore
refuses per-run environment and credential delivery, tool-config credentials,
credential-authority environment, and temporary read grants in fixed-identity
mode. A `KUBECONFIG` passed from daemon or tool environment must match the
complete generated schema, endpoint, CA, and transport bearer of an active Guard
proxy. Do not provision durable credentials under the fixed child home.

Kubectl uses a closed environment schema. Its endpoint, context, user,
impersonation, configuration, and executable selectors must be
operator-authored literals or finite enumerated values. In fixed-identity mode,
kubectl executes only with the generated kubeconfig for an active Guard proxy.
Ansible and Helm are denied before process start because their mutable profile
state cannot safely cross identities. Caller identity also denies typed
Ansible, Helm, and kubectl commands because it has no immutable profile
snapshot. Catalog coverage and access approval cannot bypass these process
admission rules.

For an admitted command, Guard preserves tool semantics and does not copy,
stage, rewrite, or interpret input files. A caller working directory is used
only when typed authority binds its canonical tree. The execution identity must
be able to traverse the authorized working-directory path and read required
files. The packaged
systemd units use `ProtectSystem=strict`, so an approved child cannot modify
protected host paths unless the deployment adds an explicit writable carve-out
or routes the operation through a remote or loopback service.

On Unix under `--exec-as-caller`, the transparent read-grant pipeline can
temporarily add an ACL for the authenticated caller child on one named file.
Fixed-identity execution refuses read grants. Credential-shaped paths,
multi-hardlink files, symlink swaps, and traversal outside the file owner's home
fail closed. The ACL is inode-pinned, TTL-scoped, audited, persisted for cleanup,
and removed by startup or periodic reconciliation. Windows keeps native file
ACLs unchanged and returns access denied.

`--exec-user` is the standard Unix identity boundary. The child account has no
access to daemon state or authority files. `--exec-as-caller` is an alternate
Unix filesystem-identity model for a root daemon. It cannot be combined with
TCP, the API proxy, or secret-file delivery.
It also moves more local filesystem authority to the caller, so it is not the
default credential-broker model. It does not admit typed Ansible, kubectl, or
Helm execution. Fixed-identity mode admits only the exact active-proxy
kubeconfig exception for kubectl and rejects Ansible and Helm.

Grant expiry does not revoke effects an opaque child has already produced or
credentials it copied while running. The execution-context comparison and SSH
stream boundary are defined in [Security model](security-model.md#execution-and-credential-isolation).

## Secrets

Store secrets in the daemon backend, then name them at execution time:

```bash
guard secrets add DEPLOY_TOKEN
guard run --secret DEPLOY_TOKEN printenv DEPLOY_TOKEN
guard run --secret API_TOKEN=DEPLOY_TOKEN printenv API_TOKEN
```

These `guard run` forms require a daemon configured with `--exec-as-caller`.
Scalar delivery uses the authenticated caller's operating-system identity and
does not shield a credential from other processes owned by that caller.
Daemon-held credentials stay behind an API proxy. Local secret-file delivery
fails closed.

Secret values never enter the request, command line, evaluator prompt, audit
record, hold row, or session history. A hold stores an installation-keyed value
HMAC and revalidates it before approval. Child output is redacted by exact values and
credential-shaped patterns.

## Structured CLI output

Human `guard run` streams the child process. `guard run --json` returns one
machine-readable result containing child stdout, stderr, exit status, decision
source, matched verb cells, and escalation guidance. `--explain` renders those
details on stderr for a successful human run; default success remains quiet.
Authority-missing denials that reduce to typed coverage render one durable
request identifier and exact `guard access approve` guidance without requiring
the flag. A novel operation that cannot yet be reduced gives the exact
`guard access request` retry and states that no durable request exists. An
operator hard-deny is labeled non-overridable and creates no request. Holds
render one durable identifier and only one-time approval guidance. Typed denial
requests offer ordinary, one-time, and bounded access.
`guard access list --json`, `guard access show --json`, and `guard access status
--json` support automation without parsing prose or handling bearer tokens.

A successful human command does not print verb matching noise. Denied and held
commands print the matching coverage and the next bounded action on stderr.

### Exit codes

`guard run` reserves three exit codes for guard-origin outcomes and otherwise
propagates the executed child's exit status untranslated:

| Code  | Meaning                                                          |
| ----- | ---------------------------------------------------------------- |
| 125   | Guard operational error (daemon unreachable, protocol failure)   |
| 126   | Denied by policy                                                 |
| 127   | Held for operator approval                                       |
| 2     | Invalid guard CLI usage (argument parsing)                       |
| other | The child's own exit status, propagated untranslated             |

The reserved range collides with codes a child can produce on its own: `sh -c`
exits 127 when the named command is missing, and `git bisect skip` uses 125. An
exit code of 125-127 therefore suggests, but cannot prove, a guard-origin
outcome. An agent that needs certainty runs with `--json` and reads the
`allowed` and `status` fields; the exit code is a convenience for shell
pipelines, not the authoritative decision channel. `guard run` prints this
contract in its own help output (`guard help run`).

## MCP

Expose the same daemon through MCP over stdio:

```bash
guard config set-server ~/.guard/guard.sock
guard mcp serve
```

The MCP server executes commands through the normal daemon protocol. Structured
results include `schema_version` and `type`. Structured and human results carry
the stable decision source, matched cells, durable request identifier, and
exact access approval commands. It does not create a parallel policy path.
Normal client configuration supplies the execution token for a TCP daemon. MCP does
not receive or forward the configured admin bearer.

Local-socket stdio MCP exposes the following tools after a successful framed
endpoint probe and self-scoped admin probe:

| Tool | Purpose | Key arguments | CLI equivalent |
| ---- | ------- | ------------- | -------------- |
| `guard_run` | Execute one command through the daemon | `binary` (string) plus `args` (string array), or `verb` (`{name, params}`) for a catalog verb; one of the two is required. Optional: `env`, `secretEnv`, `secretFiles` (string maps), `secrets` (string array), containment gating (`revert`, `confirmCheck`, `revertControlPath` strings; `confirmWithin` integer; `requireApproval` boolean; `waitApproval` integer seconds or boolean), `reevaluate` (boolean) | `guard run`, `guard verb run` |
| `guard_verbs` | Read the operator-defined verb catalog | none | `guard verb list` |
| `guard_access_request` | Request access for an intended operation | `intent` (string, required) | `guard access request` |
| `guard_access_list` | List the caller's requests, holds, and access sessions | none | `guard access list` |
| `guard_evaluate_batch` | Dry-evaluate up to 64 command shapes without executing anything | `commands` (array of `{binary, args}`, 1-64 items, required); `session` (string, optional target session) | MCP-only; no CLI equivalent |
| `guard_access_show` | Show one durable request, hold, or access session | `reference` (string, required) | `guard access show` |
| `guard_access_status` | Show activity, decisions, holds, and provisionals for one access-managed session | `reference` (string, required) | `guard access status` |
| `guard_approval_show` | Show a requester-visible hold, including its bounded terminal transcript | `handle` (string, required), `wait` (1-3600 seconds, optional) | `guard approval show` |
| `guard_approval_resume` | Resume one operator-armed hold as its original requester | `handle` (string, required), `wait` (1-3600 seconds, optional) | `guard approval resume` |

The daemon must advertise `approval-consequences-v1` for the two
`guard_approval_*` tools. A separate cached Ping determines only that
capability membership. A capability-free, unavailable-Ping, or malformed-Ping
daemon retains the seven baseline local-socket tools when the framed endpoint
probe and independent Unix admin probe succeed. An unavailable or malformed
endpoint, or a failed Unix admin probe, exposes no tools. Direct calls report
`endpoint_unavailable` for endpoint or Unix admin-probe failures and
`feature_unavailable` for capability or transport exclusions.

`guard_run` is the default name for the execution tool; `guard mcp serve
--tool-name` renames it to a name that is not reserved by another built-in
tool. `guard_run`'s `waitApproval` mirrors the CLI's
`--wait-approval`: an integer bounds the wait in seconds, `true` waits without
bound, and `false` or omission returns the held handle immediately.
`guard_evaluate_batch` evaluates every shape against the active saved-grant
revision cache context and returns per-command verdicts without running,
holding, or reverting anything.

TCP MCP exposes only `guard_run` after a successful framed endpoint probe,
including when its separate Ping is unavailable or malformed. Administrative
MCP tools require the kernel-authenticated principal available on a local
socket and are not advertised over bearer-authenticated TCP.

HTTP MCP is available for a local single-tenant runtime and requires a bearer:

```bash
export GUARD_MCP_TOKEN="..."
guard mcp serve --http 127.0.0.1:7333
```

The HTTP listener accepts loopback addresses only. Requests require the bearer,
an absent or loopback `Origin`, and an `Accept` header listing both
`application/json` and `text/event-stream`. Unsupported
`MCP-Protocol-Version` values are rejected. The transport returns 405 for GET
because it does not provide an SSE listening stream. A successful initialize
response supplies an `Mcp-Session-Id`; subsequent requests present that ID and
can reconnect without losing MCP lifecycle state. Unknown, missing, duplicate,
or terminated sessions fail closed. Every HTTP MCP caller appears to the daemon
as the MCP process principal. HTTP exposes the local baseline except
`guard_access_status`; it never lists or dispatches `guard_approval_show` or
`guard_approval_resume`, so status reports and approval transcripts remain on
stdio. Use stdio when a network transport is unnecessary.

## In-process API clients

K9s, Terraform providers, and SDKs can perform API operations without spawning
a command for each request. Operator/bootstrap clients can point at Guard's
brokered endpoint so policy applies at the request boundary. The public access
workflow uses typed command verbs and exports no API bearer. See
[API proxy](api-proxy.md).
