# guard

[![CI](https://github.com/morgaesis/guard/actions/workflows/ci.yml/badge.svg)](https://github.com/morgaesis/guard/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/morgaesis/guard/badge)](https://scorecard.dev/viewer/?uri=github.com/morgaesis/guard)

Guard is a policy-gated command and API broker for AI agents. Agents submit
ordinary commands or API requests and describe missing access in prose. The
Guard daemon applies policy, reduces approved intent to bounded enforcement
coverage, evaluates risk, and keeps daemon-held upstream credentials behind
brokered API boundaries. Fixed-identity execution uses a non-root child account
that differs from the daemon account, receives no upstream or per-run
credentials, and cannot read daemon state. An optional generated Kubernetes
client config carries only a local transport bearer scoped to the active Guard
proxy. Operators must keep independent credentials inaccessible to that child
account.

```console
$ guard run uptime
 09:18:41 up 12 days,  3:07,  2 users,  load average: 0.08, 0.11, 0.09

$ guard run rm -rf /etc/nginx
DENIED: Recursive deletion of system configuration.
  source:  static-policy
  appeal:  operator-authored policy deny; absolute -- --reevaluate never skips it
```

Guard combines operator policy and prose-first access requests with an LLM
evaluator, deterministic binary limits, consequence routing, credential
brokering, output redaction, and protocol-aware API mediation. Typed verbs and
saved grants implement enforcement behind that workflow. Guard is a policy
gate, not a sandbox. The agent must run as a principal that cannot bypass the
daemon or read its credentials.

## Install

```bash
cargo install --path .
```

Release archives are available for Linux x86-64, Linux ARM64, and Windows
x86-64. See [INSTALL.md](INSTALL.md) for release and service installation.
Bug reports, development setup, and the pull-request process are documented in
[DEVELOPMENT.md](DEVELOPMENT.md). Security reports follow
[SECURITY.md](SECURITY.md).

## Quick start

```bash
export GUARD_LLM_API_KEY="..."
sudo --preserve-env=GUARD_LLM_API_KEY guard server start \
  --socket /run/guard/guard.sock \
  --socket-group "$(id -gn)" \
  --exec-as-caller &

guard config set-server /run/guard/guard.sock
guard run uptime
guard run rm -rf /tmp/example
```

This foreground quick start uses the authenticated caller as the child
identity. It is convenient for local evaluation, but it does not isolate
caller-owned files or scalar secrets from other processes owned by that caller.
Use the packaged fixed-identity service for a worker that receives no
Guard-managed credentials and cannot read daemon state.
Raw local-file reads are rejected. Load a typed verb catalog and invoke its
bounded local-file verb when a workflow needs file authority.

The daemon reads its mode, policy, and credentials at startup. Client-side
environment changes do not alter daemon policy.

The packaged execution-capable systemd services share the host `/tmp` namespace
with brokered children, so their temporary files remain visible to the caller
subject to normal file permissions.

| Mode | Intended use |
|---|---|
| `readonly` | Investigation without state changes |
| `safe` | Bounded administration with evaluator judgment |
| `paranoid` | Minimal inspection for an untrusted workload |

Set the mode where the daemon starts:

```bash
sudo --preserve-env=GUARD_LLM_API_KEY \
  env GUARD_MODE=safe guard server start \
    --socket /run/guard/guard.sock \
    --socket-group "$(id -gn)" \
    --exec-as-caller
```

Use a separate dry-run daemon to evaluate commands without spawning approved
children:

```bash
guard server start --dry-run --socket .cache/guard-dry-run.sock
guard server connect --socket .cache/guard-dry-run.sock bash -- -c 'sudo id'
```

## Access model

Guard's supported public authority model is policy plus prose-first access
intent. Policy supplies global evaluator behavior and hard boundaries. Agents
continue to use ordinary commands and API requests, and submit a prose access
request when authority is missing. Operators approve, deny, extend, inspect, or
revoke those principal-bound requests through `guard access`.

Typed verbs, coverage cells, saved grants, and sessions are operator and
enforcement internals. The daemon maps approved intent into those bounded
objects so policy, credentials, consequence, expiry, and use counts remain
deterministic. Operator verb commands inspect and exercise the typed catalog.
Legacy grant, session, and appeal commands return a direct error pointing to
`guard access`; they cannot mint, modify, or print authority.

Internally, a verb coverage cell is silent outside its declared bounds.
Allowing one active-proxy `kubectl get` cell does not generate denies for
unrelated commands, so ordinary read-only work such as
`guard run systemctl status sshd.service` remains independently evaluable. Raw commands
reverse-match every applicable verb cell, which lets agents benefit from verbs
without changing their normal tool syntax.

Session coverage may expand a baseline readonly or evaluator posture inside its
activated regions. It does not override hard invariants, sticky operator cells,
binary limits, credential binding, or the consequence gate. A baseline cell
that declares an override marker changes only when the issued session carries
the exact operator-authored marker.

Request access in prose and let the daemon reduce it to typed coverage:

```bash
guard access request 'Inspect host-a and report drift.'
guard access list
```

An operator approves one or more durable requests with `guard access approve`.
`--once` is exactly `--uses 1`; `--uses 3` grants that request three admissions.
On a terminal, approve reviews each request first with a colored card and an
approve, deny, skip, or quit prompt; `--yes` skips the review. Each approval
retains its own scope and count. Denied results offer ordinary, one-time, and
bounded approval. A held result offers only `--once` because it represents one
immutable reviewed snapshot. Approval arms that snapshot, and its original
requester executes it with `guard approval resume <request>`. Operators remove an active
access session with `guard access revoke <session-or-agent>`.

Structured execution results include a versioned decision trace with a stable
source, every applicable typed cell, conflicts, and bounded next-step guidance.
Use `--explain` to render it on successful human runs; denials and holds always
show actionable guidance.

See [Access and authority internals](docs/saved-grants.md) and
[Operator verb catalogs](docs/verbs.md).

## Consequence routing

With `--gate consequence`, reversible operations run immediately, recoverable
changes run inside an auto-revert envelope, and irreversible or uncertain work
is held. A viable forward, verify, and revert chain can finish autonomously.
Holds are the exception path for missing or unsafe authority.

Provision the dedicated `guard` and `guard-exec` accounts first, using the
[Unix service setup](DEPLOYMENT.md#unix-service).

```bash
sudo install -d -o root -g root -m 0755 /run/guard
sudo install -o root -g guard-exec -m 0640 /dev/null /run/guard/kubeconfig
sudo env KUBECONFIG=/run/guard/kubeconfig \
  guard server start --gate consequence \
  --socket /run/guard/guard.sock \
  --exec-user guard-exec \
  --verbs /etc/guard/verbs.yaml \
  --child-env KUBECONFIG \
  --kube-proxy 127.0.0.1:8443 \
  --kubeconfig /etc/guard/upstream.kubeconfig \
  --brokered-kubeconfig-out /run/guard/kubeconfig \
  --api-policy /etc/guard/api-policy.yaml

guard config set-server /run/guard/guard.sock
guard run kubectl get pods -n production -o wide
```

On Windows, run
`& 'C:\Program Files\Guard\guard-operator.ps1' -Action confirm -Reference <handle>`
from an elevated PowerShell instead of using the Unix wrapper.

Guard preserves an admitted command's argv, working directory, exit behavior,
and native tool semantics. See [Consequence gating](docs/consequence-gating.md).

## Brokered tools and APIs

Shims preserve familiar command names while routing them through `guard run`:

```bash
guard shim kubectl systemctl
```

The caller supplies argv and its working directory. The daemon selects the
execution identity, a clean environment, and operator-owned non-credential tool
settings. Fixed-identity mode refuses per-run environment and credential
delivery because its shared UID is not an execution sandbox. A fixed-child
`KUBECONFIG` is accepted only when its complete schema, endpoint, CA, and inert
bearer match an active Guard proxy. Fixed identity denies Ansible and Helm
because their mutable profile state cannot safely cross identities. Caller
identity denies Ansible, Helm, and kubectl because it has no immutable typed
profile snapshot. See
[Agent integration](docs/agent-integration.md).

For tools that make HTTP requests in-process, the API proxy gates each typed
request and re-originates allowed traffic with daemon-held upstream credentials.
Kubernetes is the reference protocol; GitHub and Vercel adapters demonstrate
the generic protocol surface. One daemon can serve multiple named listeners.

Guard strips client authentication before forwarding and injects the endpoint's
upstream credential only after authorization. Public access sessions remain
command-only and export no API bearer. See [API proxy](docs/api-proxy.md).

## Security boundary

Credential ownership prevents bypass. The fixed child account receives no
upstream or per-run credentials, while the daemon retains secret-backend and
API upstream authority. Its optional generated Kubernetes client config carries
only a local transport bearer scoped to the active Guard proxy. Operators keep
unrelated credentials inaccessible to the child. The agent account can reach
only the Guard socket, named pipe, or a loopback broker endpoint. Output
redaction, audit records, behavioral session limits, and frozen hold snapshots
reduce exposure after a request enters the broker.

Guard cannot contain an agent that can read the same credentials or reach the
same upstream by another path. Pair it with operating-system isolation,
tool-native access control, backups, and network segmentation. See
[Security model](docs/security-model.md) and [DEPLOYMENT.md](DEPLOYMENT.md).

## Documentation

| Document | Contents |
|---|---|
| [INSTALL.md](INSTALL.md) | Binary installation and initial endpoint setup |
| [Release verification](docs/release-verification.md) | Checksums, SBOMs, and signed build provenance |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Service accounts, hardening, and unattended operation |
| [Configuration](docs/configuration.md) | Environment, endpoints, evaluator, and state |
| [Access and authority internals](docs/saved-grants.md) | Prose requests, approvals, bounded uses, and internal authority state |
| [Operator verb catalogs](docs/verbs.md) | Typed enforcement, reverse matching, precedence, and promotion |
| [Consequence gating](docs/consequence-gating.md) | Holds, auto-revert, confirmation, and recovery |
| [API proxy](docs/api-proxy.md) | Protocol policy, brokered credentials, listeners, and API reverts |
| [Agent integration](docs/agent-integration.md) | Shims, working directory, structured output, and MCP |
| [Security model](docs/security-model.md) | Principals, bypass prevention, audit, and limits |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Source hierarchy and design constraints |
| [ROADMAP.md](ROADMAP.md) | Open engineering goals |

## License

MIT
