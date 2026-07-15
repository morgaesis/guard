# guard

Guard is an evaluator-gated command and API broker for AI agents. Agents submit
ordinary commands or API requests, while the Guard daemon applies policy,
evaluates intent and risk, and executes approved work with credentials the agent
cannot read.

```console
$ guard run uptime
 09:18:41 up 12 days,  3:07,  2 users,  load average: 0.08, 0.11, 0.09

$ guard run rm -rf /etc/nginx
DENIED: Recursive deletion of system configuration.
```

Guard combines an LLM evaluator with deterministic binary limits, typed verbs,
saved grants, consequence routing, credential brokering, output redaction, and
protocol-aware API mediation. It is a policy gate, not a sandbox. The agent must
run as a principal that cannot bypass the daemon or read its credentials.

## Install

```bash
cargo install --path .
```

Release archives are available for Linux x86-64, Linux ARM64, and Windows
x86-64. See [INSTALL.md](INSTALL.md) for release and service installation.

## Quick start

```bash
export GUARD_LLM_API_KEY="..."
guard server start &

guard run uptime
guard run cat /var/log/syslog
guard run rm -rf /tmp/example
```

The daemon reads its mode, policy, and credentials at startup. Client-side
environment changes do not alter daemon policy.

| Mode | Intended use |
|---|---|
| `readonly` | Investigation without state changes |
| `safe` | Bounded administration with evaluator judgment |
| `paranoid` | Minimal inspection for an untrusted workload |

Set the mode where the daemon starts:

```bash
GUARD_MODE=safe guard server start
```

Use a separate dry-run daemon to evaluate commands without spawning approved
children:

```bash
guard server start --dry-run --socket .cache/guard-dry-run.sock
guard server connect --socket .cache/guard-dry-run.sock bash -- -c 'sudo id'
```

## Core model

Guard has three public authorization nouns:

- **Policy** supplies global evaluator behavior and hard boundaries.
- **Verbs** describe typed operation coverage, credential plans, and consequence.
- **Grants** activate or expand verb coverage for a saved scope or live session.

A verb coverage cell is silent outside its declared bounds. Allowing Ansible
`--check` mode does not generate denies for unrelated commands, so ordinary
read-only work such as `guard run ssh host uptime` remains independently
evaluable. Raw commands reverse-match every applicable verb cell, which lets
agents benefit from verbs without changing their normal tool syntax.

Session coverage may expand a baseline readonly or evaluator posture inside its
activated regions. It does not override hard invariants, sticky operator cells,
binary limits, credential binding, or the consequence gate. A baseline cell
that declares an override marker changes only when the issued session carries
the exact operator-authored marker.

Create and issue a reusable grant:

```bash
guard grant save host-a-checks \
  --verb ansible-host-a-check \
  --ttl 1800 \
  --prompt 'Inspect host-a and report drift.'

eval "$(guard grant issue host-a-checks)"
guard session status
```

Edit a saved grant with `guard grant edit`. Preview regenerated typed coverage,
inspect the candidate and delta, then apply that proposal:

```bash
guard grant regenerate host-a-checks
guard grant regenerate host-a-checks --apply <proposal-id>
```

Agents request bounded expansion through `guard grant request submit`; a denial
returns a durable handle and the exact operator action needed to resolve it.

Structured execution results include a versioned decision trace with a stable
source, every applicable typed cell, conflicts, and bounded next-step guidance.
Use `--explain` to render it on successful human runs; denials and holds always
show actionable guidance.

See [Saved grants and sessions](docs/saved-grants.md) and
[Typed verbs and coverage](docs/verbs.md).

## Consequence routing

With `--gate consequence`, reversible operations run immediately, recoverable
changes run inside an auto-revert envelope, and irreversible or uncertain work
is held. A viable forward, verify, and revert chain can finish autonomously.
Holds are the exception path for missing or unsafe authority.

```bash
guard server start --gate consequence \
  --socket /run/guard/guard.sock \
  --verbs /etc/guard/verbs.yaml

guard verb run restart-service --param unit=nginx
guard provisionals
guard confirm <handle>
```

Guard preserves the command's argv, working directory, exit behavior, and tool
semantics. It does not reinterpret Ansible, Helm, SSH, or another tool. See
[Consequence gating](docs/consequence-gating.md).

## Brokered tools and APIs

Shims preserve familiar command names while routing them through `guard run`:

```bash
guard shim ssh kubectl helm ansible ansible-playbook
```

The caller supplies argv and its working directory. The daemon supplies its own
identity, clean environment, SSH configuration and agent socket, and approved
secret bindings. File-driven tools run in place, without staging or copying
their project files. See [Agent integration](docs/agent-integration.md).

For tools that make HTTP requests in-process, the API proxy gates each typed
request and re-originates allowed traffic with daemon-held upstream credentials.
Kubernetes is the reference protocol; GitHub and Vercel adapters demonstrate
the generic protocol surface. One daemon can serve multiple named listeners.

Clients send `Authorization: Bearer <Guard session>`. Guard consumes that
session bearer, never forwards it, and injects the endpoint's upstream
credential only after authorization. See [API proxy](docs/api-proxy.md).

## Security boundary

Credential ownership prevents bypass. The daemon account owns remote SSH and API
credentials, while the agent account can reach only the Guard socket, named
pipe, or a loopback broker endpoint. Output redaction, audit records, behavioral
session limits, and frozen hold snapshots reduce exposure after a request enters
the broker.

Guard cannot contain an agent that can read the same credentials or reach the
same upstream by another path. Pair it with operating-system isolation,
tool-native access control, backups, and network segmentation. See
[Security model](docs/security-model.md) and [DEPLOYMENT.md](DEPLOYMENT.md).

## Documentation

| Document | Contents |
|---|---|
| [INSTALL.md](INSTALL.md) | Binary installation and initial endpoint setup |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Service accounts, hardening, and unattended operation |
| [Configuration](docs/configuration.md) | Environment, endpoints, evaluator, and state |
| [Saved grants and sessions](docs/saved-grants.md) | Reusable authority, live sessions, and requests |
| [Typed verbs and coverage](docs/verbs.md) | Templates, reverse matching, precedence, and promotion |
| [Consequence gating](docs/consequence-gating.md) | Holds, auto-revert, confirmation, and recovery |
| [API proxy](docs/api-proxy.md) | Protocol policy, brokered credentials, listeners, and API reverts |
| [Agent integration](docs/agent-integration.md) | Shims, working directory, structured output, and MCP |
| [Security model](docs/security-model.md) | Principals, bypass prevention, audit, and limits |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Source hierarchy and design constraints |
| [ROADMAP.md](ROADMAP.md) | Open engineering goals |

## License

MIT
