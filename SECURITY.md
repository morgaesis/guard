# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub's
["Report a vulnerability"](https://github.com/morgaesis/guard/security/advisories/new)
flow rather than opening a public issue.

If you cannot use the GitHub flow, email the maintainer at
`morgaesis+security@morgaes.is` with the details. PGP is available on
keys.openpgp.org under the same address.

Expect an initial acknowledgement within five business days. Coordinated
disclosure timelines are negotiated case by case based on severity and
deployment exposure.

## Scope

In scope:

- The `guard` daemon and CLI in this repository
- The MCP transport (`guard mcp serve`)
- The systemd unit and example deployment under `deployment/`

Client-facing denials may include the count of similar commands the same
deny-shape bucket has denied once the configured threshold is reached. Learned
rule, verb, deny-shape, and API-shape promotion state is operator-only audit
state because advertising which shapes skip evaluation invites mimicry against
the fast path.

Opaque carrier tools such as Ansible, Helm, and generic plug-ins are gated as
commands unless they use a protocol proxy. In readonly and safe modes, opaque
file-driven execution is denied or held unless an operator grants it
deliberately. Guard does not inspect playbook, chart, inventory, or values-file
contents in the command gate, and cooperative requirements such as check/diff
flags are accident controls for trusted grants rather than containment against a
malicious granted runner.

Out of scope:

- Compromise of the LLM provider or model itself
- Operator misconfiguration that disables documented guardrails (e.g.
  running with `--no-evaluator` and no static policy)
- Third-party tools invoked by approved commands
- SSH transport brokering, scoped or ephemeral SSH endpoints, file staging, and
  file-content inspection outside the protocol proxy model

## Trust boundaries

Each boundary crossing, the adversary it assumes, the asset at stake, and the
controls the daemon implements:

| Boundary | Adversary | Asset | Controls |
|---|---|---|---|
| Agent to daemon wire | Local process submitting requests or impersonating the operator | Execution authority and admin RPCs | Unix peer-credential uid and Windows named-pipe SID authentication, failing closed when the peer identity cannot be resolved; optional `--users` uid allow-list; sockets created `0600`, widened to `0660` only after `--socket-group` assignment; TCP bearer tokens compared in constant time; admin RPCs accept only the daemon's own principal (or the separate TCP admin token) |
| Operator configuration files | Non-operator principal supplying policy, verbs, or grants | Authorization catalogs and prompts | Catalogs are operator-owned files read from the daemon side; an explicitly configured missing or malformed catalog fails startup; deployment guidance keeps state, catalogs, and environment files outside the agent group |
| Evaluator LLM | Untrusted command text steering the model toward a wrong verdict | Allow/deny decisions | Command text is data in the prompt with an explicit anti-injection clause; static policy deny patterns run before the evaluator; the `--allow-bin` floor applies regardless of the verdict; consequence gating holds irreversible work for the operator; evaluator errors, overload, and open circuits fail closed; secret values never enter prompts (Guard binds them by name and value digest) |
| Secret store | Agent or other local principal reading stored credentials | Stored secret values | Values are resolved server-side inside the daemon and never returned to the client; per-principal namespaces keyed by Unix uid or Windows SID prevent cross-principal reads; policy and audit see environment and store names, not values; output redaction of known secret values is on by default |
| Brokered child process | Approved child reading daemon credentials or retaining privilege | Daemon environment, credentials, and capabilities | `env_clear()` with a fixed safe-variable allowlist plus operator-selected `GUARD_CHILD_ENV`; ambient and inheritable capabilities cleared before exec so the read-grant capabilities never reach a child; secret files are daemon-owned with child-lifetime cleanup; the packaged unit sets `NoNewPrivileges=true` |
| On-disk state database | Local principal reading or forging authorization state | Sessions, saved authority, holds, provisionals, history | Private state directories `0700` and database files `0600`; symlinked or non-regular database paths and unsafe writable parent directories are rejected; the store is schema-versioned, migrates older databases, and refuses ones written by a newer binary |
