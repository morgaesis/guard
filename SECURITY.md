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
  running with `--no-llm` and no static policy)
- Third-party tools invoked by approved commands
- SSH transport brokering, scoped or ephemeral SSH endpoints, file staging, and
  file-content inspection outside the protocol proxy model
