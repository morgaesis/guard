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

Out of scope:

- Compromise of the LLM provider or model itself
- Operator misconfiguration that disables documented guardrails (e.g.
  running with `--no-llm` and no static policy)
- Third-party tools invoked by approved commands
