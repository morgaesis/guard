# Roadmap

The roadmap contains open engineering goals only. Deployed behavior is described
in [README.md](README.md), [ARCHITECTURE.md](ARCHITECTURE.md), and [`docs/`](docs/).

## Coverage assurance

- Derive neighboring API coverage cells and require evaluator boundary probes
  before widening automatically generated regions.
- Bind verb-rendered secret material as completely as per-run secret injections,
  so a held verb invocation fails closed when any referenced value changes.
- Add property and mutation tests for resolver specificity, incompatible plans,
  session overlays, sticky operator cells, and generated-coverage expiry.

## Filesystem mediation

- Add a Linux seccomp user-notification supervisor for path-aware file mutation
  gates inside approved tools.
- Add an overlay changeset envelope that runs a tool against copy-on-write state
  and commits or discards the resulting filesystem diff as one unit.

## Protocol breadth

- Define a separately reviewed raw SSH stream adapter if interactive shells,
  subsystems, or forwarding become required beyond brokered `ssh` commands.
- Promote protocol examples to supported integrations only after protocol-specific
  policy, credential, response, and rollback audits.
- Add server-initiated MCP streaming when an agent runtime requires output beyond
  the request-response HTTP transport.

## Operations

- Report verb-catalog content hash and change time, queue depths, generated-store
  counts, and client/server version mismatch in `guard status`.
- Add cross-daemon catalog and saved-grant drift comparison without exposing
  authority or credential values.
- Expand fault-injection coverage for restart recovery, unavailable rollback
  endpoints, notification failure, and evaluator rate circuits.
