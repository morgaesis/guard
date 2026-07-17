# Architecture

Guard centralizes policy evaluation, authorization resolution, credential
binding, execution, consequence routing, and audit in one privileged daemon.
Clients and integrations submit structured work to that daemon rather than
reimplementing approval logic.

## Source of truth

1. `src/server/` owns the privileged protocol, command execution, session
   resolution, admin authorization, holds, provisionals, and audit events.
2. `src/evaluate/` owns evaluator configuration, prompting, caching, retries,
   and structured verdict parsing.
3. `src/gating/` owns consequence routing, typed verbs, coverage composition,
   generated deny shapes, generated allows, and scoped read grants.
4. `src/proxy/` owns protocol parsing, API policy, TLS termination, upstream
   credentials, response filtering, snapshots, and HTTP rollback plans.
5. `src/session.rs`, `src/grant_profile.rs`, and `src/session_store.rs` own live
   sessions, saved grants, grant requests, immutable authority snapshots,
   behavior limits, and SQLite persistence.

6. `src/secrets/` and `src/redact.rs` own secret backends, per-principal names,
   value resolution, and output redaction.
7. `src/daemon_client.rs`, `src/cli_client.rs`, `src/mcp.rs`, and `src/shim.rs`
   expose the daemon without adding another authorization path.

Operator behavior is documented in [README.md](README.md),
[DEPLOYMENT.md](DEPLOYMENT.md), and [`docs/`](docs/).

## Authorization vocabulary

The public model has three nouns:

- **Policy** defines global evaluator behavior and hard boundaries.
- **Verb** defines typed operation coverage and an execution plan.
- **Grant** activates or expands verbs for a reusable scope or live session.

Legacy profiles and unambiguous command patterns are migration inputs. They
compile into saved grants and typed coverage. Ambiguous patterns fail loading.
They do not remain an independent authority system.

A coverage cell has an explicit action and axes. It is silent outside those
axes. This prevents an instruction such as "allow Ansible check mode" from
creating complement denies that block unrelated read-only commands.

## Command flow

```text
agent -> client or shim -> authenticated daemon -> resolver -> evaluator/gate
      -> credential binding -> child process -> redaction -> client
```

The daemon authenticates a Unix uid, Windows SID, or TCP bearer before reading
request authority. It validates argv, working directory, session, injections,
and binary floor before semantic evaluation. Raw commands reverse-match all
verb cells. The resolver combines applicable global and session coverage, then
routes a miss or conflict to the evaluator when policy permits.

The execution snapshot contains canonical argv, working directory, principal,
session revision, matched coverage, credential and execution plan, consequence,
and secret-name/value bindings. A hold freezes that snapshot. Approval cannot
adopt later grant, catalog, policy, environment, or secret changes.

Approved children receive the caller's canonical working directory but the
daemon's clean environment, identity, SSH context, and secret bindings. Guard
does not rewrite command semantics, stage input files, or interpret tool-native
projects. Child stdout and stderr are redacted before crossing the daemon
boundary.

## Resolver order

Hard invariants run first and remain absolute. Inside the verb resolver:

1. Collect every matching coverage cell in canonical verb and cell order.
2. Apply session cells over matching baseline coverage only in activated regions.
3. Preserve sticky cells and exact operator override-marker requirements.
4. Prefer more specific cells inside one scope.
5. Compose compatible authorization with conservative consequence.
6. Send equally specific incompatible plans to the evaluator in one packet.
7. Hold when no single credential, execution, or rollback plan remains.

Name order never chooses authority. Generated global coverage cannot override an
explicit operator deny. A live session evaluates past matching generated global
coverage under its own intent, while policy and protocol hard-denies remain
floors.

The evaluator cache keys immutable policy, saved-grant and session revisions,
current session state, coverage, markers, conflict packet, and request. Grant
edit, regeneration, amendment, suspension, expiry, revocation, or coverage
change invalidates affected cache authority.

## Consequence gate

`src/gating/mod.rs::decide_gate` is shared by commands and API requests.
Reversible work executes immediately. Recoverable work arms a provisional with
rollback. Irreversible, high-risk, unclassified, or unsafe work creates a hold.
Classification can only raise the gate.

Command containment assesses the forward command, rollback, confirmation check,
deadline, and control path together. A viable chain runs autonomously. A chain
that may sever the authority needed to verify or revert holds.

Holds and provisionals persist in SQLite. Startup re-arms a completed forward
command after validating its frozen authority, then observes a grace before due
rollback processing. Interrupted or authority-invalid rows require an operator
decision. A due command rollback uses the frozen working directory, principal,
and credential bindings. A due HTTP rollback uses an exact live endpoint,
protocol, canonical target, session, and upstream credential identity match.

## API flow

```text
API client -> loopback TLS listener -> protocol parser -> policy/resolver
           -> evaluator/consequence gate -> daemon credential -> upstream
           -> protocol response filter -> client
```

`src/proxy/protocol.rs` defines the protocol plug-in boundary. Kubernetes is the
reference implementation. GitHub and Vercel adapters exercise the same typed
policy, consequence, response-redaction, and rollback interfaces.

`--api-endpoints` creates multiple named listeners. Endpoint identity owns the
protocol, policy, mode, upstream, credential reference, local client output,
generated coverage, history, and rollback registration. Concurrent listeners
using one protocol cannot cross credentials or reverts.

The client sends `Authorization: Bearer <Guard session>` or the compatibility
header `X-Guard-Session`. The proxy validates one live session, strips the
client credential, and binds only its fingerprint and intent to the request.
Immediately before forwarding, it revalidates expiry, revocation, suspension,
and immutable authority. The endpoint credential is injected only after these
checks and is never returned to the client.

Protocol hard-denies reject uninspectable or credential-minting surfaces before
policy. Explicit policy actions are `allow`, `deny`, `hold`, and `evaluate`.
Allowed secret-bearing reads are redacted according to protocol classification,
regardless of policy wording. Unsafe redirects, encodings, response headers,
compression, and uninspectable secret bodies fail closed.

Generated API coverage binds endpoint, session fingerprint, operation,
namespace, value-free body shape, evaluator regime, and expiry. Value-bearing
mutations remain evaluator-routed. Global concurrency, endpoint/session token
buckets, error circuits, and a session reserve bound evaluator amplification.

## Principal and credential model

Local transports use kernel-authenticated peer identity. The daemon's own uid or
SID is the operator principal. Agents run under another principal and cannot
approve holds, confirm provisionals, change grants, edit verbs, or inspect daemon
secret ownership.

TCP has no peer principal. It uses separate execution and admin bearers and
refuses consequence gating and per-principal secret injection.

Daemon-held credentials are the bypass-prevention invariant. The agent has no
usable SSH key, SSH socket, kubeconfig, API token, or direct upstream path.
Secret values resolve after authorization and remain absent from requests,
evaluator input, state, audit, and history. Frozen holds bind salted value hashes
so approval fails if a referenced value changes.

## Persistence and audit

SQLite is the durable source for saved grants, live and historical sessions,
grant requests, holds, provisionals, scoped read grants, and bounded interaction
history. Schema versioning rejects newer unsupported databases. Retention and
compaction bound historical storage.

The audit source of truth is an append-only, hash-chained JSONL file in the
state directory: every audit event is a typed record carrying a sequence
number and the SHA-256 of the previous record, so truncation, edits, or
reordering are detectable (`guard audit verify`, `guard audit tail`). The
stderr `[AUDIT]` lines on the `guard::audit` target are a projection of the
same typed events and remain active independently of diagnostic filtering.
Auditable actions fail closed when the file cannot be appended. SQLite
supports state recovery and session queries but does not replace journald,
Windows service logging, or remote log shipping.

## Evaluator boundary

Mode-specific prompts live in `config/`. The evaluator receives redacted command
or typed API context and returns a structured allow or deny verdict plus risk and
reversibility. Retry and fallback behavior is bounded; errors are not cached and
fail closed.

Global and per-principal command admission bounds handler and evaluator
concurrency. Per-principal token buckets and error circuits bound evaluator
spend and failure amplification without charging deterministic verb paths.

The evaluator reads attacker-controlled request text and is not a deterministic
security mechanism. Prompts include specific anti-injection guidance, while
binary floors, typed verbs, protocol hard-denies, explicit policy, immutable
snapshots, credential isolation, and consequence routing remain independent of
model compliance. Prompt changes require the live regression corpus before
release.

## Design constraints

- The daemon is the only policy, credential, execution, and audit boundary.
- Guard is deploy-and-forget by default. Saved grants and verbs absorb routine
  autonomous work; holds are the exception path.
- A viable forward, verify, and revert chain runs autonomously. Operator
  interaction is reserved for absent, conflicting, irreversible, or unsafe
  authority.
- Daemon-held credentials prevent bypass. A deployment that gives the agent the
  same credentials is outside the security model.
- Guard preserves ordinary argv, working directory, exit behavior, and tool
  semantics. It does not reinterpret or stage tool input.
- Coverage cells are silent outside their typed regions. Automatic generation
  cannot create complement denies or operator override markers.
- Session authority can expand baseline readonly or evaluator coverage only in
  activated regions. Hard invariants and explicit operator boundaries remain.
- Notification is an optional bounded exec hook. Delivery success never affects
  a gate decision.
- Behavioral circuits use persisted observable history. They do not claim to
  infer hidden intent or replace per-request evaluation.
- API protocol integrations share the typed resolver and consequence gate while
  retaining endpoint-specific credentials and rollback identity.
- A raw SSH stream adapter is a separate protocol-security boundary. Brokered
  `ssh` command execution does not imply transport-level mediation.
- Human output remains compatible with normal tools. Structured output carries
  decision, coverage, and escalation context for agents.
- The guard binary name is `guard`. Environment variables use the `GUARD_*` prefix. `SSH_GUARD_*` names are not recognized.
