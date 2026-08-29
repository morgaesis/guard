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

The public authority workflow has two inputs:

- **Policy** defines global evaluator behavior and hard boundaries.
- **Access intent** describes work in prose. The resolver reduces it to typed
  coverage and requests only missing authority for the authenticated principal.

Verbs, saved grants, sessions, requests, and holds are internal authority
objects. Operator-authored policy and verb catalogs remain the source of hard
invariants, sticky boundaries, credential plans, and verified revert envelopes.

A coverage cell has an explicit action and axes. It is silent outside those
axes. This prevents an instruction such as "allow kubectl pod reads" from
creating complement denies that block unrelated read-only commands.

## Command flow

```text
agent -> client or shim -> authenticated daemon -> resolver -> evaluator/gate
      -> credential binding -> child process -> redaction -> client
```

The daemon authenticates a Unix uid, Windows SID, or TCP bearer before reading
request authority. Execute requests use a versioned envelope with an explicit
feature set. A supplied working directory is canonical caller filesystem
context. An omitted directory becomes a fixed operating-system root before
evaluation and persistence. The daemon validates the wire contract, argv,
working directory, session, injections, and binary floor before semantic
evaluation. Raw commands reverse-match all verb cells. The
resolver combines applicable global and session coverage, then routes a miss or
conflict to the evaluator when policy permits.

The execution snapshot contains canonical argv, working directory, principal,
session revision, matched coverage, credential and execution plan, consequence,
the selected fixed-user or caller mode, Unix user and group identity including
sorted supplementary groups, and secret-name bindings with installation-keyed
value HMACs. A hold freezes that snapshot.
Approval cannot adopt later grant, catalog, policy, environment, or secret
changes.

Opaque interpreter and command-dispatch binaries cannot enter an authorized
execution path. The catalog and process boundary share one classifier, so a
typed verb, hold, or restored row cannot bypass this restriction. Reviewed
logic runs as a direct executable whose primary artifact is fingerprinted.
Primary-only executables use a positive registry and closed option grammar.
Read-only file operands require canonical absolute paths and exact typed
authority. Dispatchers such as `ip` and path-only mutators such as `rm` and
`touch` remain outside delayed execution authority because their complete
secondary authority cannot be pinned through their argv interface.

Approved children receive a daemon-constructed clean environment and execute
as either the configured fixed child identity or the authenticated Unix caller.
Caller-scoped scalar secret bindings are available
only in caller mode; daemon-held upstream credentials remain behind API
proxies. Fixed mode uses an explicit inert-variable schema and admits kubectl
only through an immutable kubeconfig matching an active Guard proxy. Fixed mode
rejects Ansible and Helm because their mutable profile state cannot safely cross
identities. Caller mode rejects Ansible, Helm, and kubectl because it has no
immutable typed profile snapshot. Commands start from the fixed operating-system
root unless a coverage cell binds one exact canonical caller working directory.
Guard retains authorized caller paths for the child lifetime, and Unix authority
artifacts must be immutable to the actual child uid. Typed environment bindings
require an explicit environment capability. Guard does not rewrite command
semantics, stage input files, or interpret tool-native projects. Child stdout
and stderr are redacted before crossing the daemon boundary.

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

## Access negotiation

An authenticated local principal submits prose without presenting a session.
The daemon reuses matching typed verbs, subtracts baseline and already active
authority, and persists one principal-bound request for the missing delta.
Proposed generated coverage is inert, untrusted, and non-baseline. Approval
promotes the exact reviewed matcher to trusted session coverage, stores it in
the durable request, and leaves the operator-authored catalog unchanged. The
daemon derives consequence locally: recognized read-only shapes may execute,
while unknown or mutating generated shapes remain irreversible holds.
Approval creates or reuses one access-managed session for that principal. A bounded use is committed to SQLite
under the session write lock before the admitted snapshot can spawn, so retries,
concurrency, spawn failure, restart, expiry, revocation, history, and audit see
one durable remaining-use count for the exact approved request. Independent
requests retain separate scope and accounting inside the principal's session.

Consequence holds use their immutable hold identifier as the access request and
accept only one-time approval because the reviewed snapshot executes once.
This keeps approval bound to the reviewed argv, principal, catalog revision,
credential hashes, and revert evidence. `guard access list` and `show` project
requests, holds, and sessions without exposing bearer tokens.
Access-managed sessions authorize brokered command verbs and cannot mint or use
reusable API-proxy credentials.

## Consequence gate

`src/gating/mod.rs::decide_gate` is shared by commands and API requests.
Reversible work executes immediately. Recoverable work arms a provisional with
rollback. Irreversible, high-risk, unclassified, or unsafe work creates a hold.
Classification can only raise the gate.

Command containment assesses the forward command, rollback, confirmation check,
deadline, and control path together. A viable chain runs autonomously. A chain
that may sever the authority needed to verify or revert holds. Arming captures
separate process and secret authority for the rollback and confirmation check
before the forward command starts.

Only commands with a closed delayed-execution grammar can enter a hold or a
command-shaped containment control. Fixed-identity kubectl commands bind the
immutable active-proxy profile. Literal non-starting `systemctl` operations,
direct utilities without secondary authority, and the CTF child contract use
narrow closed executable grammars. Profile-dependent Ansible and Helm commands,
and all caller-mode typed profile tools, fail before process creation.
Unknown executables, SSH, wrappers, interpreters, and implicit program or
configuration loaders fail before durable command authority is created. The
frozen versioned plan binds typed or raw provenance, profile, normalized command
digest, and secondary PATH behavior. Replay must regenerate the same plan.

Holds and provisionals persist in SQLite. Startup re-arms a completed forward
command after validating its frozen authority, then observes a grace before due
rollback processing. Interrupted or authority-invalid rows require an operator
decision. A due command rollback uses the frozen working directory, principal,
credential bindings, executable, environment, search path, and operator
artifacts. A due HTTP rollback uses an exact live endpoint,
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

The operator-generated client configuration contains the loopback endpoint and
local CA, but no Guard or upstream credential. Requests from this client are
unattributed and rely on the listener's trusted local or single-tenant boundary.
The endpoint credential is injected only after protocol, policy, evaluator, and
consequence checks and is never returned to the client.

Protocol hard-denies reject uninspectable or credential-minting surfaces before
policy. Explicit policy actions are `allow`, `deny`, `hold`, and `evaluate`.
Allowed secret-bearing reads are redacted according to protocol classification,
regardless of policy wording. Unsafe redirects, encodings, response headers,
compression, and uninspectable secret bodies fail closed.

Generated API coverage binds endpoint, attribution when present, operation,
namespace, value-free body shape, evaluator regime, and expiry. Value-bearing
mutations remain evaluator-routed. Global concurrency, endpoint and attribution
token buckets, error circuits, and a reserved evaluator slot bound amplification.

## Principal and credential model

Local transports use kernel-authenticated peer identity. Unix and foreground
Windows servers use an explicitly configured admin bearer for operator
authority. The packaged Windows service rejects an admin bearer and accepts
only kernel-authenticated local SYSTEM on its named pipe. The daemon's own uid
or Windows service SID grants nothing, so a brokered child cannot approve
holds, confirm provisionals, change grants, edit verbs, or inspect daemon
secret ownership.

Each command-access session is bound automatically to the authenticated
requester. Every local path that consumes its authority requires the requesting
peer's kernel-read principal to equal that owner, so a leaked or replayed
request reference or internal bearer is unusable by a different local peer. The
operator principal is exempt and administers all sessions. Startup rejects any
active session without an authenticated owner and matching approved-request
provenance.

TCP has no peer principal. It uses separate execution and admin bearers and
refuses consequence gating and per-principal secret injection.

Fixed-identity and API-proxy deployments use daemon-held credentials as the
bypass-prevention invariant. The agent has no usable kubeconfig, API token, or
direct path to a protected upstream. Fixed-mode local commands receive no
Guard-managed credentials. Operators keep independent credentials inaccessible
to the child account. `--exec-as-caller` deliberately uses the authenticated caller's
filesystem and caller-owned scalar credential authority and therefore provides
a weaker credential boundary. It does not admit Ansible, Helm, or kubectl
without an immutable typed profile snapshot. Secret values resolve after
authorization and remain absent from requests, evaluator input, state, audit,
and history. Frozen
holds bind value HMACs under an installation key stored outside SQLite, so
approval fails if a referenced value changes without making a copied database a
standalone guessing oracle.

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
