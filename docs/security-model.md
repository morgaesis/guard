# Security model

Guard assumes the agent can be mistaken, misaligned, or compromised. The daemon
is the trusted broker. Security depends on the agent being unable to read the
daemon's credentials or reach protected upstreams by another path.

## Trust boundaries

The operator controls daemon startup, policy, verb and grant catalogs, secret
storage, listener ACLs, and deployment isolation. The evaluator judges command
or API intent inside those deterministic limits. The agent controls requests,
project files, and its own session bearer.

The central bypass-prevention invariant is daemon-held credentials. SSH keys,
SSH agent sockets, kubeconfigs, API tokens, and secret files belong to the daemon
principal. Brokered clients receive only the local Guard endpoint and scoped
Guard session authority.

Guard is not a sandbox. If the agent can read the same credential, connect to
the upstream directly, modify daemon policy, replace the daemon binary, or gain
the daemon principal, it can bypass the broker. Operating-system isolation,
network policy, tool-native RBAC, backups, and service supervision remain part
of the deployment.

## Deterministic controls and evaluator judgment

Hard controls run independently of LLM approval: authenticated peer identity,
binary limits, request validation, credential-plan binding, protocol
hard-denies, explicit operator policy, session expiry and suspension,
consequence floors, immutable hold snapshots, and redaction.

The evaluator handles semantic intent and novel requests. It is a useful policy
component, not a proof system. Typed verbs reduce repeated semantic decisions by
turning evidenced regions into deterministic argv or API coverage. Generated
coverage remains regime-stamped, bounded, and unable to override explicit
operator boundaries.

Session overlays intentionally expand baseline evaluator or readonly coverage
inside activated verb regions. This gives a short-lived agent bounded mutation
authority without changing the global posture. The exact session revision and
coverage snapshot bind any hold or provisional.

## Execution and credential isolation

Approved commands receive the caller's canonical working directory but retain
the daemon's clean environment, identity, SSH configuration, agent socket, and
secret bindings. Caller startup variables and SSH credentials are not trusted
inputs. Guard preserves argv, exit behavior, and tool semantics.

Secret values are resolved after authorization. Environment delivery clears the
child environment first. Secret-file delivery creates a daemon-only lease for
the child lifetime. Holds store names and salted value hashes. Audit and session
history store secret names only. Output redaction covers exact resolved values
and credential-shaped text.

The API proxy consumes a Guard session bearer and injects the endpoint upstream
credential only after the request is allowed. It strips authentication headers,
redacts protocol-classified secret responses, rejects uninspectable sensitive
streams, and binds rollback to the exact endpoint and credential identity.

## Principals and admin authority

Unix sockets authenticate caller uid through peer credentials. Windows named
pipes authenticate caller SID and use a restricted pipe ACL. The daemon's own
uid or SID is the operator principal for holds, provisionals, saved grants,
verbs, and detailed status.

On Unix, the local socket is private to the daemon unless an operator configures
a group, in which case it is group-readable and group-writable. SQLite state and
sidecars are owner-only regular files beneath private, non-symlinked state
directories. Socket membership controls who may submit requests; session and
uid authorization remain separate boundaries.

Loopback TCP carries execution and admin bearer tokens but no kernel-authenticated
local principal. It therefore refuses consequence gating and per-principal
credential injection. The execution token cannot perform admin RPCs.

Every session is bound at creation to the authenticated principal it is issued
for (a Unix uid or Windows SID). On every local path that consumes a session's
authority - execution, appeals, kubeconfig issuance, batch evaluation, and
self-inspection - the daemon requires the requesting peer's kernel-authenticated
principal to equal the session owner, using the identity it reads itself rather
than any client-supplied value. A different local peer in the socket group that
learns or replays a handle is refused with a distinct `session principal
mismatch` audit reason. The daemon (operator) principal is exempt and retains
cross-session inspection and administration; a non-owner non-operator peer sees
only its own sessions. The operator names the owning principal when issuing a
session for an agent that runs under a different uid.

A session that predates principal binding has no verifiable owner and is refused
fail-closed for execution and API use with a `session predates principal
binding` reason; the operator reissues or revokes it.

Session tokens remain bearer authority on the loopback API-proxy transport,
which carries no kernel-authenticated principal: ownership is bound there at
issuance (brokered kubeconfig issuance requires the owning local peer) and
cannot be re-verified per request. Guard fingerprints tokens in logs and
history. Expiry, revocation, suspension, and saved-grant revision checks occur
before execution or API forwarding. Treat a leaked session token used over the
API proxy as an active grant until revoked or expired.

## Holds, rollback, and autonomy

Reversible work executes immediately. Recoverable work uses a forward, verify,
and revert envelope. Irreversible, uncertain, or connectivity-unsafe work holds
before execution. A hold freezes the complete authority and execution snapshot;
approval cannot pick up later catalog or secret changes.

A viable rollback chain enables unattended operation. Guard does not assume
rollback is safe when the forward action can sever its control path. Persisted
state survives restart, but startup does not fire overdue rollback commands in
an unverified environment. These operations require an explicit decision.

## Process lifetime

On Unix, brokered children lead dedicated process groups. Streaming disconnect,
request cancellation, daemon shutdown, or SIGTERM terminates the group. A child
that deliberately detaches through an external service manager or new session
can outlive the request. Windows service stop and cancellation terminate tracked
direct children.

Process ownership limits accidental or ordinary orphaning. It is not a kernel
sandbox against a child that has authority to create an independent service.

## Audit and state

The daemon emits a dedicated structured audit stream independent of ordinary
diagnostic filtering. Records include principal, session fingerprint, decision
source, matched coverage, consequence route, execution result, and safe secret
names. Ship that stream through the service manager or logging stack.

SQLite stores durable saved grants, sessions, requests, holds, provisionals,
read grants, and bounded interaction history. It is not a replacement for the
audit stream. Protect both the database and catalog files from the agent
principal.

Behavioral limits suspend sessions on observable denial or hold patterns. They
reduce repeated abuse and evaluator spend amplification but cannot prove a
multi-step trajectory is benign.

## API and SSH boundaries

The API proxy mediates request-response protocols with typed parsing, bounded
bodies, response inspection, and protocol-specific rollback. Named endpoints
share one generic gate while retaining separate listener, policy, credential,
coverage, and revert identities.

Raw SSH is a bidirectional byte stream with forwarding, subsystems, interactive
shells, and nested transports. Guard brokers ordinary `ssh` commands by
running the SSH client with daemon-held configuration and credentials. That
does not make Guard an SSH transport proxy. A raw stream adapter requires its
own protocol design and security review rather than being treated as a generic
HTTP proxy configuration.

## Practical limits

Guard can bound visible argv, typed API operations, session lifetime, fanout,
credential selection, consequence, and observable behavior. It cannot infer all
effects hidden in arbitrary local files or remote program behavior. An approved
Ansible playbook, Helm chart, shell-capable tool, or API extension may have wider
effects than its top-level invocation suggests.

Use narrow verbs and short grants for opaque file-driven tools, protocol-level
mediation where request semantics are available, and native read-only identities
where the upstream provides them. Keep irreversible and control-path-changing
operations behind holds unless their rollback chain is independently viable.
