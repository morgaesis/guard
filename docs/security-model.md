# Security model

Guard assumes the agent can be mistaken, misaligned, or compromised. The daemon
is the trusted broker. Security depends on the agent being unable to read the
daemon's credentials or reach protected upstreams by another path.

## Trust boundaries

The operator controls daemon startup, policy, verb and grant catalogs, secret
storage, listener ACLs, and deployment isolation. The evaluator judges command
or API intent inside those deterministic limits. The agent controls requests
and project files.

The central bypass-prevention invariant is daemon-held upstream credentials.
API tokens, upstream kubeconfigs, and secret-store values belong to the daemon
principal and enter only protocol brokers or caller-specific execution. The
shared fixed child receives no Guard-managed credentials. Operators keep
independent credentials inaccessible to it. Brokered clients receive only the
local Guard endpoint and scoped Guard authority.

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

Trusting the evaluator's judgment is a design position. Safe mode gives an
agent broad maintenance authority so a daemon can hold wide host access and
remain useful for local debugging and administration without an operator in
the loop. A wrong allow is an instruction defect: the correction is the mode
prompt, an operator prompt supplement, the verb catalog, or a regression
case - never routine holds or a stripped-down daemon. Frequent holds train
operators to approve reflexively, which is worse than a well-instructed
evaluator. Holds are reserved for the genuinely irreversible tail.

The safe-mode envelope is visible, bounded, recoverable: a mutation is
approvable when its complete effect is stated in the command text, its
targets are enumerable from the text, and routine means undo it. Execution
whose effects are defined in files, remote content, or tool state -
configuration-management applies, infrastructure-as-code, chart releases,
opaque scripts - fails visibility by construction and is denied toward the
grant escalation path. Tools without a built-in executable authority profile
are unevaluable, not implicitly trusted. Prompt supplements can improve
evaluator semantics inside an existing profile but cannot authorize an
unprofiled executable.

The profile boundary is a deterministic floor under consequence gating, not
prompt compliance alone. Fixed-identity kubectl executes only with an immutable
kubeconfig matching an active Guard proxy. Ansible and Helm are denied because
their mutable profile state cannot safely cross identities. Caller identity
denies all three typed profile tools because it has no immutable profile
snapshot. Evaluator approval, typed verbs, access approval, and replay cannot
soften these process-admission rules. Unprofiled carriers such as Terraform and
Make remain denied. An evaluator deny is never softened, and readonly and
paranoid modes are unchanged.

Authorized execution uses a positive executable-profile registry. Shells,
language runtimes, generic command-dispatch tools, and every unknown binary
lack a profile. Verb catalog validation, hold creation, containment arming, and
process admission reject unprofiled binaries for every authority source.
Package reviewed logic as a profiled direct executable so Guard can fingerprint
the complete primary artifact.

Only commands with a built-in closed authority grammar and a mode-compatible
profile execute under evaluator, verb, approval, or persisted-control authority.
The executable set consists of fixed-identity active-proxy kubectl commands,
literal non-starting `systemctl` operations, and an explicit set of primary-only
system utilities. Structured Ansible and Helm grammars support classification
but do not authorize process creation in either identity mode. Caller-mode
kubectl is likewise denied. Unknown executables, SSH, file-testing utilities,
wrappers, and tools with implicit configuration or program files fail before
process start. Each frozen command stores a versioned authority plan containing
its typed or raw provenance, closed profile, normalized command digest, and
whether secondary PATH discovery exists. Replay regenerates that plan under
current code and requires exact equality. Command-family classification
normalizes Windows executable spelling independently of the host-specific
executable identity used for process lookup.

Session overlays intentionally expand baseline evaluator or readonly coverage
inside activated verb regions. This gives a short-lived agent bounded mutation
authority without changing the global posture. The exact session revision and
coverage snapshot bind any hold or provisional. Outside an activated region,
an access-managed session is inert and the command follows baseline policy,
regardless of whether the client or daemon attached the internal session token.

## Execution and credential isolation

Approved commands may receive the caller's canonical working directory while
Guard selects a clean environment and either a fixed child identity or the
authenticated caller identity. Static coverage accepts a caller working directory
only when its coverage cell binds that exact directory and Guard holds the
recursively validated tree for the child lifetime. Guard resolves the primary
executable to a canonical absolute path and retains it for the child lifetime.
Typed tools accept injected environment only through a closed authority schema,
receive the canonical form of their retained server-owned PATH directories, and
retain every direct custom-directory entry and executable link target found
there. Missing PATH entries are removed before spawn. Primary-only and
`systemctl` profiles receive no child PATH; profiles that dispatch subordinate
executables retain only canonical operator-controlled directories. Endpoint,
remote identity, signing-key, transport, strategy, plugin, and backend selectors
are operator-authored literals or finite enumerated sets.
Caller startup variables and SSH credentials are not trusted inputs in fixed
mode. A fixed-child kubeconfig is valid only when its entire schema, endpoint,
certificate authority, and generated transport bearer match an active Guard
proxy. Existing Ansible and Helm profiles are unavailable in fixed mode, and
their commands are denied before spawn. Caller mode also denies Ansible, Helm,
and kubectl because mutable profile discovery is not an immutable execution
snapshot.
Credential-bearing fixed-mode profile inputs fail closed. Protected typed tools
do not inherit the daemon's working directory. Guard preserves argv, exit
behavior, and tool semantics for admitted commands.

The environment floor and disabled kubectl shadow dispatch apply to evaluator
approvals and exact replays as well as typed verb coverage.
Authority-bearing scalar environment values require a selected typed cell that
explicitly covers the value; a surviving verb name is not that capability.

Secret values are resolved after authorization only for caller-specific scalar
delivery. Environment delivery clears the child environment first. Fixed-mode
per-run bindings, tool-config secrets, credential-authority environment, and
temporary read grants fail before spawn. Secret-file delivery is unavailable
because neither a shared child UID nor caller ownership provides an isolated
daemon-to-child file boundary. Holds store names and installation-keyed HMACs, never secret
values. The HMAC key lives outside SQLite in the private state directory, so a
copied database is not a standalone offline guessing oracle. Audit and session
history store secret names only. Output redaction covers exact resolved values
and credential-shaped text.

Execution identity and credential delivery have different compromise bounds:

| Context | Intended use | Compromise bound |
|---|---|---|
| Dedicated child identity | Default Unix identity for commands without Guard-managed credentials | A child cannot read daemon state, per-run credentials, tool-config credentials, or temporary read-grant ACLs. Operators keep independent credentials inaccessible to this account. The UID is shared across executions and is not a process sandbox. |
| Per-caller child identity | Root Unix socket deployments using `--exec-as-caller` | The child receives the authenticated caller's filesystem authority and may receive caller-scoped scalar secrets. Typed Ansible, Helm, and kubectl profiles are denied. TCP, API proxying, fixed-child credential bindings, and secret-file delivery are unavailable in this mode. |
| Windows | Named-pipe policy, access administration, and inspection | Local process execution and API proxying fail closed because no distinct worker identity or secure client-authority handoff is available. |

Guard has no general scoped SSH credential endpoint. Brokered SSH-using tools
receive no Guard-managed SSH credential in fixed mode or use caller-owned authority under
`--exec-as-caller`. Daemon-held SSH requires a separately authenticated stream
protocol, destination and forwarding constraints, revocation semantics, and an
independent security review.

The API proxy injects the endpoint upstream credential only after the request is
allowed. It strips authentication headers, redacts protocol-classified secret
responses, rejects uninspectable sensitive streams, and binds rollback to the
exact endpoint and credential identity. The public access workflow exports no
API bearer.

## Principals and admin authority

Unix sockets authenticate caller uid through peer credentials. Windows named
pipes authenticate caller SID. The stock Windows DACL admits authenticated local
users, then Guard isolates their authority by SID; it does not restrict the pipe
to one configured client SID. On Unix, operator authority for holds,
provisionals, saved grants, verbs, and detailed status is the admin bearer
token: the token reaches the daemon through stdin at startup and is presented
only by the root-owned operator wrapper, so a brokered dedicated child holds no
operator authority. On Windows, kernel-authenticated local
SYSTEM is the packaged operator principal. The installer runs operator commands
in transient SYSTEM tasks. Local process execution is unavailable because the
service has no distinct worker identity. The service SID receives no operator
exception. Packaged service mode
requires a named pipe and rejects an admin bearer and TCP listener. A foreground
Windows server can use an explicitly configured admin bearer instead and gives
SYSTEM no implicit operator authority.

Windows clients request identification-level named-pipe security. The daemon
can authenticate the client SID, but a process that wins the pipe name cannot
impersonate a privileged Guard client.

On Unix, the local socket is private to the daemon unless an operator configures
a group, in which case it is group-readable and group-writable. SQLite state and
sidecars are owner-only regular files beneath private, non-symlinked state
directories. Socket membership controls who may submit requests; session and
uid authorization remain separate boundaries.

Loopback TCP carries execution and admin bearer tokens but no kernel-authenticated
local principal. It therefore refuses consequence gating and per-principal
credential injection. The execution token cannot perform admin RPCs.

Every command-access session is bound at creation to the authenticated principal
that requested it, represented by a Unix uid or Windows SID. On every local path
that consumes its authority, the daemon requires the requesting peer's
kernel-authenticated principal to equal the session owner. A different local
peer in the socket group that learns or replays a request reference or bearer is
refused with a distinct `session principal mismatch` audit reason. The daemon
operator principal retains cross-session inspection and administration; a
non-owner non-operator peer sees only its own requests and sessions.

Startup rejects sessions without a verifiable owner and matching approved
access-request provenance. Every active command session has a principal-bound
request and an explicit use policy.

Access-managed sessions are command-only authority. Guard refuses brokered
kubeconfig issuance and API-proxy resolution for them, so one-time and N-use
command admissions cannot become reusable API credentials.

## Holds, rollback, and autonomy

Reversible work executes immediately. Recoverable work uses a forward, verify,
and revert envelope. Irreversible, uncertain, or connectivity-unsafe work holds
before execution. A hold freezes the complete authority and execution snapshot;
approval cannot pick up later catalog or secret changes. The snapshot binds the
resolved executable, tool registry, ordered executable-search directories,
operator artifacts, and complete effective child environment. Persisted state
contains secret references and installation-keyed value HMACs, never secret values or
ephemeral secret-file paths. A caller-specific replay resolves each scalar
secret once, validates that in-memory snapshot, and carries the same values
through process start without a second secret-store read.

Containment freezes independent process and secret authority for the rollback
and confirmation-check commands before the forward command starts. Each replay
resolves its referenced secrets once, validates those values and every bound
process artifact, and carries the validated in-memory values through spawn.
Rows without these bindings cannot execute a command-shaped check or rollback.

A viable rollback chain enables unattended operation. Guard does not assume
rollback is safe when the forward action can sever its control path. Persisted
state survives restart. Startup reconstructs and revalidates the frozen
process, environment, secret, and artifact authority for both the check and
rollback before re-arming a completed forward command. Missing or changed
bindings and interrupted outcomes require an explicit operator decision.

## Process lifetime

On Unix, brokered children lead dedicated process groups. A streaming client
disconnect, request cancellation, daemon shutdown, or SIGTERM terminates the
group. A buffered non-streaming request is daemon-owned after admission and runs
to completion if its client disconnects; its bounded result remains available
through the durable hold or provisional record when one exists. Choose streaming
execution when disconnect means cancel, and buffered execution when completion
must not depend on the client connection. A child that deliberately detaches
through an external service manager or new session can outlive the request.
Windows service stop and cancellation terminate tracked direct children.

Process ownership limits accidental or ordinary orphaning. It is not a kernel
sandbox against a child that has authority to create an independent service.

## Audit and state

The daemon emits a dedicated structured audit stream independent of ordinary
diagnostic filtering. Records include principal, session fingerprint, decision
source, matched coverage, consequence route, execution result, and safe secret
names. Ship that stream through the service manager or logging stack.

SQLite stores durable saved grants, sessions, requests, holds, provisionals,
read grants, and bounded interaction history. It is not a replacement for the
audit stream. Protect the database, installation HMAC key, and catalog files
from the agent principal.

Behavioral limits suspend sessions on observable denial or hold patterns. They
reduce repeated abuse and evaluator spend amplification but cannot prove a
multi-step trajectory is benign.

## API and SSH boundaries

The API proxy mediates request-response protocols with typed parsing, bounded
bodies, response inspection, and protocol-specific rollback. Named endpoints
share one generic gate while retaining separate listener, policy, credential,
coverage, and revert identities.

Raw SSH is a bidirectional byte stream with forwarding, subsystems, interactive
shells, and nested transports. The fixed child carries no daemon-held SSH
credentials, and `--exec-as-caller` uses caller-owned authority. A daemon-held
raw stream adapter requires its own protocol design and security review rather
than being treated as a generic HTTP proxy configuration.

## Practical limits

Guard can bound visible argv, typed API operations, session lifetime, fanout,
credential selection, consequence, and observable behavior. It cannot infer all
effects hidden in arbitrary local files or remote program behavior. A
shell-capable tool or API extension may have wider effects than its top-level
invocation suggests.

Use protocol-level mediation where request semantics are available and native
read-only identities where the upstream provides them. Keep irreversible and
control-path-changing operations behind holds unless their rollback chain is
independently viable.
