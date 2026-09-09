# API proxy

Command gating cannot see HTTP operations performed inside external
operator/bootstrap clients such as Helm, Terraform providers, k9s, or SDKs.
Guard's API proxy terminates
a local TLS connection, parses each request into a typed operation, applies
policy and evaluator judgment, and re-originates allowed traffic with an
upstream credential held only by the daemon.

Kubernetes is the reference protocol. GitHub and Vercel adapters exercise the
same protocol-independent gate and are example integrations.

## Kubernetes quick start

Provision the dedicated accounts first, using the
[Unix service setup](../DEPLOYMENT.md#unix-service).

```bash
sudo install -d -o root -g root -m 0755 /run/guard
sudo install -o root -g guard-exec -m 0640 /dev/null /run/guard/kubeconfig
sudo guard server start \
  --gate consequence \
  --exec-user guard-exec \
  --kube-proxy 127.0.0.1:8443 \
  --kubeconfig /etc/guard/kubeconfig \
  --api-policy /etc/guard/api-policy.yaml \
  --brokered-kubeconfig-out /run/guard/kubeconfig

sudo -u guard-exec -- env KUBECONFIG=/run/guard/kubeconfig \
  kubectl get pods -n dev
```

The input kubeconfig belongs to the daemon and may contain a bearer token or
client certificate. Exec and auth-provider plugins are rejected. The brokered
kubeconfig points only to Guard, trusts its local CA, and contains a generated
proxy transport bearer rather than an upstream credential. Guard writes it
only to a regular `0640` file owned by the daemon and readable by the fixed
execution account's private group.

Every upstream endpoint uses HTTPS and contains no URL userinfo, query, or
fragment. Guard rejects plaintext endpoints before loading any upstream
credential.

`--brokered-kubeconfig-out` produces transport-authenticated read-only access.
A permissive API policy cannot turn its transport bearer into mutation
authority. Guard does not export caller-scoped session credentials through the
public CLI. Fixed-identity kubectl uses approved typed command verbs and the
active proxy kubeconfig, preserving request-scoped admission counts. Local Helm
execution is denied.

## Client boundary and attribution

The daemon-generated kubeconfig carries one random per-proxy transport
bearer. The proxy consumes it before forwarding and accepts no request without
either that bearer or a live Guard session bearer. The transport bearer can
read policy-permitted objects but cannot create, update, patch, or delete them.
Incoming client authorization is never forwarded to the upstream. A Guard
session authorization header that does not resolve to live internally
integrated state fails closed; the public CLI does not create that state.
Session-attributed mutations carry the session fingerprint and immutable
authority revision into request summaries, audit records, and rollback
envelopes.

Each request also binds the complete API policy and evaluator-intent generation
before classification. A hot reload that changes any policy field or evaluator
intent invalidates every in-flight request before its next upstream operation.
The client submits a fresh request under the new authority.

## Policy

Load a hot-reloaded YAML policy with `--api-policy`; absence is default deny.
[`examples/api-policy.yaml`](../examples/api-policy.yaml) documents the schema.
Rules match typed protocol fields such as operation verb, resource, namespace,
subresource, object name, and request-body metadata. Actions are:

| Action | Behavior |
|---|---|
| `allow` | Route through the consequence floor and forward if eligible. |
| `deny` | Reject without contacting upstream. |
| `hold` | Park in the shared approval queue; without that queue, deny. |
| `evaluate` | Ask the evaluator under policy and live-session intent. |

Explicit policy denies and protocol hard-denies are absolute. A readonly
listener is the default. Every Kubernetes mutation requires a live attributable
session even on an explicitly configured policy-mode listener. Policy `allow`,
operator approval, and evaluator judgment cannot grant transport-bearer-only
mutation authority. Evaluated traffic cannot override those absolute
boundaries.

`names` is an OR-list of case-sensitive globs. For named requests, Guard uses
the path name; for collection creates, it uses `metadata.name` from the request
body. `annotations` and `labels` are key-to-glob maps, and every configured map
entry must match the object-shaped `metadata` carried by the request. The glob
syntax supports `*`, `?`, and character classes such as `[abc]`.

```yaml
rules:
  - verbs: [delete]
    resources: [jobs]
    namespaces: [dev]
    names: ["*-admission*"]
    action: allow

  - verbs: [create]
    resources: [jobs]
    namespaces: [dev]
    names: ["*-admission*"]
    annotations:
      "helm.sh/hook": "pre-*"
    labels:
      "app.kubernetes.io/managed-by": Helm
    action: allow
```

The requesting agent controls object metadata. Annotation and label predicates
are convenience selectors for ephemeral, tool-managed objects, not a trust
boundary. Pair them with narrow `names`, resource, and namespace predicates.
Delete bodies normally carry `DeleteOptions`, not the deleted object's
metadata, so annotation and label predicates do not match deletes. Use a name
predicate for Helm's `before-hook-creation` cleanup. JSON Patch arrays likewise
do not expose object-shaped metadata to these predicates.

Kubernetes interactive subresources (`exec`, `attach`, `portforward`, and
`proxy`), `pods/ephemeralcontainers`, and Secret watches are hard-denied. Writes
to other subresources require an explicit matching subresource rule. Allowed
Secret reads redact values regardless of policy wording, and an unparseable
secret-bearing response fails closed. Raw upgraded streams cannot be inspected,
bounded, or redacted after the protocol upgrade. An operator-approved typed verb
with a fixed noninteractive command shape is the sanctioned path for Kubernetes
container diagnostics.

## Write arbitration

A successful session-attributed read of one named Kubernetes object records its
UID, `resourceVersion`, and a digest of the object state. The observation is
bound to the endpoint, session fingerprint, complete session revision, API
group and version, resource, subresource, namespace, name, and UID. Successful
mutation responses refresh only that same session's observation.
Transport-bearer-only reads, lists, and watches establish no write authority.

Before update, patch, or delete, Guard fetches the live object and returns HTTP
409 unless the same session observed the same UID and a compatible version.
Guard then adds a Kubernetes-native atomic precondition to the forwarded
request: updates and merge, strategic, or apply patches carry
`metadata.resourceVersion`; JSON Patch begins with UID and resourceVersion
`test` operations; delete carries UID and resourceVersion preconditions. A race
after Guard's comparison therefore resolves as an upstream conflict rather than
an unguarded overwrite.

For a parent-object write, Guard ignores `status` and server-managed
`managedFields` while comparing object state. This permits controller status
updates to advance `resourceVersion` without falsely treating the desired state
as changed; the forwarded request still uses the latest live version as its
strict precondition. Status-subresource writes include status in the comparison.
Changes to spec or user-managed metadata conflict.

Observations are process-local and bounded. A daemon restart, registry eviction,
object recreation, unreadable object, collection mutation, unsupported patch
media type, or response without UID and `resourceVersion` requires a fresh
named-object read or fails with HTTP 409. Secret redaction does not establish an
observation. Typed command verbs are a separate deterministic authority path;
when they bypass the API proxy, concurrency behavior comes from the invoked tool
and verb contract rather than this observation registry.

## Multiple listeners

`--api-endpoints <yaml>` hosts multiple named listeners, including multiple
instances of one protocol. Each endpoint owns its listen address, mode,
protocol, upstream, credential reference, policy, CA output, and optional
brokered kubeconfig output.

```yaml
endpoints:
  - name: cluster-readonly
    listen: 127.0.0.1:8443
    protocol: kubernetes
    mode: readonly
    kubeconfig: /etc/guard/cluster.kubeconfig
    policy: /etc/guard/cluster-policy.yaml
    brokered_kubeconfig_out: /run/guard/cluster.kubeconfig

  - name: github-automation
    listen: 127.0.0.1:9443
    protocol: github
    mode: policy
    upstream: https://api.github.com
    token_file: /etc/guard/github-token
    policy: /etc/guard/github-policy.yaml
    ca_out: /run/guard/github-ca.pem
    client_config_out: /run/guard/github-client.json
```

Generic GitHub and Vercel clients load `client_config_out`. Its closed JSON
document contains the loopback base URL, generated CA certificate, and generated
transport bearer. Guard writes it with the same validated private-group checks
as a brokered kubeconfig on Unix. Windows rejects API proxy configuration
because Guard cannot deliver generated authority through a race-free,
client-specific filesystem boundary. Clients keep the bearer out of arguments
and logs. Generic protocol mutations require an endpoint explicitly configured
with `mode: policy`; the default readonly mode admits only policy-permitted
reads.

Endpoint identity binds policy, generated coverage, history, upstream credential
selection, and persisted rollback. A plan created on one listener cannot run
through another listener, even when both use the same protocol.

Listeners bind loopback only and require either the generated proxy transport
bearer or a live Guard session bearer on every request. Keep the protected
client material inside the dedicated Unix worker boundary. API proxy mode is
incompatible with `--exec-as-caller`.

## Consequence and rollback

Under consequence gating, recoverable writes snapshot the prior state or record
the newly created object before forwarding. The protocol constructs a plain HTTP
revert plan:

- update or patch restores the prior object;
- create deletes the server-named object;
- faithfully recreatable delete restores a sanitized snapshot;
- side-effect-only operations without a faithful inverse hold.

The persisted plan binds endpoint, protocol, canonical target, attribution, and
upstream credential identity. A create and its cleanup are correlated only
inside the same connection and attribution context, and explicit policy deny
still wins.
Every successful contained write returns `X-Guard-Provisional: <handle>` and an
HTTP `Warning` that identifies the provisional. Kubernetes clients display the
warning on standard error, and automation can read the header before treating
the write as durable. Unix operators use `sudo guard-operator confirm <handle>`
or `sudo guard-operator revert <handle>`; Windows operators use the installer
script installed at `C:\Program Files\Guard\guard-operator.ps1` from an elevated
PowerShell. `guard provisionals`
manages API and command envelopes through the same interface.

A held request that returns HTTP 403 includes its approval reference in the
Kubernetes status message and in `X-Guard-Approval`. Client error output can
name the request, and automation can poll it with `guard approval show <ref>`.

## Generated coverage and evaluator limits

Evaluate-routed traffic can produce exact verb coverage cells. Each cell binds
endpoint, attribution when present, typed operation fields, namespace,
value-free body shape, evaluator regime, and expiry. Value-bearing mutations
remain evaluator-routed. Generated coverage cannot displace operator policy.
Use `guard verb coverage list` and `guard verb coverage clear` for inspection
and reset.

The API judge has configurable global concurrency, endpoint/session token
buckets, error circuits, and a reserved session slot. Limits bound spend and
failure amplification. Exhaustion and circuit-open states fail closed, and
cumulative admission counters enter the audit stream.

## Response boundary

Guard forwards only safe response headers. Credential-bearing authentication
headers are stripped unless a protocol explicitly permits one. Response bodies
are inspected and redacted before delivery, including across transport chunks.
Compressed upstream responses are rejected unless the negotiated representation
can be inspected. Unsafe cross-origin redirects and paths with ambiguous encoded
separators, dot segments, or NULs fail closed.
