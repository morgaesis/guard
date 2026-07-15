# API proxy

Command gating cannot see HTTP operations performed inside Helm, Terraform
providers, k9s, SDKs, or another long-lived process. Guard's API proxy terminates
a local TLS connection, parses each request into a typed operation, applies
policy and evaluator judgment, and re-originates allowed traffic with an
upstream credential held only by the daemon.

Kubernetes is the reference protocol. GitHub and Vercel adapters exercise the
same protocol-independent gate and are example integrations.

## Kubernetes quick start

```bash
guard server start \
  --gate consequence \
  --kube-proxy 127.0.0.1:8443 \
  --kubeconfig /etc/guard/kubeconfig \
  --api-policy /etc/guard/api-policy.yaml

guard api kubeconfig --output "$HOME/.kube/guard-config"
KUBECONFIG="$HOME/.kube/guard-config" kubectl get pods -n dev
```

The input kubeconfig belongs to the daemon and may contain a bearer token or
client certificate. Exec and auth-provider plugins are rejected. The brokered
kubeconfig points only to Guard, trusts its local CA, and contains no upstream
credential.

`guard api kubeconfig` authenticates the local caller and embeds its live,
finite-expiry `GUARD_SESSION` bearer. The caller process writes a mode 0600,
caller-owned output file. Expired, revoked, or suspended sessions stop working
at the proxy and cannot issue another config. Reissue the config after session
or daemon TLS rotation. `--brokered-kubeconfig-out` remains an explicit
operator/bootstrap compatibility path and does not replace caller-scoped
issuance.

## Session attribution

A client attributes requests with a standard Guard bearer:

```http
Authorization: Bearer <Guard session>
```

`X-Guard-Session` is a compatibility alias. Guard rejects duplicate or
conflicting forms, validates the live unsuspended session, strips the client
header, and records only the session fingerprint and safe operation context.
The upstream never receives the Guard session bearer. Guard injects the named
endpoint's upstream credential only after authorization.

The session is revalidated immediately before forwarding, including after a
slow snapshot or held approval. Expiry, revocation, suspension, or a changed
immutable authority snapshot fails closed.

Each request also binds the complete API policy and evaluator-intent generation
before classification. A hot reload that changes any policy field or evaluator
intent invalidates every in-flight request before its next upstream operation.
The client submits a fresh request under the new authority.

## Policy

Load a hot-reloaded YAML policy with `--api-policy`; absence is default deny.
[`examples/api-policy.yaml`](../examples/api-policy.yaml) documents the schema.
Rules match typed protocol fields such as operation verb, resource, namespace,
and subresource. Actions are:

| Action | Behavior |
|---|---|
| `allow` | Route through the consequence floor and forward if eligible. |
| `deny` | Reject without contacting upstream. |
| `hold` | Park in the shared approval queue; without that queue, deny. |
| `evaluate` | Ask the evaluator under policy and live-session intent. |

Explicit policy denies and protocol hard-denies are absolute. A readonly
listener baseline rejects unattributed writes. A live prompt-bearing session may
send writes to the evaluator under its own bounded intent, but cannot override
those absolute boundaries.

Kubernetes interactive subresources (`exec`, `attach`, `portforward`, and
`proxy`), `pods/ephemeralcontainers`, and Secret watches are hard-denied. Writes
to other subresources require an explicit matching subresource rule. Allowed
Secret reads redact values regardless of policy wording, and an unparseable
secret-bearing response fails closed.

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
    session_env: GUARD_SESSION

  - name: github-automation
    listen: 127.0.0.1:9443
    protocol: github
    upstream: https://api.github.com
    token_file: /etc/guard/github-token
    policy: /etc/guard/github-policy.yaml
    ca_out: /run/guard/github-ca.pem
```

Endpoint identity binds policy, generated coverage, history, upstream credential
selection, and persisted rollback. A plan created on one listener cannot run
through another listener, even when both use the same protocol.

Listeners bind loopback only. A Guard session bearer conveys scope but is not a
network client identity, so expose the proxy only inside a trusted local or
single-tenant boundary. API proxy mode is incompatible with `--exec-as-caller`.

## Consequence and rollback

Under consequence gating, recoverable writes snapshot the prior state or record
the newly created object before forwarding. The protocol constructs a plain HTTP
revert plan:

- update or patch restores the prior object;
- create deletes the server-named object;
- faithfully recreatable delete restores a sanitized snapshot;
- side-effect-only operations without a faithful inverse hold.

The persisted plan binds endpoint, protocol, canonical target, session, and
upstream credential identity. A create and its cleanup are correlated only
inside the same connection and session, and explicit policy deny still wins.
`guard provisionals`, `guard confirm`, and `guard revert` manage API and command
envelopes through the same interface.

## Generated coverage and evaluator limits

Evaluate-routed traffic can produce exact verb coverage cells. Each cell binds
endpoint, session fingerprint, typed operation fields, namespace, value-free
body shape, evaluator regime, and expiry. Value-bearing mutations remain
evaluator-routed. A session can evaluate past a global generated deny under its
own intent; operator policy cannot be displaced. Use `guard verb coverage list`
and `guard verb coverage clear` for inspection and reset.

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
