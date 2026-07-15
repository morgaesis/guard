# Saved grants and sessions

A saved grant is reusable operator-authored authority. It activates typed verbs,
selects an evaluation mode, carries evaluator context and secret-name
entitlements, declares a default TTL, and defines the ceiling for automatic
request approval. Issuing it creates a live bearer-token session bound to that
saved-grant revision.

```bash
guard grant save host-a-maintenance \
  --description 'Bounded maintenance on host-a' \
  --verb host-a-read \
  --verb host-a-apply \
  --override-marker operator:host-a-apply \
  --ttl 1800 \
  --prompt 'Inspect and maintain host-a only.'

eval "$(guard grant issue host-a-maintenance --label incident-42)"
guard session status
```

`GUARD_SESSION` is bearer authority. Keep the token out of logs and command
output. Audit and history use a stable fingerprint instead of the token bytes.

## Authority and precedence

An issued session may expand a global readonly or evaluator posture inside the
verb regions the grant activates. This is the intended path for a short-lived
agent to perform bounded mutations while the daemon baseline remains readonly.

The overlay cannot bypass hard invariants, including the server binary floor,
protocol hard-denies, credential-plan binding, secret-value checks, consequence
routing, audit, and behavioral suspension. Operator verb cells may be sticky. A
baseline `evaluate` or `deny` cell changes only when it declares an
`override_marker` and the issued grant carries that exact marker. Generated
coverage cannot mint or silently replace an operator marker.

A coverage cell says nothing outside its bounds. A grant that activates an
Ansible check-mode cell does not deny another command or another verb. Missing
regions continue through their ordinary evaluator or policy path. Guard does not
generate complement denies from phrases such as "only --check mode."

See [Typed verbs and coverage](verbs.md) for the complete resolver order.

## Lifecycle

`guard grant save` creates a reusable grant. Use these commands for maintenance:

```bash
guard grant list
guard grant show host-a-maintenance

guard grant edit host-a-maintenance \
  --clear-verbs \
  --verb host-a-read \
  --ttl 900

guard grant regenerate host-a-maintenance \
  --prompt 'Inspect host-a and apply only the bounded service verb.'
# Inspect the candidate and deterministic delta, then apply its exact proposal:
guard grant regenerate host-a-maintenance --apply <proposal-id>

guard grant issue host-a-maintenance --ttl 600 --label interactive-debug
guard grant delete host-a-maintenance
```

An edit increments the saved-grant revision. Regeneration previews a validated
candidate and deterministic delta without changing authority. Applying its
integrity-bound proposal commits that exact candidate only when the saved-grant
revision and evaluator regime remain unchanged. Issued sessions retain their
immutable authority snapshot; they do not silently acquire a later saved-grant
revision.

Saved grants can also live in the YAML catalog selected by `--grants` or
`GUARD_GRANTS`. [`examples/saved-grants.yaml`](../examples/saved-grants.yaml)
shows TTLs, evaluation modes, activated verbs, markers, secret names, and
auto-approval ceilings.

## Evaluation modes

Saved grants and live sessions use three miss behaviors:

| Mode | A request outside activated verb coverage |
|---|---|
| `evaluator` | Reaches the evaluator with the session prompt. |
| `policy-only` | Requires deterministic policy or verb authorization. |
| `read-only` | Uses readonly evaluator behavior for uncovered work. |

The mode controls misses. It does not weaken a matched deny, hard invariant, or
consequence classification.

## Agent requests

An agent can ask for a bounded amendment without gaining admin authority:

```bash
guard grant request submit \
  --justification 'Need the host-a service restart verb for this incident.' \
  --verb host-a-restart \
  --ttl 600
```

The response contains a durable handle. The requester can inspect or withdraw
its request; the daemon principal or TCP admin principal can decide it:

```bash
guard grant request show <handle>
guard grant request withdraw <handle>

guard grant request approve <handle>
guard grant request deny <handle> --reason 'outside the saved-grant ceiling'
```

When a saved grant enables automatic approval, only requests inside its declared
ceiling apply automatically. The ceiling can limit verbs, secret names, TTL,
prompt expansion, and evaluation modes. Requests outside the ceiling retain the
same escalation handle for operator action.

## Session operations

`guard session show` and `guard session status` let an agent inspect its own
effective scope without exposing the raw bearer. Operators can list, extend,
label, revoke, and bulk-revoke sessions:

```bash
guard session show
guard session list --history --since 2h
guard session extend <token> --ttl 900
guard session label <token> incident-42
guard session revoke <token>
guard session revoke-matching --label incident-42
guard session revoke-matching --saved-grant host-a-maintenance
```

The SQLite state database stores saved grants, revisions, sessions, requests,
transitions, and bounded interaction history. Each interaction carries a
versioned decision trace with its stable decision source, matched typed cells,
failed dimensions or conflicts, and actionable guidance. Holds and provisionals
persist the same trace with their immutable snapshots. History includes names of
delivered secrets but never secret values. A later grant edit does not rewrite
an already reviewed action.

Optional rolling denial-count, hold-count, and denial-ratio thresholds suspend a
session into deny-all while the triggering behavior remains in the configured
window. `guard session status` reports suspension and the operator action rather
than hiding it behind an ordinary evaluator denial.

## Migration aliases

Legacy profile flags, environment variables, YAML keys, and exact command
patterns are accepted only as migration inputs. Exact argv and an exact prefix
ending in a separate `*` token migrate deterministically to saved grants and
typed coverage. Ambiguous patterns fail loading and never become a parallel
authorization language. New configuration uses saved grants and verbs.
