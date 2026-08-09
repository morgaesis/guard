# Access, saved grants, and sessions

`guard access` is the public authority workflow. An authenticated local agent can
request work in prose without already owning a session:

```bash
guard access request 'Inspect host-a and report drift.'
guard access show <request>
```

The daemon records the kernel-authenticated uid or SID as requester. The wire
request has no owner field, and a request cannot select or transfer authority to
another principal. Equivalent retries for one principal and target return the
same durable request. Requests from different principals remain separate.

An operator decides requests individually or in a batch:

```bash
guard access approve <request>...
guard access approve <request> --once
guard access approve <request> --uses 3
guard access deny <request>... --reason 'outside the approved task'
guard access revoke <session-or-agent>
```

`--once` is exactly `--uses 1`. Batch results are per request. One invalid or
stale item does not widen or roll back another item that succeeds.

On a terminal, `guard access approve` reviews each request before deciding: it
prints the requester, intent, state, and typed capability coverage with
consequence classes colored, states the use budget an approve grants, then
takes an approve, deny, skip, or quit answer per request. A deny accepts an
optional reason and ignores the use flags, which only shape approvals. A held
request is approved as one-time automatically, matching the only form it
accepts. Decisions are sent one request at a time, so quitting mid-batch never
undoes a decision already made. Requests left undecided by skip or quit stay
pending, are listed on stderr, and exit 0 unless a lookup or sent decision
failed. `--yes` decides without the review, a piped, redirected, or `--json`
invocation decides immediately with unchanged output, and `guard access deny`
is deliberately immediate in every mode.

## Resolution and precedence

The daemon reduces intent against typed verbs, daemon baseline authority,
active requester authority, evaluator gates, credential plans, and verified
revert envelopes. A request stores only the missing non-baseline delta.
Generated proposals are inert, untrusted, and non-baseline. Approval promotes
the exact reviewed matcher to trusted access-session coverage stored with the
durable request. Guard derives consequence independently of the model:
recognized read-only shapes may execute, while unknown or mutating generated
shapes remain irreversible holds. Daemon-wide baseline promotion requires an
operator-authored catalog change.

Access cannot bypass the binary floor, protocol hard-denies, sticky operator
cells, credential-plan binding, secret-value checks, consequence routing,
audit, or behavioral suspension. A model-authored revert is not treated as a
verified rollback envelope.

## Sessions and bounded uses

Approval creates or reuses one access-managed session bound to the requester.
The bearer remains internal. CLI, JSON, audit, and history use stable session
references such as `session:0123456789abcdef` and never expose raw tokens.

A bounded use is consumed atomically when Guard admits the bound execution
snapshot. The durable count is decremented before process spawn, so a later
spawn failure consumes the use. Concurrent requests cannot admit more snapshots
than the remaining count. SQLite persistence, restart recovery, expiry,
revocation, history, status, and audit retain the limit and remaining count.

Every approved request has its own typed scope and counter. An ordinary approval
for one system does not make a one-time or exhausted grant for another system
unlimited.

Access-managed sessions authorize brokered command verbs. They cannot issue a
reusable brokered kubeconfig or authenticate directly to the API proxy because
that would bypass command admission and bounded-use accounting.

An operator extends a specific active target by stable session reference or
agent label:

```bash
guard access extend session:0123456789abcdef 'Inspect host-a logs.'
guard access extend agent:1001 'Restart the bounded fixture service.' --once
```

There is no implicit latest-session target. Repeating an equivalent extension
reuses its durable request and does not refill a partially consumed budget. An
expired or revoked target does not reuse its terminal approval; a new request
creates new review state.

## Inspection

`guard access list` prints one compact line per request, hold, and session with
requester, target, effective scope, expiry, remaining uses, state, and next
action. `guard access show` includes typed capability coverage and evidence.
`guard access status` adds activity statistics, recent decisions, approvals,
provisionals, and authority requests for one access-managed session. These
commands support `--json` with `schema_version: 1` and never return a raw
session bearer.

```bash
guard access list
guard access list --json
guard access show <request-or-session>
guard access show <request-or-session> --raw
guard access show <request-or-session> --json
guard access status <session>
guard access status <session> --json
```

`guard access show` and the interactive approval prompt describe each capability
in the terms an approval decision needs: a plain-language description of the
access the matcher admits, the command line it pins with caller-supplied values
shown as `<param>`, one line per parameter carrying its anchored pattern and, for
a pinned literal or a closed enumeration, a reading of the values it accepts, and
the coverage cells, credential plan, consequence class, trusted flag, and revert
availability. The matcher digest stays on its own line because held approvals
bind to it. `--raw` adds the exact matcher JSON beneath that rendering.

A catalog verb shows its operator-authored description. A matcher synthesized
from a prose request uses the synthesis response's description, with a
matcher-derived description as the fallback. A denied command with structured
argv produces an exact matcher directly from that argv and always uses a
matcher-derived description. Description generation does not delay a request.

A pending request reports the budget a bare `guard access approve` would apply
rather than the internal `unselected` state: `unlimited` unless the request asked
for a bound, and a single use for a consequence hold, which accepts no other
budget. `--json` keeps `use_policy: unselected` and carries the default in
`default_use_policy` and `default_uses`.

Denied operations that can be represented as missing typed authority return one
durable request identifier. Consequence-gated holds use the immutable hold
identifier as that request, preserving the exact argv, principal, catalog
revision, credential hashes, and revert evidence reviewed by the operator. A
hold accepts only `guard access approve <request> --once`; ordinary and N-use
approval apply to authority requests.

## Internal authority objects

Saved grants define reusable ceilings, evaluation modes, secret-name selectors,
and default lifetimes. Sessions hold immutable issued authority snapshots. Grant
requests and holds record review transitions. These objects persist in SQLite
and are managed through the principal-bound access resolver. Removed grant,
session, and appeal commands return a direct `guard access` migration error and
cannot author or expose authority.

The state database stores saved grants, revisions, sessions, requests,
transitions, bounded-use counts, and bounded interaction history. History names
delivered secrets but never stores secret values. A later catalog or saved-grant
edit does not rewrite an already reviewed execution snapshot.
