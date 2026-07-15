# Consequence gating

Consequence gating converts an evaluator approval into one of three execution
routes. Enable it on a local authenticated listener:

```bash
guard server start --gate consequence \
  --socket /run/guard/guard.sock \
  --verbs /etc/guard/verbs.yaml
```

| Class | Route |
|---|---|
| `reversible` | Execute immediately. |
| `recoverable` | Execute inside an auto-revert envelope. |
| `irreversible`, high-risk, or uncertain | Hold before execution. |

Classification can raise the gate but cannot lower it. Missing or conflicting
classification holds. Trusted verbs skip evaluator approval, not consequence
routing.

The operator is the daemon principal: the daemon uid over a Unix socket or the
daemon SID over a Windows named pipe. TCP lacks kernel-authenticated local peer
identity and cannot host consequence gating.

## Recoverable commands

The caller can propose a complete containment envelope:

```bash
guard run \
  --revert 'systemctl stop app' \
  --confirm-check 'systemctl is-active app' \
  --revert-control-path 'local systemd control socket' \
  --confirm-within 900 \
  systemctl restart app
```

The evaluator considers the forward command, rollback, confirmation check,
deadline, and control path together. A chain that can sever the SSH, API,
socket, credential, daemon, or other authority required to verify or revert is
held. A recoverable operation without a usable rollback is also held.

At the deadline, a confirmation check that exits zero keeps the change. Any
other outcome, including timeout or spawn failure, runs the rollback. Without a
check, an unconfirmed envelope rolls back. An operator can decide early:

```bash
guard provisionals
guard confirm <handle>
guard revert <handle>
```

Forward, verification, and rollback preserve the canonical working directory,
principal, and approved daemon-side credential bindings. Persisted plans store
credential references and hashes, not values. A changed secret value fails
closed rather than executing under authority different from the reviewed
snapshot.

API writes use the same provisional registry. Their rollback plans bind the
named endpoint, protocol, canonical target, session fingerprint, and a
secret-free upstream credential identity. The sweeper executes a due rollback
only through an exact live endpoint match. If that path is unavailable, the
change remains visible for operator handling instead of using another endpoint.

## Holds

A held operation has not executed. Guard stores the exact command or API
request, caller working directory, effective grant revision, applicable verb
coverage, secret-name/value bindings, and consequence decision. This frozen
snapshot prevents a later grant edit, verb reload, secret swap, or caller
environment change from rewriting what the operator reviews.

```bash
guard approvals
guard approvals <handle>
guard approval-note <handle> 'Verified maintenance window and target.'
guard approve <handle>
guard deny <handle>
```

Only the daemon principal or TCP admin principal can approve or deny. The
original requester may add notes to its hold but cannot decide it. Discussion
freezes when the hold is decided.

`guard run --wait-approval` waits without a client-side timeout;
`--wait-approval <seconds>` adds a client bound. `--approval-ttl unbounded`
keeps a durable hold until a decision, while a numeric TTL fails closed on
expiry. Disconnecting a waiting client does not grant authority.

## Restart and failure behavior

Holds and provisionals persist in SQLite. A daemon restart does not run a
rollback unattended during startup. A provisional already past its deadline
becomes an explicit operator decision rather than firing through an unverified
environment.

Evaluator errors, missing authority snapshots, unsafe replay checks, malformed
rollback commands, and unavailable gate infrastructure fail to deny or hold.
`DENIED` always means the forward operation did not execute. A provisional
result states that execution occurred and rollback remains armed.

## Autonomous operation

The operational target is deploy-and-forget authority for routine bounded work,
including overnight incident response. Saved grants and typed verbs cover known
regions. A viable forward, verify, and rollback chain proceeds without waking an
operator. Holds are reserved for expired, conflicting, irreversible, or
connectivity-unsafe work and return a durable escalation handle.

An optional `--notify-cmd` receives bounded lifecycle JSON on standard input for
holds, provisionals, session behavior, and grant requests. Guard does not own
webhook credentials or make notification success part of the policy decision.
