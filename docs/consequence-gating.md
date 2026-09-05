# Consequence gating

Consequence gating converts an evaluator approval into one of three execution
routes. Enable it on a local authenticated listener:

Provision the dedicated accounts first, using the
[Unix service setup](../DEPLOYMENT.md#unix-service).

```bash
sudo install -d -o root -g root -m 0755 /run/guard
sudo install -o root -g guard-exec -m 0640 /dev/null /run/guard/kubeconfig
sudo env KUBECONFIG=/run/guard/kubeconfig \
  guard server start --gate consequence \
  --socket /run/guard/guard.sock \
  --exec-user guard-exec \
  --verbs /etc/guard/verbs.yaml \
  --child-env KUBECONFIG \
  --kube-proxy 127.0.0.1:8443 \
  --kubeconfig /etc/guard/upstream.kubeconfig \
  --brokered-kubeconfig-out /run/guard/kubeconfig \
  --api-policy /etc/guard/api-policy.yaml
```

| Class | Route |
|---|---|
| `reversible` | Execute immediately. |
| `recoverable` | Execute inside an auto-revert envelope. |
| `irreversible`, high-risk, or uncertain | Hold before execution. |

Classification can raise the gate but cannot lower it. Missing or conflicting
classification holds. Trusted verbs skip evaluator approval, not consequence
routing.

In safe mode, an evaluator allow of a profile-dependent carrier is denied when
its runtime identity cannot reproduce an immutable authority snapshot. Fixed
identity admits kubectl only through the generated kubeconfig for an active
Guard proxy and denies Ansible and Helm. Caller identity denies all three typed
profile tools. Prompt supplements, catalog entries, access approval, and replay
cannot bypass these process-admission rules. Unprofiled carriers such as
Terraform and Make remain denied. An evaluator deny stays a deny.

Unix and foreground Windows operators hold the explicitly configured admin
bearer. The packaged Windows service rejects that bearer and accepts
kernel-authenticated local SYSTEM on its named pipe so the installer can broker
elevated decisions; the daemon service SID receives no matching exception.
Unix root receives no matching exception, and TCP administration requires the
separate admin bearer. TCP lacks
kernel-authenticated local peer identity and cannot host consequence gating.

## Recoverable commands

The caller can propose a complete containment envelope. The following is a
schematic command shape; every forward, rollback, and check executable must have
a closed mode-compatible profile:

```bash
guard run \
  --revert "$CLOSED_ROLLBACK_COMMAND" \
  --confirm-check "$CLOSED_CONFIRMATION_COMMAND" \
  --revert-control-path "$CONTROL_PATH_DESCRIPTION" \
  --confirm-within 900 \
  "$CLOSED_FORWARD_EXECUTABLE" "${FORWARD_ARGUMENTS[@]}"
```

The evaluator considers the forward command, rollback, confirmation check,
deadline, and control path together. A chain that can sever the SSH, API,
socket, credential, daemon, or other authority required to verify or revert is
held. A recoverable operation without a usable rollback is also held.

The `PROVISIONAL` banner states the armed deadline, in both elapsed seconds and
wall-clock time, and names `--confirm-within` as the flag that sets it.

At the deadline, a confirmation check that exits zero keeps the change. Any
other outcome, including timeout or spawn failure, runs the rollback. Without a
check, an unconfirmed envelope rolls back. An operator can decide early:

```bash
guard provisionals
sudo guard-operator confirm <handle>
sudo guard-operator revert <handle>
```

On Windows, run
`& 'C:\Program Files\Guard\guard-operator.ps1' -Action confirm -Reference <handle>`
or the corresponding `-Action revert` from an elevated PowerShell. A Unix
`guard-operator confirm` or `guard-operator revert` on a handle whose deadline
already fired reports when the automatic rollback ran and the window that
elapsed, so an envelope that did what it was armed to do is distinguishable
from a fault.

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
coverage, secret-name bindings with installation-keyed value HMACs, and
consequence decision. This frozen snapshot prevents a later grant edit, verb reload, secret
swap, or caller environment change from rewriting what the operator reviews.

```bash
guard access list
guard access show <request>
guard access approve <request> --once
guard access approve <request> --once --wait=300
guard approval resume <request>
guard approval show <request>
guard approval show <request> --wait=300
guard access deny <request> --reason 'outside the approved task'
```

A consequence hold accepts only `--once`. Approval arms its immutable snapshot
without executing it as the operator. The kernel-authenticated requester runs
the snapshot with `guard approval resume <request>`, which returns its stdout, stderr,
and exit status. Each hold can be resumed once. Bounded copies of stdout and
stderr remain in durable approval state and identify truncation in their stored
text. `guard approval show <request>` retrieves that terminal transcript if the
resume response is lost. The requester can add context with `guard approval
note` or cancel an unexecuted hold with `guard approval withdraw`. Ordinary and
N-use approval apply to authority requests created from denied or proactive
access intent, not to held execution snapshots.

`guard access approve --wait=<seconds> <request>` accepts one hold and a bound
from 1 through 3600 seconds. It checks daemon capability before mutation, then
sends one approval RPC that registers the waiter before changing the hold.
Ordinary holds return `armed` for requester resume; API-proxy holds normally
return `approved` after release. Other outcomes are `denied`, `expired`,
`exec_failed`, and `timed_out`. Armed or unresolved waits exit 127, denial or
expiry exits 126, execution failure exits 125, and approval exits 0. Grant
requests cannot use this wait because approval grants authority rather than
executing a held operation.

`guard approval show --wait=<seconds>` and `guard approval resume
--wait=<seconds>` use the same bounds and outcome vocabulary. They remain separate
read and requester-resume operations; `guard access approve --wait` does not
send a follow-up wait RPC. Daemons without the consequence capability require
polling with `guard approval show`. Their missing consequence field is rendered
as `grant` for `gr-` references and `arm` for other references; JSON marks this
as `consequence_source: legacy_prefix_fallback` and never infers `release`.

Only an authenticated operator can approve or deny. The original requester may
add notes to its hold but cannot decide it. Discussion freezes when the hold is
decided.

`guard run --wait-approval` waits without a client-side timeout and resumes on
the same requester connection after approval. `--wait-approval <seconds>` adds
a client bound. `--approval-ttl unbounded` keeps a durable hold until a
decision, while a numeric TTL fails closed on expiry. Disconnecting a waiting
client does not grant authority; the requester can reconnect with `guard
approval resume` after approval.

## Restart and failure behavior

Holds and provisionals persist in SQLite. A daemon restart does not run a
rollback unattended during startup. A provisional already past its deadline
becomes an explicit operator decision rather than firing through an unverified
environment.

Evaluator errors, missing authority snapshots, unsafe replay checks, malformed
rollback commands, and unavailable gate infrastructure fail closed before
forward execution. `DENIED` means the forward operation did not execute.
`PROVISIONAL` means the forward operation executed and the durable auto-revert
window is armed. A `CONTAINMENT_FAILED` result identifies whether the forward
command exited nonzero, ended without an exit code, or ran without a durable
containment outcome. It never claims that an auto-revert timer is armed.

A denial names the authority that produced it on a `source:` line and the route
back on an `appeal:` line. `static-policy` is a matched operator-authored deny
rule and is absolute; `static-default-deny` is missing coverage that `guard
access request` supplies; `learned-deny` is a generated fast path that
`--reevaluate` skips; `evaluator` and `evaluator-cache` are model judgments
that `guard access request` escalates. A similar-command counter is evidence
recorded after an evaluator denial, not a matched learned shape. The underlying
source also appears in structured output as `decision_source`.

## Autonomous operation

The operational target is deploy-and-forget authority for routine bounded work,
including overnight incident response. Saved grants and typed verbs cover known
regions. A viable forward, verify, and rollback chain proceeds without waking an
operator. Holds are reserved for expired, conflicting, irreversible, or
connectivity-unsafe work and return a durable escalation handle.

An optional `--notify-cmd` receives bounded lifecycle JSON on standard input for
holds, provisionals, session behavior, and grant requests. Guard does not own
webhook credentials or make notification success part of the policy decision.
