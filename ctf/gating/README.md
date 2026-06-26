# Consequence-gating adversarial harness

Self-contained Docker harness that exercises consequence gating end-to-end with
a uid-separated daemon and agent. Unlike the podman CTF in the parent directory,
this needs only Docker — no podman, no Claude OAuth, no external egress.

```bash
./ctf/gating/run.sh          # adversarial attack (deterministic, offline)
./ctf/gating/run.sh test     # full cargo test suite, in Linux
```

## Deployment under test

An unprivileged daemon runs as uid 1000 (also the operator); the agent is uid
1001. The operator gate is bypass-resistant precisely because the daemon UID
differs from the agent's: only uid 1000 can approve, deny, confirm, or revert.
Approved commands execute as the daemon identity (the policy-gate deployment).
The root-broker `--exec-as-caller` variant — where commands drop to the caller's
uid — is the WSL/Linux production deployment; it relies on setuid privilege drop
that a plain container does not grant, so it is not exercised here.

The attacks are deterministic and offline: the verbs in `verbs.yaml` are
`trusted`, so they skip the LLM and route purely on their declared consequence
class. Real-LLM classification is covered separately (see the README's
consequence-gating section) and is gated on `OPENROUTER_API_KEY`.

## What it asserts

1. A reversible verb executes immediately.
2. A recoverable verb applies behind an auto-revert envelope, then auto-reverts
   when left unconfirmed.
3. An operator `confirm` cancels the auto-revert; an agent cannot confirm.
4. An irreversible verb is held, not executed.
5. An agent cannot self-approve its own held command (the bypass-resistance).
6. The operator approves and the bound snapshot executes.
7. Parameter shell- and flag-injection are structurally rejected.
8. A raw destructive command stays gated.
9. A daemon restart mid-window leaves the change as `needs_operator_decision`
   with no unattended revert at boot.
