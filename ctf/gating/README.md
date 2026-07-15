# Consequence-gating adversarial harness

Self-contained Docker/Podman harness that exercises consequence gating
end-to-end with a uid-separated daemon and agent. Unlike the credentialed CTF in
the parent directory, this needs no Claude OAuth and no external service
credentials.

```bash
./ctf/gating/run.sh          # adversarial attack (deterministic, offline)
./ctf/gating/run.sh test     # full cargo test suite, in Linux
```

The harness applies conservative container resource defaults. Override them
with `CTF_CONTAINER_MEMORY`, `CTF_CONTAINER_MEMORY_SWAP`,
`CTF_CONTAINER_CPUS`, `CTF_CONTAINER_PIDS_LIMIT`, or `CARGO_BUILD_JOBS` when a
host needs different limits.

## Deployment under test

An unprivileged daemon runs as uid 1000 (also the operator); the agent is uid
1001. The operator gate is bypass-resistant precisely because the daemon UID
differs from the agent's: only uid 1000 can approve, deny, confirm, or revert.
Approved commands execute as the daemon identity (the policy-gate deployment).
The root-broker `--exec-as-caller` variant - where commands drop to the caller's
uid - is the WSL/Linux production deployment; it relies on setuid privilege drop
that a plain container does not grant, so it is not exercised here.

The attacks are deterministic and offline: the verbs in `verbs.yaml` are
`trusted`, so they skip the LLM and route purely on their declared consequence
class. Real-LLM classification is covered separately (see the README's
consequence-gating section) and is gated on `OPENROUTER_API_KEY`.

## What it asserts

1. Direct `ssh` has no usable credential, while the transparent `ssh` shim
   reaches the guarded fake primary with argv/cwd preserved and a broker-owned
   `SSH_AUTH_SOCK`.
2. Transparent `kubectl`, `helm`, `ansible`, and `ansible-playbook` shims broker
   through `guard run` and preserve argv/cwd.
3. With `GUARD_SESSION` set, `ansible -m ping all` discovers `ansible.cfg` and
   inventory from the caller cwd while ambient `ANSIBLE_CONFIG` is not inherited.
4. Typed verb templates require cooperative Helm/Ansible check, diff, namespace,
   and limit controls; duplicate or equivalent option bypass attempts fail.
5. Opaque file-driven `ansible-playbook` execution without the typed controls is
   denied.
6. A reversible verb executes immediately.
7. A recoverable verb applies behind an auto-revert envelope, then auto-reverts
   when left unconfirmed.
8. An operator `confirm` cancels the auto-revert; an agent cannot confirm.
9. An irreversible verb is held, not executed.
10. An agent cannot self-approve its own held command (the bypass-resistance).
11. The operator approves and the bound snapshot executes.
12. Parameter shell- and flag-injection are structurally rejected.
13. A raw destructive command stays gated.
14. A daemon restart mid-window leaves the change as `needs_operator_decision`
   with no unattended revert at boot.
