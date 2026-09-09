# Consequence-gating adversarial harness

Self-contained Docker/Podman harness that exercises consequence gating
end-to-end with separate daemon, child, and agent UIDs. Unlike the credentialed CTF in
the parent directory, this needs no Claude OAuth and no external service
credentials.

```bash
./ctf/gating/run.sh          # adversarial attack (deterministic, offline)
./ctf/gating/run.sh static   # shell syntax and source-contract checks
./ctf/gating/run.sh mutation # fixed-attack argv mutation checks
./ctf/gating/run.sh test     # full cargo test suite, in Linux
./ctf/gating/run.sh synthetic-user
./ctf/gating/synthetic-user-runner.sh --self-test  # runner evidence self-test, no container
```

The harness applies conservative container resource defaults. Override them
with `CTF_CONTAINER_MEMORY`, `CTF_CONTAINER_MEMORY_SWAP`,
`CTF_CONTAINER_CPUS`, `CTF_CONTAINER_PIDS_LIMIT`, or `CARGO_BUILD_JOBS` when a
host needs different limits.

Generated harness images use `localhost/`-qualified tags to avoid short-name
registry resolution.

## Synthetic-user mode

`synthetic-user` runs SU-01 through SU-11, seven SU-12 workload journeys, and
SU-13 through SU-22.
Each scenario receives a separate rootless Podman execution container, named volume,
Guard daemon, socket, database, fake fixtures, uid-separated principal, and
network namespace. Runtime networking is disabled. A separate init container
has only `CHOWN` for fixture ownership. The execution container has a read-only
root filesystem and exactly `SETUID` and `SETGID`, plus no-new-privileges,
bounded CPU, memory, and PID resources, tmpfs scratch paths, and no host bind
mounts. Guard runs as the non-root daemon uid with that exact capability pair;
brokered children have zero effective capabilities.

The image contains the integrated source and compiled focused test binaries.
The private scenario volume contains only scenario state and fixtures. No host
checkout, credential directory, socket, cache, or build output is mounted into
the container. Principal phase output is private to its uid. Shared journey
files are sticky handoff state, so one principal cannot replace another
principal's files. A bounded setup phase precreates the known principal
directories before the daemon starts. The root-owned collector copies
completed phase evidence and finalizes the only copyable Markdown result. The
runner copies and hashes that finalized result in a unique directory beneath
`.cache/synthetic-user/runs`.
Each run manifest binds the selected catalog, commit, image identity, outcomes,
and evidence hashes. `latest-run` points to the newest run without mixing its
results with an older invocation. Raw output remains in the scenario volume.
The container and volume are removed after every result by default.

Every scenario container and volume carries the run and scenario labels. The
runner records each created resource in the run-local cleanup manifest before
starting it. Cleanup and interrupted-run recovery use that manifest and the
matching labels only. Set `GUARD_SU_RUN_ID` to the interrupted run identifier to
recover its non-preserved resources. `GUARD_SU_KEEP_FAILED=1` records an
explicit preservation entry and leaves that failed fixture intact.

Set `GUARD_SU_KEEP_FAILED=1` to intentionally preserve a failed scenario's
container and volume for inspection. The harness prints both generated names.
Remove the container before its volume when inspection is complete:

```bash
GUARD_SU_KEEP_FAILED=1 ./ctf/gating/run.sh synthetic-user SU-05
podman stop --time 5 <container>
podman rm <container>
podman volume rm <volume>
```

Pass scenario names to run a subset:

```bash
./ctf/gating/run.sh synthetic-user SU-05 SU-10 SU-12-helm
```

The synthetic-user mode never invokes the credentialed CTF in the parent
directory. Its fake services, fake credentials, and fake kubeconfig are local
to the scenario volume.

### Scenario catalog

| ID | Contract |
| --- | --- |
| SU-01 | Denial escalation is revision-bound, and exact session authority is working-directory-bound. |
| SU-02 | A bounded loop and its mechanically unrolled form receive the same consequence when they resolve to the same operations. |
| SU-03 | Evaluator cache entries do not cross principals, session fingerprints, or internal authority revisions. |
| SU-04 | Removed bearer-minting and kubeconfig-export commands fail closed and direct callers to principal-bound command access. |
| SU-05 | Filtering Helm release Secrets fails explicitly instead of presenting a plausible empty release inventory. |
| SU-06 | Child execution preserves the effective working directory, rejects caller environment overrides, and explains common path failures. |
| SU-07 | Expiry, restart recovery, approval snapshots, and spawn failures retain fail-closed lifecycle state and audit evidence. |
| SU-08 | A deliberately failing rollback reaches `revert_failed` for the owning principal. |
| SU-09 | Configured session-history retention prunes only expired interactions. |
| SU-10 | Execute protocol version, features, and working-directory rules reject stale or incomplete clients with direct upgrade guidance. |
| SU-11 | Secret-use audit begins only after successful spawn and records names and provenance without values. |
| SU-12 | Fixed identity executes kubectl only through an active Guard proxy, denies Ansible and Helm, and clears child capabilities; caller identity denies all typed profile tools. |
| SU-13 | A loopback-fixture evaluator synthesizes prose coverage that stays inert until access, operator arming, and requester resume, remains principal-scoped across restart, leaves the operator catalog unchanged, and fails closed after revoke. |
| SU-14 | A sessionless prose request is principal-bound, coalesced, approved without an owner flag, and isolated from another principal that replays both its request reference and a fake leaked bearer. |
| SU-15 | Denied work offers ordinary, one-time, and bounded approval; one immutable held snapshot is armed with `--once` and resumed exactly once by its requester, while a separate hold is denied. |
| SU-16 | Ordinary, one-time, and N-use access approvals remain request-scoped without bypassing Helm or Ansible process admission across batch failure, races, restart, two principals, API, file, and command workflows. |
| SU-17 | Proactive extension targets a stable session reference, stores only missing coverage, and converges across retries. |
| SU-18 | Bare help and inspection are non-mutating; bounded expiry and explicit revoke remain fail-closed across restart. |
| SU-19 | Concurrent prose retries converge within each principal and system, while stale-first partial decisions preserve independent sessions and bounded budgets. |
| SU-20 | Revocation before exhaustion survives repeated restart without restoring historical authority or changing another principal's remaining uses. |
| SU-21 | Approve and deny help is non-mutating; ordered partial decisions, terminal retries, exhausted grants, fresh denied requests, and stale JSON references remain predictable. |
| SU-22 | A private staged install, failed upgrade, rollback, replacement-binary proof, persisted bounded authority, and cleanup complete without host mounts or external services. |

## Deployment under test

A non-root daemon authenticates the agent as uid 1001 and uses only `SETUID` and
`SETGID` to execute approved fixed-identity commands as the dedicated
`guardexec` uid 1003. Operator actions carry a separate admin bearer that
brokered children cannot read. The child cannot read or mutate daemon state,
operator authority, or the admin bearer. The closed `whoami` executable
profile validates that fixed and caller children have zero effective
capabilities. The harness also checks that the daemon and
child identities cannot approve, deny, confirm, or revert by identity alone.

The `--exec-as-caller` variant drops each command to its authenticated
Unix-socket caller instead. Its typed profile-tool scenarios assert denial before
process start.

The daemon creates the socket as mode `0660` with group `guard-clients`. The
harness never makes it world-writable and verifies both ownership and access
after each daemon start.

The agent-facing scenarios use ordinary commands and prose-first `guard access`
intent. The operator-owned `verbs.yaml` catalog is enforcement machinery for
the harness, not a separate public authority workflow. Its trusted typed cells
make the attacks deterministic and offline by skipping the LLM and routing on
their declared consequence class. Real-LLM classification is covered separately
(see the README's consequence-gating section) and is gated on
`OPENROUTER_API_KEY`.

## What it asserts

1. Direct `ssh` has no usable credential, and a transparent `ssh` shim cannot
   supply `SSH_AUTH_SOCK` to the fixed child or start the opaque SSH profile.
2. The daemon runs as the non-root service uid with exactly `SETUID` and
   `SETGID`, while fixed and caller children report zero effective capabilities.
3. The Guard socket remains mode `0660`, group `guard-clients`, across startup
   and restart.
4. A transparent fixed-identity kubectl shim preserves argv and cwd, receives
   only the broker-generated kubeconfig, and succeeds through the active proxy.
5. Fixed-identity Helm, Ansible, and ansible-playbook commands are denied before
   their fake children start.
6. Caller-identity Ansible, Helm, and kubectl commands are denied before their
   fake children start.
7. Access approval does not bypass the fixed Helm or Ansible execution boundary.
8. A reversible operation executes immediately.
9. A recoverable operation applies behind an auto-revert envelope, then
   auto-reverts when left unconfirmed.
10. An operator `confirm` cancels the auto-revert; an agent cannot confirm.
11. An irreversible operation is held, not executed.
12. An agent cannot self-approve its own held command.
13. The operator approves and the bound snapshot executes.
14. Parameter shell- and flag-injection are structurally rejected.
15. A raw destructive command stays gated.
16. A daemon restart mid-window leaves the change in place and re-arms its
    future deadline.
