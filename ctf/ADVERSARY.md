# Adversarial CTF: cross-user secret isolation

This harness runs a scripted Codex CLI attacker against a guard daemon that
holds another user's secret. It evaluates whether guard keeps the victim's
secret inside the victim's private namespace for each configured scenario.

## Participants

Each rootless Podman container has three UIDs. The guard daemon uses UNIX
socket peer credentials to distinguish them:

- `guard` (uid 900) runs `guard server start`. Admin RPCs are restricted to
  this UID.
- `victim` (uid 1000) stores `CTF_FLAG` and credential-shaped decoys.
- `attacker` (uid 1001) runs the Codex CLI with an open-weight model over a
  dedicated OpenRouter key and uses the shared guard socket.

The daemon starts with `--socket-group guard-clients`, so the socket is mode
0660 owned by that group and all three users belong to it. Guard relies on
`SO_PEERCRED` for identity, and the daemon allows these UIDs to connect. The
attacker does not receive an approved access grant or the evaluator credential;
the evaluator key reaches only the daemon, through a guard-owned Podman secret
file it reads with its own shell.

## Scenario boundary and state

`run-adversary.sh` builds one image, then starts exactly one uniquely named
rootless container for every selected entry in `scenarios.yaml`. The run's
`scenario-containers.tsv` records each scenario-to-container mapping and the
fresh-state invariant.

Every scenario container has fresh tmpfs scratch space, a fresh per-scenario
home volume, fresh daemon state, a newly generated flag, and a newly
provisioned Codex runtime. The
runner requires `ATTACKER_KEY_FILE` to name an explicit dedicated, short-lived
OpenRouter key file for the attacker, and `ATTACKER_MODEL` selects the
open-weight model (default `moonshotai/kimi-k3`). The host stages that key in
a private temporary file, copies it into the stopped scenario container, and
removes the host copy during cleanup. The key remains available to the attacker
process inside its scenario container. The harness does not enforce the key's
scope; the dedicated key must carry a credit limit and exclude personal and
production resources. The entrypoint retains only bounded,
flag-redacted transcripts, reports, and daemon logs in `/tmp/ctf-runs`; the host
retains those results after removing the container. An attacker invocation
failure or a missing final report is an inconclusive failing result.

The harness uses a read-only root filesystem, a full capability drop with only
`CHOWN`, `SETGID`, and `SETUID` added back for startup provisioning, no-new-
privileges, rootless user namespaces, blocked host loopback through
slirp4netns, and PID, CPU, memory, and memory-swap bounds. Raw evidence stays
in root-owned paths the attacker cannot alter: the daemon's log and durable
audit sink and the raw transcripts live under a root-owned directory on the
results volume, so an attacker who fills its own writable tmpfs cannot drop
the evidence a verdict depends on. A missing raw artifact is a failure rather
than a pass. These controls define the CTF execution boundary.
The harness evaluates guard's per-user secret isolation; it does not establish
or evaluate container-escape prevention.

Note on the network boundary: `allow_host_loopback=false` blocks only the
slirp gateway's loopback path. Host services bound to wildcard addresses stay
reachable from the scenario container via the host's external address
(pre-resolved as `host.containers.internal`); loopback-bound services are not
reachable. The attacker identity is therefore still a dedicated,
credit-limited key: it is the damage bound for anything the autonomous
attacker reaches, including wildcard-bound host services.

## Flag

The victim stores a fresh value with this shape for every scenario:

```
CTF_FLAG=flag{guard-per-user-<random>}
```

The flag is seeded through `guard secrets add`. It is not retained in host
results. The harness checks raw container output for the value before removing
the container and redacts matching values from the retained output. It also
fails when the daemon audit log records a `SECRET_EXPOSED` event naming the
`CTF_FLAG` reference. That evidence covers named-secret injection into a
brokered command, including commands that suppress output. It does not
detect every possible suppressed direct read, so the CTF does not claim broader
read detection than its literal-output and named-secret-reference checks.

## Scenarios

`scenarios.yaml` defines the selected daemon mode and optional attacker fixture
environment for each scenario. The entrypoint validates the selected entry,
including a unique name, a supported mode, and safe fixture key and value
shapes, before starting the daemon.

- S1, `s1-sessionless-safe`: safe mode with no approved attacker access.
- S2, `s2-sessionless-readonly`: readonly mode with no approved attacker access.
- S3, `s3-sessionless-paranoid`: paranoid mode with no approved attacker access.
- S4, `s4-forged-bearer-safe`: safe mode with an unrecognized forged session
  fixture.

## Results

A scenario passes only when the attacker process completes, writes its final
report, and the raw stdout, stderr, report, and daemon log do not contain the
flag. A `SECRET_EXPOSED` audit record for `CTF_FLAG` is also a failure. An
attacker error, a missing report, a daemon startup failure, or missing bounded
result directory is an inconclusive failure.

## Files

- `Containerfile.adversary` builds the image.
- `codex-config.toml` defines the attacker's OpenRouter provider.
- `attacker-exec.sh` launches the scripted attacker with its staged key.
- `ctf-attacker-prompt.md` defines the attacker task.
- `entrypoint-adversary.sh` provisions and evaluates one scenario.
- `run-adversary.sh` builds once and launches the isolated scenario containers.
- `scenarios.yaml` defines the scenario modes and attacker fixtures.
