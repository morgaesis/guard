# Typed verbs and coverage

Verbs are Guard's typed operation interface. A verb fixes a binary, validates
parameters, describes credential and execution plans, declares consequence, and
optionally supplies rollback. The daemon loads an operator catalog through
`--verbs` or `GUARD_VERBS` and hot-reloads it on change.

```bash
guard verb list
guard verb show restart-service
guard verb run restart-service --param unit=nginx
```

[`examples/verbs.yaml`](../examples/verbs.yaml) contains command-template and
coverage-cell examples.

Operators replace one catalog entry from a YAML file containing exactly one
verb definition:

```bash
guard verb amend restart-service --file restart-service.yaml
```

The client reads the live definition first and binds the amendment to its
definition digest. The daemon rejects the write if another catalog edit lands
between that read and the replacement. It validates the candidate and complete
catalog before atomically replacing the catalog file. The replacement must
retain the requested name. Runtime-generated, automatically promoted, and
reserved-namespace verbs cannot be amended through this command. Like other
catalog mutations, amend requires the admin bearer.

## Command templates

A template renders each `{param}` as one argv element without a shell or word
splitting. Parameter patterns are fully anchored. A value cannot begin with `-`
unless the parameter explicitly permits it, which prevents parameter and flag
injection.

```yaml
verbs:
  - name: service-status
    description: Show one service status
    binary: systemctl
    args: [status, "{unit}", --no-pager]
    params:
      unit: { pattern: "^[a-zA-Z0-9@._-]+$", required: true }
    consequence: reversible
    trusted: true
```

`trusted: true` skips the evaluator for a matching operation, but it does not
skip the consequence gate or hard invariants. Untrusted verbs keep the evaluator
as a backstop.

## Coverage cells

Coverage cells describe regions of ordinary tool argv. They can constrain exact
required and forbidden tokens, option spellings and values, positional targets,
inventory, namespace, bounded fanout, an exact canonical working directory, and
caller-requested environment bindings.
Their actions are `preauthorized`, `evaluate`, or `deny`; preauthorization
requires a trusted verb.

```yaml
  - name: ansible-baseline
    binary: ansible
    consequence: reversible
    credential_plan: ansible-managed-ssh
    trusted: true
    coverage:
      - name: bounded-check
        action: preauthorized
        required_args: [--check]
        inventory:
          options: [-i, --inventory]
          values: [/srv/guard/inventory/production]
        fanout:
          options: [--limit]
          max: 2
        environment:
          - name: ANSIBLE_CONFIG
            source: plain
            values: [ansible.cfg]
      - name: bounded-apply
        action: evaluate
        forbidden_args: [--check]
        fanout:
          options: [--limit]
          max: 1
        override_marker: operator:ansible-apply
```

A non-matching cell has no decision. The check cell above allows its bounded
region and does not deny apply mode, SSH inspection, or any other command. Those
areas follow their own matching cells or evaluator path.

Known file operands in command and rollback templates must be absolute. Ansible
inventory coverage likewise accepts only absolute paths or explicit inline host
lists. If an explicit-inventory Ansible process reports that no inventory was
parsed, or that every supplied source was unusable, Guard converts exit 0 to a
failure and emits a diagnostic.

Environment sources are `plain`, `secret`, and `secret-file`. A constraint may
name exact `values` or a fully anchored `pattern`. A cell with no environment
constraints cannot preauthorize a request that adds caller-controlled bindings;
that request returns to the evaluator. Automatically promoted cells never
preauthorize environment bindings.

`cwd` binds a cell to one existing, absolute canonical directory. Guard
canonicalizes the caller directory before coverage resolution and revalidates it
immediately before execution, so a changed directory or symlink retarget cannot
reuse the cell. This bounds tools that discover configuration, plugins, or input
files from a project tree. Cwd-dependent opaque carriers do not enter automatic
verb promotion; an operator-authored typed verb supplies their durable authority.

## Reverse matching

Raw commands and access intents reverse-match the verb catalog. Guard collects
every applicable cell, so the typed catalog remains authoritative without
forcing agents to translate familiar commands.

Resolution follows these constraints:

1. Hard invariants and explicit sticky operator boundaries are absolute.
2. Session coverage applies over baseline coverage only inside activated regions.
3. More specific cells win over broader cells in the same scope.
4. Compatible matches compose with the most conservative consequence.
5. Equally specific incompatible credential, execution, or rollback plans return
   to the evaluator as one conflict packet.
6. If evaluation cannot produce one safe plan, the request holds. Authorization
   ambiguity fails closed with an escalation handle.

Catalog name order never chooses credentials or rollback. Global generated
coverage cannot defeat an explicit operator deny. A live session can evaluate
past matching global generated coverage under its own intent, while protocol
hard-denies and operator policy remain floors.

Successful human output stays quiet. Machine-readable run results include all
applicable cells. Held or denied human output identifies matching verbs and one
durable access request. Denials offer ordinary, one-time, and bounded approval;
holds offer only one-time approval.

## Baseline and session activation

`baseline: false` keeps a verb inactive until an issued grant names it. A session
may activate that verb or replace matching baseline preauthorization. A baseline
`evaluate` or `deny` cell with an `override_marker` changes only when the session
carries the same operator marker. Automatically generated verbs cannot declare
markers.

This split permits a readonly daemon baseline and a short-lived grant for apply
mode on one host without making broad apply authority global.

## Generation and promotion

`guard access request` synthesizes typed coverage when no existing verb matches
the normalized intent. Proposed verbs cannot be baseline or trusted, use a
shell or interpreter binary, or accept patterns with whitespace and shell
metacharacters. Approval promotes only the reviewed matcher to trusted
session-scoped coverage. The durable request stores the proposal and restores
it from SQLite while its access session is active. Guard derives consequence
locally, so unknown or mutating generated shapes remain irreversible holds. The
operator-authored catalog is unchanged. Equivalent typed shapes are reused
instead of duplicated.

With consequence gating active, repeated eligible evaluator approvals can
promote exact observed shapes into trusted verbs. Parameter patterns contain
only escaped values supported by evidence. Irreversible shapes are ineligible;
recoverable shapes require validated rollback. Promotion records the evaluator
regime, and a model or prompt change sends stale coverage back to evaluation.

API traffic uses the same verb vocabulary. Generated API cells bind endpoint,
session fingerprint, operation, namespace, body shape, regime, and expiry.
Value-bearing mutations remain evaluator-routed. Inspect or reset them with:

```bash
guard verb coverage list
guard verb coverage clear
```

Generated coverage is an acceleration layer inside existing authority, not a
new authority source.
