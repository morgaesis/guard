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
inventory, namespace, bounded fanout, and caller-requested environment bindings.
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
          values: [inventory/production]
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

Environment sources are `plain`, `secret`, and `secret-file`. A constraint may
name exact `values` or a fully anchored `pattern`. A cell with no environment
constraints cannot preauthorize a request that adds caller-controlled bindings;
that request returns to the evaluator. Automatically promoted cells never
preauthorize environment bindings.

## Reverse matching

Agents may call `guard verb run`, but raw commands also reverse-match the verb
catalog. Guard collects every applicable cell, so the typed catalog remains
authoritative without forcing agents to translate familiar commands.

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
applicable cells. Held or denied human output identifies matching verbs and
guidance so an agent can request the exact grant change.

## Baseline and session activation

`baseline: false` keeps a verb inactive until an issued grant names it. A session
may activate that verb or replace matching baseline preauthorization. A baseline
`evaluate` or `deny` cell with an `override_marker` changes only when the session
carries the same operator marker. Automatically generated verbs cannot declare
markers.

This split permits a readonly daemon baseline and a short-lived grant for apply
mode on one host without making broad apply authority global.

## Generation and promotion

An operator can synthesize a validated verb from prose:

```bash
guard verb create --preview --binary cmk \
  --prompt 'List one CloudStack VM by UUID.'
guard verb create --binary cmk \
  --prompt 'List one CloudStack VM by UUID.'
```

Synthesized verbs cannot be trusted, use a shell or interpreter binary, or
accept patterns with whitespace and shell metacharacters. The catalog records
the source prose and rationale.

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
