# Typed verbs and coverage

Verbs are Guard's typed operation interface. A verb fixes a binary, validates
parameters, describes credential and execution plans, declares consequence, and
optionally supplies rollback. The daemon loads an operator catalog through
`--verbs` or `GUARD_VERBS`. Foreground servers hot-reload catalog changes. The
packaged Windows service loads its administrator-owned catalog once at startup.
Other service managers can select the same immutable startup mode with
`--immutable-verbs-lock`, using a writable lock path separate from the catalog.

```bash
guard verb list
guard verb show scale-deployment
guard verb run scale-deployment --param name=web --param replicas=2 --param namespace=production
```

The requester view of `guard verb show` prints the ordered argument template
and each parameter's anchored pattern. This makes absolute-path and other value
conventions visible before invocation. Executable, credential, provenance, and
trust metadata remain available only in the operator view.

[`examples/verbs.yaml`](../examples/verbs.yaml) contains command-template and
coverage-cell examples. A catalog may declare `platform: unix` or
`platform: windows`; Guard rejects a catalog for a different platform during
linting and startup.

On file-backed deployments, operators add one catalog entry from a YAML file
containing exactly one verb definition:

```bash
guard verb add --file inspect-service.yaml
```

The daemon validates the candidate and the complete catalog before atomically
appending it. The command fails without changing the catalog when the name
already exists or the definition is invalid. Generated and reserved verb
identities are not accepted through this operator-authored boundary. Adding a
verb requires operator authentication.

Operators replace one catalog entry from a YAML file containing exactly one
verb definition:

```bash
guard verb amend scale-deployment --file scale-deployment.yaml
```

The client reads the live definition first and binds the amendment to its
definition digest. The daemon rejects the write if another catalog edit lands
between that read and the replacement. It validates the candidate and complete
catalog before atomically replacing the catalog file. The replacement must
retain the requested name. Runtime-generated, automatically promoted, and
reserved-namespace verbs cannot be amended through this command. Like other
catalog mutations, amend requires the admin bearer.

The packaged Windows service treats the installed catalog as immutable process
input and disables automatic promotion. Administrators update that catalog
while the service is stopped, then restart the service to load the new bytes.

## Linting a catalog

`guard verb lint` validates a catalog file directly, without contacting or
starting a daemon. It reports every invalid verb, naming the verb and the
failing parameter, instead of stopping at the first failure, and exits 1 when
findings exist. Linting a catalog with the new binary before swapping binaries
turns a would-be startup abort into a pre-upgrade report:

```bash
guard verb lint --file /var/lib/guard/verbs.yaml
guard verb lint --fix
```

Without `--file`, lint reads `GUARD_VERBS` or the daemon's default catalog
path. A structurally valid catalog whose verbs are not in canonical form also
exits 1 and names each verb needing repair; `--fix` applies the same
canonicalization the daemon performs at load time (operator-boundary
normalization and generated-authority envelopes) and rewrites the file through
the same atomic replacement path, printing each repaired verb.

## Command templates

A template renders each `{param}` as one argv element without a shell or word
splitting. Parameter patterns are fully anchored. A value cannot begin with `-`
unless the parameter explicitly permits it, which prevents parameter and flag
injection.

Shell interpreters are not valid verb binaries because a script and everything
it dispatches cannot be bound as closed process authority. Catalog linting and
server startup reject these entries with guidance to invoke a supported
profiled executable directly, before a script can fail at execution time.

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

Parameters use `token` semantics by default and cannot contain whitespace.
Use `value_type: single_argv` with a required `max_length` only for a narrow,
bounded value that must retain ordinary spaces inside one argv element, such as
an exact query or selector. `single_argv` values remain unsplit and reject
control characters and shell operators. Automatically promoted verbs use this
form only when their finite observed values contain whitespace, with the bound
derived from those values.

`hold: true` routes every matching operation to operator approval after policy
admission, including operations declared `reversible`. Use it for reads whose
scope or sensitivity requires review, such as bulk account enumeration. The
field defaults to `false` when omitted.

## Coverage cells

Coverage cells describe regions of ordinary tool argv. They can constrain exact
required and forbidden tokens, option spellings and values, positional targets,
inventory, namespace, bounded fanout, an exact canonical working directory, and
caller-requested environment bindings.
Their actions are `preauthorized`, `evaluate`, or `deny`; preauthorization
requires a trusted verb.

Use `required_args` for independent exact tokens and complete joined option
tokens such as `--mode=check`. An option whose value is a separate argv element
uses an `options` value constraint so the selected value remains bound to that
specific option regardless of argument order.
Generic kubectl cells bind the parsed local subcommand with
`command_path`. Guard compares that path at the tool grammar boundary, before
matching ordinary argv constraints, so a command name in a resource name or in
kubectl's remote argv cannot select unrelated coverage. A cell may omit
`command_path` only for `evaluate` or `deny`, when `required_args` contains
exactly one recognized local subcommand. Preauthorized cells always declare it.

```yaml
  - name: kubernetes-pod-read
    binary: kubectl
    consequence: reversible
    trusted: true
    coverage:
      - name: staging-pods
        action: preauthorized
        command_path: [get]
        required_args: [pods]
        namespace:
          options: [-n, --namespace]
          values: [staging]
```

A non-matching cell has no decision. The pod-read cell above allows its bounded
region and does not deny kubectl mutation, SSH inspection, or any other command. Those
areas follow their own matching cells or evaluator path.

Recognized local-file operands in command and rollback templates must be
absolute. The bounded grammar covers documented option values, including
`key=path` and `label@path` payloads. Kubernetes endpoint, context, user, and
impersonation selectors are literals or finite operator-enumerated sets. Direct
credential arguments such as bearer tokens and passwords are not eligible for
static coverage; fixed-identity kubectl receives only the generated active-proxy
kubeconfig. Fixed paths identify artifacts in the daemon's
operator-controlled filesystem trust boundary and must not point into
caller-writable locations. Guard revalidates these artifacts and an authorized
working tree at process start, rejects symlinks, reparse points, and unsafe
ownership or permissions, and retains pinned handles for the child lifetime.
Directory-valued authority is checked recursively, including every nested
directory and regular file. Caller-selected local input is available only
through an exact typed template, is included in the process-lifetime artifact
set, and cannot enter through evaluator-only or untyped replay authority. The
daemon resolves the primary executable to a canonical absolute path. Typed
tools also bind their server-owned executable search directories. System
executable directories use their package-managed trust boundary. Every direct
regular file and resolved link target in a custom directory is pinned, including
files that are not executable when the request starts, so a caller cannot use a
later content or mode change to introduce a child executable. Guard replaces
aliases in the child PATH with the canonical retained directories. Kubernetes
file and kustomization sources are local absolute paths or standard input, not
caller-selected URLs. File-producing tool
operations use standard output where supported; static coverage does not grant
a caller-selected filesystem output path, positional output directory, or local
copy destination.
Transport passthroughs are fixed literals in exact templates, never
caller-selected generic coverage. Unknown kubectl subcommands are treated as
external plugins and do not receive static coverage. Ambiguous command grammars
that cannot be modeled safely do not receive file-path coverage.

Kubeconfig paths are literals or finite exact parameter sets because kubeconfigs
can invoke credential plugins; generic coverage and open-ended path patterns
cannot select them. Process admission accepts only the complete generated
kubeconfig matching an active Guard proxy.

Environment sources are `plain`, `secret`, and `secret-file`. A constraint may
name exact `values` or a fully anchored `pattern`. A cell with no environment
constraints cannot preauthorize a request that adds caller-controlled bindings;
that request returns to the evaluator. Kubectl configuration and credential
paths use typed fixed values. Tool-prefixed environment variables without a
classification do not receive static coverage. Typed tools also reject
unclassified injected environment variables, including names without a tool
prefix. Fixed-identity execution rejects `secret` and `secret-file` delivery
even when a typed cell classifies the binding; the shared UID is not an
execution-isolation boundary. It accepts kubectl only with an immutable
`KUBECONFIG` matching an active Guard proxy and disables kuberc and command
shadowing. Ansible and Helm are denied in fixed mode because their mutable
profile state cannot safely cross identities. Caller mode denies all three
typed profile tools because it has no immutable profile snapshot.
Automatically promoted cells never preauthorize environment bindings.

`cwd` binds a cell to one existing, absolute canonical directory. Guard
canonicalizes the caller directory before coverage resolution, recursively
validates the tree, and holds its trusted directory handles for the child
lifetime. This bounds tools that discover configuration, plugins, or input files
from a project tree. It does not make mutable Ansible, Helm, or caller kubectl
profiles admissible. A protected typed tool with no explicit `cwd` starts from
a fixed operating-system directory rather than inheriting the daemon's launch
directory. Cwd-dependent opaque carriers do not enter automatic verb promotion.
Only tools with a built-in structured profile can receive typed durable authority.
Operator-authored catalogs use the same positive executable-profile registry as
process admission. The primary-only profiles are `cat`, `df`, `echo`, `false`,
`free`, `hostname`, `id`, `ls`, `printf`, `printenv`, `ps`, `pwd`, `tail`, `true`,
`uptime`, and `whoami`. Ansible, kubectl, Helm, and `systemctl` have structured
grammars, but grammar recognition does not bypass identity-mode admission.
Fixed-identity active-proxy kubectl, literal non-starting `systemctl`, and
primary-only profiles can execute. Ansible and Helm cannot execute in either
identity mode, and caller-mode kubectl cannot execute. Shells, language runtimes,
SSH, Git, generic command-dispatch binaries, and every unknown executable have
no profile and are rejected. Executable support requires a built-in profile
that lets Guard fingerprint the complete primary artifact and validate its
invocation grammar.

A command that may execute after an approval or restart gap also requires a
built-in delayed-execution grammar and a mode-compatible executable profile.
Fixed-identity active-proxy kubectl commands, literal non-starting `systemctl`
operations, and profiled primary-only utilities satisfy that boundary. Ansible,
Helm, and caller-mode kubectl cannot enter executable durable state. Unknown
executables, SSH, wrappers, file-testing utilities, and commands that discover
program or configuration files cannot be held or registered as unattended
checks or rollbacks. Raw evaluator approval does not supply that authority.

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

`guard verb create --preview` safety-checks and validates a synthesized
candidate, then keeps it only in a bounded in-memory review cache. The preview
does not enter the active catalog. Direct creation and
`guard verb create --from-preview` enumerate every finite parameter binding and
run each rendered command through the production evaluator admission path with
execution disabled. A denial, non-finite pattern, or candidate set above the
admission bound prevents catalog persistence.

`guard access request` synthesizes typed coverage when no existing verb matches
the normalized intent. Proposed verbs cannot be baseline or trusted, use a
shell or interpreter binary, or accept unbounded whitespace or shell-control
patterns. A bounded `single_argv` parameter may carry an exact finite value
with ordinary spaces inside one argv element. Approval promotes only the
reviewed matcher to trusted
session-scoped coverage. The durable request stores the proposal and restores
it from SQLite while its access session is active. Guard derives consequence
locally, so unknown or mutating generated shapes remain irreversible holds. The
operator-authored catalog is unchanged. Equivalent typed shapes are reused
instead of duplicated.

With consequence gating active, repeated eligible evaluator approvals can
promote exact observed, statically read-only shapes into trusted verbs. Parameter
patterns contain only escaped values supported by evidence. Irreversible and
recoverable shapes are not auto-promoted: mutating commands remain under
consequence gating or operator review, and a model-proposed rollback never
creates unattended authority. An auto-promoted verb never carries a consequence
above `reversible`. Promotion records the evaluator regime, and a
model or prompt change sends stale coverage back to evaluation.

Auto-promoted verbs are marked `auto_promoted` in `guard verb list`, and their
coverage provenance states how it was produced: `observation_replays` record
the observed evaluator decisions a matcher was derived from, plus the
generator's own boundary example. Provenance `probes` are reserved for checks a
generator actually executed against the finished matcher; automatic promotion
records none.

API traffic uses the same verb vocabulary. Generated API cells bind endpoint,
session fingerprint, full session revision, operation, namespace, body shape,
protocol authority selectors, evaluator regime, and expiry. Authority selector
identity includes attached option aliases, so changing an attached alias or the
session revision requires a fresh evaluation. Value-bearing mutations remain
evaluator-routed. Inspect or reset generated cells with:

```bash
guard verb coverage list
guard verb coverage clear
```

Generated coverage is an acceleration layer inside existing authority, not a
new authority source.
