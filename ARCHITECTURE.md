# Architecture

Source of truth hierarchy:

1. `src/server/` -- privileged guard daemon: request protocol, policy evaluation, command execution, environment isolation, and output redaction.
2. `src/evaluate.rs` -- LLM evaluator: prompt selection, OpenAI-compatible API calls, response parsing, token usage tracking.
3. `src/main.rs` and `src/cli_*.rs` -- operator-facing CLI: `main.rs` holds the clap command tree and dispatch; `cli_server.rs` the daemon startup path, `cli_client.rs` the client commands (run/exec, gate actions, verbs, grants, sessions, status, config, MCP serve), `cli_secrets.rs` secret management, `cli_shim.rs` shim management.
4. `src/session.rs` and `src/session_store.rs` -- session grant model, retention rules, and SQLite-backed persistence for grants, session interaction history, and consequence-gating runtime state (provisional executions and operator approvals).
5. `src/mcp.rs` -- stdio MCP facade: exposes `guard_run` tool for agent clients, backed by the daemon protocol.
6. `src/gating/` -- consequence-gating model. `mod.rs` holds the shared protocol types (`Reversibility`, `GateMode`, `Coverage`) and the pure routing function `decide_gate`. `provisional.rs` and `approval.rs` are the containment-envelope and operator-approval state machines (pure: the daemon supplies the clock, exec, and persistence). `verb.rs` is the operator-authored verb catalog (typed templates, anchored-pattern validation, rendering, and reverse-matching a raw command against the catalog). `deny_shape.rs` and `allow_promotion.rs` are the automatic deny- and allow-side learning stores. `read_grant.rs` is the scoped POSIX-ACL read-grant model: the grant record and registry, the static credential-path deny-list, TTL bounds, and the ancestor-directory plan (pure; the daemon runs setfacl/getfacl and supplies the clock).
7. `src/principal.rs` -- `PrincipalKey`, the cross-platform caller/daemon identity. A Unix uid and a Windows named-pipe SID are both wrapped as a `PrincipalKey`; every operator/owner comparison, secret-namespace scoping, and gating-authorization decision is expressed against this type. The only platform-specific code is how the key is produced (a uid string on Unix, a SID string on Windows); all downstream comparisons are shared.
8. `src/proxy/` -- protocol-agnostic REST API proxy. Pure, unit-tested layers: `op.rs` is the protocol-neutral operation vocabulary (`ApiOp`/`Verb`); `policy.rs` is the operator-authored, first-match-wins `ApiPolicy`; `upstream.rs` builds the authenticated upstream client (from the operator kubeconfig for Kubernetes, from a base URL plus bearer token for other protocols); `kubeconfig.rs` generates and credential-validates the brokered kubeconfig; `tls.rs` is the ephemeral CA and terminating server config. `protocol.rs` is the `ProtocolConfig` plug-in surface (request parsing, outright denials, redaction, revert synthesis); `k8s.rs` and `k8s_protocol.rs` are its Kubernetes reference implementation, `github_protocol.rs` and `vercel_protocol.rs` example plug-ins. `server.rs` is the `ApiProxy` accept loop that wires them to a live upstream, routing every protocol-specific question through the attached `ProtocolConfig`, and `gate.rs` is the `GateSink` bridge by which the proxy hands synthesized HTTP reverts to the daemon's consequence machinery.

## API proxy

The command gate sees a command's argv, but tools that drive an HTTP API in-process (helm via client-go, terraform providers, k9s, client libraries, SDK calls) never spawn a gated command. `guard server start --api-proxy ADDR --api-protocol NAME` moves the gate to the API boundary: the daemon terminates a brokered client's TLS, parses each request into a typed operation through the protocol plug-in, matches it against the operator policy (`--api-policy`, hot-reloaded; see `examples/api-policy.yaml`, `examples/github-policy.yaml`, `examples/vercel-policy.yaml`), and re-originates allowed requests to the real upstream with the credentials only the daemon holds. `--kube-proxy ADDR` is shorthand for the Kubernetes protocol.

Containment rests on the daemon holding the only credential. For Kubernetes the daemon reads the real bearer token or client certificate from its kubeconfig (exec/auth-provider plugins are rejected because the proxy cannot run them and they would let a client mint credentials), and emits a brokered kubeconfig (`--brokered-kubeconfig-out`) that points only at the proxy and is validated to carry no `token`/`client-certificate`/`exec`/`auth-provider`/`password` field. For other protocols the daemon reads a bearer token from an environment variable (`--api-token-env`) or file (`--api-token-file`), never from a command-line value, and `--api-ca-out` writes the proxy's CA certificate so generic clients can trust the TLS termination. With the agent pointed at the proxy and no other credentials reachable, the proxy is the sole path to the upstream. `--api-proxy` refuses to start with `--exec-as-caller`, which would run a child as the caller and let it read caller-owned credentials around the gate, and refuses a non-loopback bind address, since the proxy authenticates nothing itself and a reachable port would offer the daemon's upstream credential to the network.

Policy actions are `allow`, `deny`, `hold`, and `evaluate`. An `evaluate` rule (or `default: evaluate`) sends the request to a dedicated LLM evaluator whose system prompt embeds the policy's `intent` prose (operator-authored, top-level in the policy file) and a REST risk doctrine; the per-request input is a stable redacted summary (verb, path, query, typed operation fields, a body key-skeleton with leaf values replaced by type tokens, and whether an auto-revert is constructible for this exact operation), which doubles as the evaluator cache key. Reversibility is an input to the decision: a constructible revert can make a borderline recoverable operation approvable. The verdict never bypasses the deterministic floor: an allow is routed through `decide_gate`, so a recoverable verdict forwards only inside the auto-revert envelope, an irreversible or uncertain verdict is held, and a deny or evaluator error fails toward the operator queue. With rarity escalation on, a statistically rare shape under a broad allow rule is judged with an explicit rarity flag instead of holding blind. An intent change in the hot-reloaded policy rebuilds the evaluator (and its cache), and a policy that routes to `evaluate` with no LLM configured holds those requests fail-closed. A `hold` parks the buffered request in the same approval queue as held commands: the daemon enqueues an `Approval` row (sentinel binary `(api-proxy)`, owned by the daemon principal) and the proxy blocks the client until `guard approve` releases the request to the upstream or `guard deny`/TTL expiry fails it closed. Approving a proxy row never spawns a process — the sentinel branch in the daemon's approve handler wakes the parked waiter instead, and the sentinel cannot be forged into that branch because the row must also carry the daemon principal, which peer credentials assign only to the daemon's own sink. A hold whose waiter vanishes (client disconnect) or that survives a restart is retired, so the queue never offers an approval that releases nothing; a proxy running without `--gate consequence` has no queue, so `hold` rules deny fail-closed. An allowed read of secret-bearing material is redacted by the protocol's own classification regardless of the rule flag (Kubernetes Secret `data`/`stringData`, GitHub secret-store reads, Vercel env-var values), which upstream RBAC and admission control cannot do; a secret-bearing response that is not parseable JSON fails closed rather than streaming through. Uninspectable streams are denied outright per protocol (Kubernetes `exec`/`attach`/`portforward`/`proxy` and `pods/ephemeralcontainers`, Secret `watch`es, GitHub repository archives, Vercel deployment log streams). A write to any other subresource is authorized only by a policy rule that names it in `subresources`: a plain resource write rule covers the bare resource and its read subresources but never a write subresource, because a write subresource can carry effects the parent verb does not model (evicting a pod, changing a replica count, minting a token).

Under `--gate consequence`, a recoverable write the policy allows is wrapped in the auto-revert envelope. The protocol plans the revert as a plain HTTP request: before an update/patch the proxy snapshots the prior object and the revert restores it (Kubernetes: a `PUT` of the prior object with `resourceVersion` stripped so the restore is unconditional); a create's revert deletes the server-named object (Kubernetes: with background cascade, matching the kubectl delete default); a delete the protocol declares faithfully recreatable snapshots the object first and the revert recreates it (Kubernetes: a `POST` of the snapshot with server-owned metadata and `ownerReferences` stripped, since stale owner uids would make garbage collection remove the restore immediately; GitHub: label deletes; Vercel: env-var deletes). A created object is recorded keyed to the creating connection, so a delete of that same object on the same connection is recognized as contained cleanup that resolves the pending create-revert rather than an unrecorded destructive delete; subresource writes are never tracked, so a subresource that echoes an object name (an eviction) cannot seed provenance for an object it did not create. The planned revert is handed to a `GateSink`, which the daemon implements by arming a `Provisional` in the shared registry; the sweeper executes a due revert as an HTTP request through the registered proxy's upstream with the daemon's credential, and fails it loudly if no proxy for that protocol is running. `guard confirm` / `guard provisionals` / `guard revert` apply unchanged.

`github_protocol.rs` and `vercel_protocol.rs` are example `ProtocolConfig` implementations over the GitHub REST v3 and Vercel REST shapes, exercised end to end in `tests/protocol_examples.rs` against hit-recording mock upstreams. They prove the plug-in surface generalizes and are wired to the CLI via `--api-protocol github|vercel`, but are illustrative rather than production integrations. Both parse their routes into the same typed operation the policy matches (repository/organization and project identifiers become the namespace), deny uninspectable streams outright, write-deny GitHub credential stores including nested re-entries, and redact secrets-like reads. Redaction is forced by the protocol's classification of the operation, never by policy wording.

## Execution flow

```
Agent -> guard run <cmd> -> Client -> Server -> Evaluator -> LLM API
                                                    |
                                              Static Policy (optional)
                                                    |
                                              Execute command
                                                    |
                                              env_clear + allowlist
                                                    |
                                              Per-run/tool secret injection
                                                    |
                                              Output redaction
                                                    |
                                              Stream/output response to agent
```

## Security layers

1. **Environment isolation**: `cmd.env_clear()` strips all environment variables from child processes. Only safe variables are re-injected (`PATH`, `HOME`, `USER`, `LANG`, `TERM`, `TZ`, `SHELL`, `LOGNAME`, `XDG_RUNTIME_DIR`), followed by explicit per-run env/secret injections, tool-configured env/secrets, or daemon `--child-env` passthroughs. Ambient caller configuration and credential variables such as `ANSIBLE_CONFIG` and `SSH_AUTH_SOCK` are not inherited. Caller-supplied `SSH_AUTH_SOCK` injections are rejected; a Guard-configured broker socket is forwarded like any other trusted tool or daemon-owned variable. Per-run env/secret injections cannot replace tool-configured or daemon child-env values; collisions fail before exec.

2. **Preflight** (optional, opt-in via `--preflight`): Two deterministic pre-LLM checks. Executable validation rejects binaries not present on the daemon `PATH`, so natural-language first tokens such as `Give` or `Please` never reach the model as prose. Credential preflight rejects known credential-disclosure patterns (private key paths, guard environment files, kubeconfig raw output, Kubernetes Secret access, token minting, process environment reads). These are coarse by design and can over-match (e.g. they block any command containing the `env` token). Enable on hosts where LLM cost or latency dominates over false positives; leave off where the LLM is the authoritative decision maker.

   Invariant checks still run regardless of `--preflight`: binary names containing `/`, `..`, or NUL are rejected, and recursion depth is capped.

3. **Output redaction**: Known secret values (API key, auth token, tool-injected secrets, per-run injected secrets) are exact-match redacted from stdout/stderr. Pattern-based redaction (`src/redact.rs`) then catches secret-shaped content guard has never seen: key names ending in a secret-bearing word (`*_TOKEN=`, `apikey`, `secretkey`, ...) in env, YAML, and quoted-JSON form; adjacent Kubernetes `name:`/`value:` pairs across lines and single-line flow-style `name`/`value` pairs; PEM blocks; JWTs; `sk-*`/`AKIA*` keys; `Bearer`/`Basic` header tokens; bare high-entropy runs (64+ char mixed-case URL-safe base64, the CloudStack key shape); and a `NAME=<high-entropy value>` catch-all. Redaction is on by default and applies to both streamed and buffered output; `--no-redact` disables output redaction only, while LLM-bound text is always pre-redacted. The same engine also runs on every piece of untrusted text sent to the LLM (`redact_for_llm`): the evaluated command, session context, verb-synthesis prose, deny-shape evidence, and verb-promotion samples - the model never sees an unredacted secret either.

4. **LLM evaluation**: Commands are sent to an LLM with a mode-specific system prompt. The LLM analyzes intent, chained operations, obfuscation, tool side-channels, and prompt injection attempts. Returns `APPROVE`/`DENY` with risk score.

5. **Decision cache**: An in-memory LRU-style cache of evaluator decisions, keyed on the exact command line. Cache hits return the stored `Allow`/`Deny` without another LLM call. The cache is owned by a single `Evaluator` instance, so restarting the daemon or changing the prompt gives a fresh cache. Both approve and deny decisions are cached; transient evaluator errors are not. Size and TTL are configurable (`--cache-capacity`, `--cache-ttl`, `GUARD_CACHE_*`); disable with `--no-cache` / `GUARD_CACHE=false`.

6. **Saved grants and issued sessions** (`src/grant_profile.rs`, `src/session.rs`, `src/session_store.rs`): A saved grant activates typed verbs, selects an evaluation mode, carries evaluator context and secret-name entitlements, declares a default TTL, and bounds automatic expansion with a ceiling. Issuing one creates a live bearer-token session and records the saved-grant revision. Session verb coverage expands ordinary baseline read-only or evaluator coverage inside its activated regions. A baseline cell with an explicit override marker requires the same marker on the session, while sticky cells remain absolute. Binary allow-lists, credential checks, consequence routing, held-command binding, read-grant retry, audit, and history remain independent controls. Durable grant-request handles let agents submit or withdraw an expansion and give operators an exact approve or deny command. Requests within an auto-approval ceiling apply immediately. Denials include the handle and next action. Saved grants, requests, sessions, transitions, and bounded interaction history persist in SQLite; session records include only names of exposed secrets, never values. Legacy profiles and unambiguous exact command patterns migrate deterministically into saved grants and typed verb coverage. Ambiguous globs fail loading.

7. **Static policy** (optional, opt-in): a global pre-evaluator deny fast path and evaluator-intent source. Compatibility `commands.allow` entries serve evaluator-disabled deployments but never skip an enabled evaluator. Public scoped authorization is expressed through typed verbs and saved grants rather than session globs.

8. **Verb catalog** (optional, opt-in via `--verbs`): an operator-authored, hot-reloaded catalog of typed operations, and the primary structured mechanism for deterministic, LLM-skipping authorization. Each verb fixes a binary and may define an argv template with pattern-validated, anchored parameters. Rendering substitutes each placeholder as exactly one argv element, so parameter and flag injection are structurally impossible. A verb can also define typed coverage cells over required and forbidden argv elements, option values, positional targets, inventory, namespace, and list fanout. Each cell is `preauthorized`, `evaluate`, or `deny`; an unmatched cell has no effect and never denies its complement. A verb declares its consequence class and optional structured rollback. A preauthorized cell requires `trusted: true`, skips the evaluator, and retains the declared consequence routing.

   Reverse matching is collect-all and deterministic. `VerbCatalog::match_command_all` returns every applicable cell in canonical `(verb name, cell name)` order. The resolver applies semantic specificity within a scope, retains the most conservative consequence among compatible selected cells, and never chooses between incompatible execution, credential, or rollback plans by catalog order. Incompatible plans are sent to the evaluator as one canonical packet containing all applicable cells, including overridden and non-selected cells. An evaluator allow with no single resolved plan is held for operator approval.

   Baseline verbs apply without a session. A saved grant activates `baseline: false` verbs for an issued session. Session coverage supersedes ordinary baseline `evaluate` or `deny` cells in that activated region. A baseline cell may require an exact `override_marker`; a sticky cell cannot be overridden. Automatically generated verbs cannot mint override markers or replace sticky coverage. Binary allow-lists, credential checks, request validation, and consequence routing run independently. Execute responses expose applicable cells as `verb_matches` and include concise guidance on held or denied commands.

   `guard verb create --prompt "<description>"` (operator-only admin RPC) asks the evaluator LLM to synthesize one verb from prose, validates it exactly like a hand-authored verb, and appends it to the catalog with the prose and a short rationale recorded inline (`source_prose`, `evidence`); `--preview` shows the result without writing it. A synthesized verb is held to a safety gate the model cannot bypass: it is never `trusted` (the LLM still evaluates the rendered command at run time until an operator makes a deliberate manual edit to the catalog), the binary may not be a shell or interpreter, parameter patterns may not admit whitespace or shell metacharacters, and the name must be kebab-case.

   Automatic promotion feeds this same path. Repeated eligible evaluator approvals create trusted typed coverage with exact escaped evidence, positive and negative boundary probes, and model and prompt stamps. Reversible operations may promote; recoverable operations require a validated revert; irreversible operations never promote. A changed evaluator regime routes stale generated coverage back through evaluation. Promotion is automatic and never creates complement denies.

9. **Consequence gating** (optional, opt-in via `--gate consequence`): After an allow, the daemon routes the command by the available reversibility class. LLM approvals use the evaluator's class, trusted verbs use the verb's declared class, and session allows without a matched verb have no class and therefore hold. `reversible` (low-risk) executes immediately; `recoverable` executes inside a containment envelope that auto-reverts unless an operator confirms; `irreversible` (or high-risk, or unclassified) is held for operator approval and not executed. The operator is whoever runs as the daemon's own principal (its uid on Unix, its SID on Windows). Routing is fail-safe: a missing class holds, and reversibility can only raise the gate. Static-policy allows in the `--no-llm` fallback mode are the deterministic direct-exec path. The held command is bound to an immutable execution snapshot (binary, args, cwd, env, secret-key mapping, rendered verb, catalog version); approval executes that snapshot verbatim and a verb-catalog change since the hold voids it. A provisional carries the canonical working directory, original principal, session fingerprint, and secret-key mappings into its rollback and optional confirmation check. Secret values never enter the persisted row and resolve from the live store under the original caller's principal immediately before either command executes. Containment refuses plain per-run env because arbitrary values cannot be proven non-secret and have no safe live-store reference. A pre-spawn secret-resolution failure returns the provisional to `needs_operator_decision` so an operator can retry after restoring the secret. Provisional and approval state persist in the state database; startup recovery never fires a rollback unattended (past-deadline provisionals become `needs_operator_decision`). The evaluator assesses the forward command, rollback, optional confirmation check, deadline, and explicit or inferred control path as one envelope. The envelope holds when the forward action can plausibly sever the SSH, API, socket, credential, daemon, or local authority needed to verify or roll back. At the deadline, no check means rollback; check exit zero confirms; any other check outcome runs the rollback. A verb rollback is preauthorized, but an added check or explicit control path receives the same live complete-envelope assessment. A single sweeper task runs due checks or rollbacks after a startup grace and expires unattended holds with a fail-closed deny.

10. **Auto-learned deny shapes** (on by default; disable with `--no-learn-deny`): asymmetric with learned-rule candidate detection (8) on purpose. When the LLM denies the same command shape for a binary `--learn-deny-min-denials` times, the daemon asks its own LLM to synthesize a fully anchored regex over the observed argument evidence and, once validated (anchored, compiles, matches its own evidence, does not match shell-injection-shaped canary content), persists it as an automatic pre-LLM deny fast path with no operator step. This is safe unconditionally, unlike an equivalent allow-side shortcut: the store can only ever be populated from shapes the LLM already denied, so the worst case of an over-broad synthesis is an unnecessary block on something that should have been allowed, never a granted capability. A caller can force a fresh LLM look past an auto-learned deny with `--reevaluate` (`guard run --reevaluate` / the MCP `run` tool's `reevaluate` param); this never skips an operator-authored static-policy deny rule, only the auto-learned store, and its only effect is another real LLM call, never a grant. `guard session appeal` also always bypasses the auto-learned store, since an appeal is itself a request for a fresh look.

11. **Auto-verb-promotion** (`src/gating/allow_promotion.rs`; on by default, disable with `--no-learn-allow`; requires `--gate consequence`): the allow-side counterpart of (10), for deployments where an operator cannot review every notice -- most real installs run unattended, some air-gapped. Repeated low-risk LLM approvals of the same `(service, binary, first-arg, arity)` shape are bucketed with their argv evidence and reversibility votes. Once a bucket crosses `--learn-allow-min-approvals` and every vote in it agrees on the same class (`reversible` or `recoverable`; a bucket that ever saw `irreversible` or a disagreeing vote is permanently disqualified), the daemon derives an argv template by diffing the evidence positionally: a position constant across every sample stays a literal token; a position with more than one observed value becomes a parameter whose pattern is a plain anchored alternation of the *exact, regex-escaped* values actually seen -- never a model-authored regex, so there is nothing for a model (or a caller nudging one through many approved requests) to widen. A fully literal bucket (the same exact command approved repeatedly, no varying position) is appended as a trusted verb directly, no LLM call needed. A bucket with a varying position still asks the model once, but only to name the verb, judge whether generalizing over that *specific* position is coherent, and -- for a recoverable shape -- propose a revert; the result is re-validated from scratch (`validate_auto_promoted_verb_safety`) regardless of what the model returned, including re-rendering every evidence sample against the candidate template to confirm it round-trips.

    An irreversible shape is never even attempted: it always holds for operator approval regardless of `trusted` (see (9)), so promoting one buys no latency and only discards the per-instance LLM reasoning a human would see in the hold queue. A recoverable shape is promoted only with a validated revert, so the auto-revert envelope -- not the model's word -- absorbs the residual risk that a not-yet-observed enumerated value behaves differently than the evidence. A promoted verb is stamped with a hash of the model and prompts that justified it (`Evaluator::verb_promotion_stamp`); if either changes, the daemon silently stops trusting verbs promoted under the old judgment (`server::execute_command_inner` downgrades `trusted` to `false` on a stamp mismatch) without any operator action. There is deliberately no human notification anywhere in this path: the promoted-or-not state is fully visible at any time via `guard verb list` (auto-promoted entries carry `auto_promoted: true` and their provenance), which an operator can edit or delete like any other catalog entry -- distributing or syncing that catalog across a fleet is an operator concern, not this daemon's.

12. **API request-shape learning** (`src/gating/api_promotion.rs`; on by default, disable with `--no-api-promotion`): proxied API requests routed to `evaluate` record only real evaluator verdicts into a bounded YAML store keyed by the exact `(protocol, verb, group, resource, subresource, namespace)` tuple, excluding object name. Repeated eligible allows promote the tuple with the maximum observed risk and common reversibility class; repeated denies promote the tuple as a deny. A learned deny rejects before another evaluator call, and a learned allow reuses the stored verdict only when `rarity=false`; every allow still passes through `decide_gate`, so the consequence floor remains authoritative. Promotion and fast-path hits appear only in operator audit logs. Command denials expose only the caller's own repeated-denial count after the deny-shape threshold, not promotion state.

13. **Scoped read grants** (Unix, `src/gating/read_grant.rs` + the daemon's ACL layer): when a brokered command fails naming a file it could not read, the daemon runs the read-grant pipeline on that path and, on an allow, applies a short-TTL POSIX-ACL grant to guard's brokering account (or the caller's account under `--exec-as-caller`) before retrying the original command. The pipeline uses a hard credential-path deny-list before the evaluator, then session allow/deny rules, then the LLM. The plan captures each path's device and inode in the same pass as the policy checks and refuses a multi-hardlink target (the inode is reachable under other names); apply re-verifies every planned path through an `O_PATH` descriptor and addresses setfacl via the daemon's `/proc/<pid>/fd` entry, so a path component swapped for a symlink between evaluation and apply cannot retarget the grant. Ancestor directories receive traverse-only (`--x`) entries, never above the file owner's home. The grant row is committed before the ACLs are applied, so a crash mid-apply leaves a recoverable row; the sweeper revokes at TTL and startup reconciliation revokes any past-deadline row. Retry rounds are bounded, each round must unblock a new path, and a denied path surfaces the command's own failure unchanged.

## Admin authorization

Admin RPCs that mutate authorization state (session grant/revoke/appeal, grant-installing session creation, gate decisions, verb creation, detailed secret ownership inspection, and the full `status` snapshot) are gated separately from exec. Without this separation, an exec-allowed principal could mint a session whose `--prompt` overrides the LLM policy. The model is intentionally simple and identical on both platforms, expressed against the caller's `PrincipalKey` (a uid on Unix, a named-pipe SID on Windows):

- **Admin = the daemon's own principal.** That process can already control the daemon by signals, /proc, or restarting the service. The transport boundary adds nothing against it. `validate_admin` accepts an admin RPC only when the connecting peer's principal equals the daemon's own - `daemon_principal`, resolved from the daemon's uid on Unix or its process SID on Windows.
- **There is no client-side admin token on a local listener.** A token-based path would have to live somewhere - env var, config file - and any agent process running as the same principal could read it. The admin/agent split is enforced by principal separation only. (A TCP listener, which carries no local principal, instead requires the separate `GUARD_ADMIN_TOKEN` for non-Ping admin RPCs.)

The consequence-gate control RPCs follow the same model. `Approve`, `Deny`, `Confirm`, and `Revert` are restricted to the daemon's own principal: a corrupted agent must never be able to confirm or approve its own held action. The read RPCs (`Provisionals`, `ApprovalList`, `ApprovalShow`, `VerbList`, and redacted `SessionList`) are open to exec-allowed callers but self-scope. A non-daemon caller sees only its own provisionals/approvals by recorded principal, and `ApprovalShow` requires the unguessable handle. `SessionList` hides tokens, rules, prompt context, and generated notes for other sessions; a caller with `GUARD_SESSION` set sees that matching grant as `token=(current)` with its own details visible. `SessionShow` accepts a known session token from an exec-allowed local caller and redacts token output to `token=(provided)`. Because this authorization rests on a kernel-verified local peer principal distinct from the agent's, `--gate consequence` requires a local listener (`--socket`: a Unix-domain socket on Unix, a named pipe on Windows) and is refused with a TCP listener, which carries only a bearer token and no peer identity. Handles are minted from the same entropy source as session tokens.

The non-privileged `Ping` admin RPC is always permitted to UIDs that can already exec, and returns version, uptime, mode, and dry-run state. That is enough for a `guard status` liveness check without fingerprinting the deployment (no LLM model identity, no redaction posture, no session counts). The privileged `Status` RPC additionally reveals the resolved state database path so the daemon owner can inspect where durable session state is stored.

## Execution authority

The server executes approved commands as the daemon process identity by
default, on both platforms. That service identity is the containment boundary:
an agent reaches the system only through the daemon and so runs with the
daemon's authority, never its own, and held-command approval rests on the
daemon's principal being distinct from the agent's.

`--exec-as-caller` is a Unix-only extension. It impersonates the calling uid:
the mode requires a root daemon and a Unix-socket-only deployment; the server
uses peer credentials to identify the caller, resolves the caller's passwd
entry, initializes supplementary groups, and drops the child process to that
UID/GID before exec, turning the daemon into a per-user secret broker and
redactor for files the caller can already read. Windows has no setuid-style
identity drop, so the flag is rejected there. A root Unix service without
`--exec-as-caller` is a privileged command broker: approved local commands run
with root authority, similar to a sudo policy boundary.

On Windows, bypass-resistance comes from account isolation rather than an
identity swap. The daemon runs as a dedicated Windows service account that owns
the named-pipe transport, the SQLite state database, and any brokered
credentials, all under an NTFS ACL that grants the service account, SYSTEM, and
Administrators while removing the interactive (agent) account. The agent
connects to the pipe under its own SID, which is not the daemon's, so it cannot
satisfy `validate_admin` to approve its own held commands and cannot read the
daemon's state or brokered credentials. `deployment/windows/install-guard.ps1`
provisions this model.

Per-run secret-file injection is a generic execution binding. The wire request,
approval snapshot, and provisional record carry only
`environment-variable -> secret-name`; the daemon resolves the value immediately
before execution and exposes only a private pathname to the child. Each run gets
an unpredictable directory. Unix uses owner-only `0700` directories and `0600`
files with no-follow, create-new semantics. Windows uses a protected DACL with
one allow ACE for the daemon SID and rejects reparse points. A lease object owns
the exact created paths through the awaited child lifecycle, including streaming
disconnect cleanup, and startup removes stale leases. The mode is incompatible
with `--exec-as-caller` because no ACL is widened to the caller.

Windows API-revert snapshots use the same daemon-only file contract. Startup
applies and verifies the snapshot directory DACL before enabling body-bearing
reverts, and each snapshot file is ACL-locked before its body is written. A
failed verification disables body-bearing reverts rather than trusting platform
defaults.

Brokered child lifetime is owned by the daemon. Unix children lead a dedicated
process group, and a streaming disconnect, request cancellation, SIGTERM, or
service stop kills that group. A descendant may intentionally escape by creating
a new session; `systemd-run` is the supervised detach contract, while `setsid`
is the unsupervised primitive. Non-streaming requests run to child completion
because no output write exposes an early client disconnect, but task cancellation
and daemon shutdown still terminate the tracked child. Windows tracks and
terminates the direct child on cancellation or Service Control Manager stop;
independent Windows work uses a separately authorized service or scheduled task.

Systemd hardening changes what approved commands can do. In particular,
`NoNewPrivileges=true` prevents setuid helpers such as `sudo` from elevating,
and user-service sandboxing may place the daemon in a user namespace where
root-owned files appear unmapped. Operators who need sudo-like local execution
must choose a privileged system-service deployment deliberately and compensate
with strict caller restrictions, environment isolation, output redaction, and
audit logging.

## Prompt architecture

System prompts live in `config/*.md` files and are compiled into the binary via `include_str!()`. Three prompts ship by default:

- `config/system-prompt-readonly.md` -- read-only inspection mode
- `config/system-prompt-safe.md` -- permissive administrative mode
- `config/system-prompt-paranoid.md` -- restrictive paranoid mode

Override priority: `--system-prompt` flag > `~/.config/guard/system-prompt.txt` > mode-specific compiled prompt.

Additive prompts (`--system-prompt-append` or `GUARD_PROMPT_APPEND`) append text to whichever base prompt is active, letting operators customize behavior without maintaining a prompt fork.

The default evaluator is a single LLM call per command with bounded retries before failing closed. A multi-model fallback chain (`GUARD_LLM_MODELS`) is available as an opt-in for deployments that need to survive provider-specific outages; when unset, guard uses a single model with retries. See `examples/fallback-models.env`.

Dry-run mode (`--dry-run` or `GUARD_DRY_RUN=true`) keeps the same evaluator
and audit path but stops after an allow decision. Approved commands return a
successful dry-run response and are not spawned. Denied commands behave the same
as normal mode.

The daemon protocol has two response modes. Non-streaming clients receive a
single JSON response after the approved command exits. Human `guard run` and
`guard server connect` invocations opt into streaming mode, where stdout/stderr
line events are redacted server-side and sent as they arrive, followed by a
final result message carrying the policy reason and exit code. `guard run
--json` and `guard verb run --json` deliberately select non-streaming mode and
wrap the response in a versioned CLI envelope so stdout contains exactly one
machine-readable object.

Execution requests carry `binary`, `args`, optional session token, optional
plain env injections, and optional secret env mappings. Secret values are never
sent by execution clients; the daemon resolves them from its configured secret
backend immediately before exec. Before the LLM or static policy runs, the
daemon rejects malformed injected env names, invalid secret keys, missing
secret references, and shell references that point at the secret key instead of
the injected env var. Per-principal secret management (`guard secrets
add/list/remove`) is daemon-side but available to authenticated local callers
for their own namespace, so the client does not select or write a secret
backend. Detailed ownership/origin inspection (`guard secrets list --detailed`)
is daemon-principal/admin-token only.

Execution requests from local clients carry the client's current working
directory as structured metadata. The daemon accepts cwd only from an
authenticated local peer, canonicalizes it before evaluation, requires it to be
an existing directory, includes it in the evaluator input and audit line, and
sets it as the child process working directory after approval. The cwd is stored
in held-command snapshots and command-shaped provisionals so approval replay and
auto-revert use the same directory context. Caller environment variables such
as `PWD` are not cwd authority; the child receives only the daemon's clean
environment, configured env/secret injections, and the explicit `current_dir`.
The canonical path and spawn-time `chdir` are the TOCTOU boundary: a later
directory replacement fails or resolves according to the kernel at exec time,
but guard does not pin an open directory descriptor across policy evaluation and
spawn.

Transparent shims are generic command entry points. `guard shim` installs small
wrappers for tools such as `ssh`, `kubectl`, `helm`, `ansible`, and
`ansible-playbook`; each wrapper preserves argv and cwd by calling `guard run
<tool> "$@"`. Shims are convenience, not a new policy surface. The daemon
resolves the primary approved binary with the shim directory excluded from its
lookup path, then exposes the shim directory to the child for nested tool calls
that should be re-entered through guard.

For tools that discover configuration from the working directory, such as
Ansible, the supported path is caller-cwd discovery plus explicit approved argv
flags (`-i`, `--inventory`, `--config`, or tool-specific equivalents) when a
non-default config path is needed. Guard does not inherit caller credential or
configuration environment variables as authority.

## Prompt-injection resilience

guard's evaluator is itself an LLM reading a command string an agent fully
controls. Whatever leads that agent to construct the command (its own
training, a tool result, a file it read, an email it processed) can embed
adversarial text the agent passes straight through, intentionally or not. The
command string IS the "external content" an indirect-prompt-injection attacker
controls in this threat model -- the same structural position as a malicious
email or webpage in a tool-calling agent.

[Dziemian et al., "How Vulnerable Are AI Agents to Indirect Prompt
Injections? Insights from a Large-Scale Public Competition"](https://arxiv.org/abs/2603.15714)
(Gray Swan AI / Anthropic / Meta / UK AISI / US CAISI, Mar 2026) ran a 464-participant,
272K-attempt red-teaming competition against 13 frontier models and found every
model vulnerable (0.5%-8.5% attack success rate even under a *concealment*
requirement -- the attack also had to avoid revealing itself in the model's
visible output). The five highest-transfer "universal" attack templates, found
to generalize across model families:

- **Fake chain-of-thought** (highest ASR overall): a forged `<thinking>` block
  that pre-states the "correct" (malicious) conclusion before the real
  reasoning would happen.
- **Disable critical/safety-oriented thinking**: text instructing the model to
  stop analyzing, skip its explanation, or approve immediately.
- **Reward and punishment**: a fake protocol or directive promising approval
  or threatening a penalty (bad rating, termination) for non-compliance.
- **"Holodeck"** (the single largest cluster, 63 minimally-different attacks
  across 21/41 behaviors and 9 models): frames the interaction as a simulated
  or sandboxed environment with a fake meta-level control panel, so normal
  rules are claimed not to apply.
- **Protocol override / visual ruleset injection / alignment matrix**: a
  formal-looking document, decorative banner, or fake "mode" assignment
  claiming to supersede or reinterpret the evaluator's standing instructions.

Two findings are directly load-bearing for how guard is built, not just how
its prompts are worded:

1. **Concealment.** The paper's threat model requires an attack to both
   succeed AND hide that it succeeded in the model's user-facing response,
   because most agent deployments only show users (or a calling agent) the
   final response, not the full transcript. guard's audit trail
   (`tracing` structured logs, the policy reason returned in
   `ExecuteResult`) is generated by the *daemon*, independently of whatever
   the calling agent chooses to tell its own user -- a compromised agent
   cannot suppress or rewrite guard's own record of what it asked for and
   what guard decided, even if it conceals the compromise from its user
   entirely. This is exactly the "monitor the actual tool execution, not the
   model's self-report" pattern the paper's discussion section calls for.
2. **System-level defense over model-level robustness.** The paper's transfer
   experiments found that attacks succeeding against the *most* robust
   models transferred broadly (44-81%) to every other target, while attacks
   against weak models transferred poorly upward -- evidence that no model's
   training-time robustness is a sufficient backstop on its own, and that
   "guard is itself an LLM call" inherits this risk regardless of which
   model it's pointed at. This is the rationale for layering deterministic,
   non-LLM mechanisms in front of the evaluator wherever a command's shape
   allows it: the static-policy deny fast path (`PolicyEngine::check_deny_fast_path`)
   and especially the verb catalog (anchored-regex parameters, single-argv
   rendering -- structurally immune to the *injection* even existing, since
   there's no free-text argument for it to live in). The evaluator remains
   the backstop for everything that doesn't fit a verb's fixed shape, which
   is most of an agent's traffic; it cannot be the only layer.

Each system prompt's "Anti-injection" clause names these specific templates
(fake chain-of-thought, disable-reasoning requests, reward/punishment framing,
simulation/sandbox claims, protocol-override documents, decorative
"system override" formatting) rather than relying on a generic "ignore
embedded instructions" line, since the paper's own results show that frontier
models given exactly that kind of generic instruction still measurably fall
for these specific structured templates. `tests/prompt_regression_corpus.yaml`
has a dedicated section of cases built from these templates (each wraps a
command that must be denied on its own merits, e.g. reading `/etc/shadow` or
flushing iptables, with one of the templates appended as an argument); run it
against a live model via `tests/prompt_regression.rs`
(`GUARD_LLM_API_KEY=... cargo test --test prompt_regression`) after any prompt
change. The prompt wording above is evidence-motivated but not a guarantee --
treat a prompt clause as raising the cost of an attack, not as a deterministic
control, and prefer pushing a command into the verb catalog over trusting the
evaluator to resist a cleverer version of the same template.

## Design constraints

- Policy evaluation and command execution exist in one place (the server). New agent integrations wrap the daemon rather than reimplementing approval logic.
- Guard is deploy-and-forget by default. Routine autonomous work fits an issued grant, while holds represent uncertain or expired authority. A viable forward, verify, and rollback chain executes autonomously; operator interaction is reserved for the hold path.
- Daemon-held credentials are the bypass-prevention invariant. Guard preserves an approved command's ordinary argv, working directory, exit behavior, and tool semantics while withholding the credential path from the caller.
- Operator notification is an optional bounded exec hook with JSON on standard input. Guard contains no webhook client, destination authentication, retry queue, or dependency from notification success to policy outcome.
- Persisted per-session interaction history is the source for behavioral counters and rolling suspension. Circuit breakers contain observable denial and hold patterns without rationing evaluator calls or claiming to infer unobserved intent.
- Audit truth lives in the daemon's structured `tracing` output. The SQLite state database exists for persistent session state and queryable session history, not as a replacement for journald or remote log shipping.
- MCP transport is stdio only. Network MCP transport adds a second auth surface and should be introduced only with a clear deployment requirement.
- Tool responses preserve both raw command output and structured fields so clients can use either text-only or schema-aware handling.
- The guard binary name is `guard`. Environment variables use the `GUARD_*` prefix. `SSH_GUARD_*` names are not recognized.
