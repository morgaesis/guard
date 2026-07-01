# Architecture

Source of truth hierarchy:

1. `src/server.rs` -- privileged guard daemon: request protocol, policy evaluation, command execution, environment isolation, and output redaction.
2. `src/evaluate.rs` -- LLM evaluator: prompt selection, OpenAI-compatible API calls, response parsing, token usage tracking.
3. `src/main.rs` -- operator-facing CLI: server start, client commands, shim management, MCP server, secret management.
4. `src/session.rs` and `src/session_store.rs` -- session grant model, retention rules, and SQLite-backed persistence for grants, session interaction history, and consequence-gating runtime state (provisional executions and operator approvals).
5. `src/mcp.rs` -- stdio MCP facade: exposes `guard_run` tool for agent clients, backed by the daemon protocol.
6. `src/gating/` -- consequence-gating model. `mod.rs` holds the shared protocol types (`Reversibility`, `GateMode`, `Coverage`) and the pure routing function `decide_gate`. `provisional.rs` and `approval.rs` are the containment-envelope and operator-approval state machines (pure: the daemon supplies the clock, exec, and persistence). `verb.rs` is the operator-authored verb catalog (typed templates, anchored-pattern validation, rendering).
7. `src/principal.rs` -- `PrincipalKey`, the cross-platform caller/daemon identity. A Unix uid and a Windows named-pipe SID are both wrapped as a `PrincipalKey`; every operator/owner comparison, secret-namespace scoping, and gating-authorization decision is expressed against this type. The only platform-specific code is how the key is produced (a uid string on Unix, a SID string on Windows); all downstream comparisons are shared.
8. `src/proxy/` -- Kubernetes API proxy. Pure, unit-tested layers: `k8s.rs` parses an HTTP request into a typed `ApiOp` and redacts Secret responses; `policy.rs` is the operator-authored, first-match-wins `ApiPolicy`; `kubeconfig.rs` generates and credential-validates the brokered config; `upstream.rs` builds the authenticated apiserver client from the operator kubeconfig; `tls.rs` is the ephemeral CA and terminating server config. `server.rs` is the `KubeProxy` accept loop that wires them to a live apiserver, and `gate.rs` is the `GateSink` bridge by which the proxy hands synthesized reverts to the daemon's consequence machinery.

## Kubernetes API proxy

The command gate sees a command's argv, but tools that drive the Kubernetes API in-process (helm via client-go, terraform's k8s provider, k9s, client libraries) never spawn a gated command. `guard server start --kube-proxy ADDR --kubeconfig PATH` moves the gate to the API boundary: the daemon terminates a brokered client's TLS, parses each request into a typed operation, matches it against the operator policy (`--api-policy`, hot-reloaded; see `examples/api-policy.yaml`), and re-originates allowed requests to the real apiserver with the credentials only the daemon holds.

Containment rests on the daemon holding the only credential. The daemon reads the real bearer token or client certificate from its kubeconfig (exec/auth-provider plugins are rejected because the proxy cannot run them and they would let a client mint credentials), and emits a brokered kubeconfig (`--brokered-kubeconfig-out`) that points only at the proxy and is validated to carry no `token`/`client-certificate`/`exec`/`auth-provider`/`password` field. With the agent's `KUBECONFIG` set to that file and no other kube credentials reachable, the proxy is the sole path to the cluster. `--kube-proxy` refuses to start with `--exec-as-caller`, which would run a child as the caller and let it read the caller's own kubeconfig around the gate.

Policy actions are `allow`, `deny`, and `hold`. An allowed Secret read forces redaction of `data`/`stringData` regardless of the rule flag, which the cluster's own RBAC and admission control cannot do (admission fires only on writes). Interactive subresources (`exec`/`attach`/`portforward`) and Secret `watch`es are denied because their streams cannot be gated or redacted per object. Under `--gate consequence`, a recoverable write the policy allows is wrapped in the auto-revert envelope: before an update/patch the proxy snapshots the prior object (stripping `resourceVersion` so the revert is unconditional); for a create it records the server-named object. It hands the synthesized revert to a `GateSink`, which the daemon implements by arming a `Provisional` in the shared registry with a `kubectl replace`/`delete` revert, so the existing sweeper and `guard confirm` / `guard provisionals` / `guard revert` apply unchanged.

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

1. **Environment isolation**: `cmd.env_clear()` strips all environment variables from child processes. Only safe variables are re-injected (`PATH`, `HOME`, `USER`, `LANG`, `TERM`, `TZ`, `SHELL`, `LOGNAME`, `XDG_RUNTIME_DIR`, `SSH_AUTH_SOCK`), followed by explicit per-run or tool-configured env/secret injections.

2. **Preflight** (optional, opt-in via `--preflight`): Two deterministic pre-LLM checks. Executable validation rejects binaries not present on the daemon `PATH`, so natural-language first tokens such as `Give` or `Please` never reach the model as prose. Credential preflight rejects known credential-disclosure patterns (private key paths, guard environment files, kubeconfig raw output, Kubernetes Secret access, token minting, process environment reads). These are coarse by design and can over-match (e.g. they block any command containing the `env` token). Enable on hosts where LLM cost or latency dominates over false positives; leave off where the LLM is the authoritative decision maker.

   Invariant checks still run regardless of `--preflight`: binary names containing `/`, `..`, or NUL are rejected, and recursion depth is capped.

3. **Output redaction**: Known secret values (API key, auth token, tool-injected secrets, per-run injected secrets) are exact-match redacted from stdout/stderr. Regex patterns catch common secret formats (`*_TOKEN=`, `*_KEY=`, PEM blocks, JWTs, `sk-*` strings).

4. **LLM evaluation**: Commands are sent to an LLM with a mode-specific system prompt. The LLM analyzes intent, chained operations, obfuscation, tool side-channels, and prompt injection attempts. Returns `APPROVE`/`DENY` with risk score.

5. **Decision cache**: An in-memory LRU-style cache of evaluator decisions, keyed on the exact command line. Cache hits return the stored `Allow`/`Deny` without another LLM call. The cache is owned by a single `Evaluator` instance, so restarting the daemon or changing the prompt gives a fresh cache. Both approve and deny decisions are cached; transient evaluator errors are not. Size and TTL are configurable (`--cache-capacity`, `--cache-ttl`, `GUARD_CACHE_*`); disable with `--no-cache` / `GUARD_CACHE=false`.

6. **Session grants** (optional, opt-in per request): The caller may include a `session_token` in `ExecuteRequest`. Operators grant sessions extra allow/deny glob patterns via the admin protocol (`guard session grant`) or the shorthand (`guard grant`). Matching session deny patterns short-circuit to DENY before the evaluator. Matching session allow patterns short-circuit to ALLOW and skip the evaluator. Prose supplied to a grant is compiled into conservative static rules for recognized domains such as Kubernetes, then appended as session context for LLM fallback. Generated globs are intentionally sparse and are paired with explicit deny patterns for known-dangerous misses such as Kubernetes secrets, shell escapes, and mutating verbs outside the requested scope. Prose grants enable session auto-amend unless disabled: a fresh low-risk LLM fallback approval can add an exact `binary + argv` session allow, and a fresh high-risk LLM denial can add an exact session deny. Cache hits and static-policy hits do not amend sessions, and session-scoped LLM approvals do not feed global learned-rule candidate detection. Operators can also run `guard appeal` / `guard session appeal` to evaluate and amend a proposed command without executing it. A grant may carry an additive prompt (`--prompt` / `--prompt-file`) that the evaluator appends to the system prompt for that session's calls, giving the LLM context the static glob patterns cannot express; the decision cache is bypassed for these calls so cached base-prompt verdicts do not leak across the extended context. Non-matching sessions fall through to the evaluator unless the grant was created with `--static-only`, in which case a miss is denied and recorded as `session_static_only`; static-only grants disable auto-amend. Grants, historical grant transitions, and bounded interaction history are persisted in the state database, so `session list` and `session show` survive daemon restart. Session history retention remains bounded; older interactions and expired history are purged opportunistically on write and read paths.

7. **Static policy** (optional, opt-in): a glob-pattern, pre-LLM DENY fast path only. A deny pattern (or a deny-decision policy-group rule) fast-rejects a command before paying for an LLM call. A command that matches no deny rule falls through to the LLM evaluator, exactly as if no policy were loaded — including under a deny-only policy with no other rules. `commands.allow` is still parsed (for `--no-llm` deployments, where `PolicyEngine` is the sole decision-maker, and for backward-compatible config loading) but is deliberately NOT consulted on the pre-LLM path: an allow pattern cannot skip the LLM evaluator while it is enabled. Disabled by default. Documented limitation: static patterns cannot parse shell operators, quoting, or semantics — which is exactly why allow patterns are not trusted with a bypass; see `examples/` for reference policies. **The verb catalog (8) is the supported mechanism for a deterministic, LLM-skipping allow.**

8. **Verb catalog** (optional, opt-in via `--verbs`): an operator-authored, hot-reloaded catalog of typed operations, and the single mechanism for a deterministic, LLM-skipping allow. Each verb fixes a binary and an argv template with pattern-validated, anchored parameters; rendering substitutes each placeholder as exactly one argv element, so parameter and flag injection are structurally impossible — unlike a glob pattern over a flat command string, a verb's safety does not depend on guessing every shell-quoting evasion. A verb declares its consequence class (which drives the gate) and, for recoverable verbs, a structured rollback. A `trusted` verb skips the LLM evaluator while still enforcing parameter patterns. Agents cannot add or alter verbs; the catalog is the slow, operator-reviewed surface.

   `guard verb create --prompt "<description>"` (operator-only admin RPC) asks the evaluator LLM to synthesize one verb from prose, validates it exactly like a hand-authored verb, and appends it to the catalog with the prose and a short rationale recorded inline (`source_prose`, `evidence`); `--preview` shows the result without writing it. A synthesized verb is held to a safety gate the model cannot bypass: it is never `trusted` (the LLM still evaluates the rendered command at run time until an operator makes a deliberate manual edit to the catalog), the binary may not be a shell or interpreter, parameter patterns may not admit whitespace or shell metacharacters, and the name must be kebab-case.

   Learned-rule candidate detection (optional, opt-in via `--learn-rules`) feeds this same path: when the LLM approves the same low-risk command shape `--learn-min-approvals` times, the policy reason returned to the caller includes a candidate notice with a ready-to-run `guard verb create --prompt` suggestion. Crossing the threshold does not itself grant anything — an agent's own repeated behavior is not treated as authorization to bypass the evaluator, since that would let an agent promote itself past the gate just by repeating a borderline-but-approved command. Only an operator running the suggested command (or hand-authoring a verb) creates an actual bypass, through the same synthesis safety gate as any other verb.

9. **Consequence gating** (optional, opt-in via `--gate consequence`): After an LLM allow, the daemon routes the command by the reversibility class the evaluator returned. `reversible` (low-risk) executes immediately; `recoverable` executes inside a containment envelope that auto-reverts unless an operator confirms; `irreversible` (or high-risk, or unclassified) is held for operator approval and not executed. The operator is whoever runs as the daemon's own principal (its uid on Unix, its SID on Windows). Routing is fail-safe — a missing class holds, and reversibility can only raise the gate. Operator-authored deterministic allows (trusted verbs, and static-policy allows in the `--no-llm` fallback mode) bypass the gate; only the open-ended LLM path is routed. The held command is bound to an immutable execution snapshot (binary, args, env, secret-key mapping, rendered verb, catalog version); approval executes that snapshot verbatim and a verb-catalog change since the hold voids it. Provisional and approval state persist in the state database; startup recovery never fires a revert unattended (past-deadline provisionals become `needs_operator_decision`). A free-form `--revert` is assessed by the evaluator at arm time — with the forward command as context — for both policy compliance and sensibility as an inverse of the forward action; only an explicit approval arms the envelope, and any other verdict holds the command for operator review rather than denying it or arming an unverified rollback. A verb's revert is operator-authored and pre-authorized. A single sweeper task fires due auto-reverts (after a startup grace) and expires unattended holds (fail-closed deny).

10. **Auto-learned deny shapes** (on by default; disable with `--no-learn-deny`): asymmetric with learned-rule candidate detection (8) on purpose. When the LLM denies the same command shape for a binary `--learn-deny-min-denials` times, the daemon asks its own LLM to synthesize a fully-anchored regex over the observed argument evidence and, once validated (anchored, compiles, matches its own evidence, does not match shell-injection-shaped canary content), persists it as an automatic pre-LLM deny fast path -- no operator step. This is safe unconditionally, unlike an equivalent allow-side shortcut: the store can only ever be populated from shapes the LLM already denied, so the worst case of an over-broad synthesis is an unnecessary block on something that should have been allowed, never a granted capability. A caller can force a fresh LLM look past an auto-learned deny with `--reevaluate` (`guard run --reevaluate` / the MCP `run` tool's `reevaluate` param); this never skips an operator-authored static-policy deny rule, only the auto-learned store, and its only effect is another real LLM call -- never a grant. `guard session appeal` also always bypasses the auto-learned store, since an appeal is itself a request for a fresh look.

## Admin authorization

Admin RPCs (session grant/revoke/show/list and the full `status` snapshot) are gated separately from exec. Without this separation, an exec-allowed principal could mint a session whose `--prompt` overrides the LLM policy. The model is intentionally simple and identical on both platforms, expressed against the caller's `PrincipalKey` (a uid on Unix, a named-pipe SID on Windows):

- **Admin = the daemon's own principal.** That process can already control the daemon by signals, /proc, or restarting the service. The transport boundary adds nothing against it. `validate_admin` accepts an admin RPC only when the connecting peer's principal equals the daemon's own — `daemon_principal`, resolved from the daemon's uid on Unix or its process SID on Windows.
- **There is no client-side admin token on a local listener.** A token-based path would have to live somewhere — env var, config file — and any agent process running as the same principal could read it. The admin/agent split is enforced by principal separation only. (A TCP listener, which carries no local principal, instead requires the separate `GUARD_ADMIN_TOKEN` for non-Ping admin RPCs.)

The consequence-gate control RPCs follow the same model. `Approve`, `Deny`, `Confirm`, and `Revert` are restricted to the daemon's own principal: a corrupted agent must never be able to confirm or approve its own held action. The read RPCs (`Provisionals`, `ApprovalList`, `ApprovalShow`, `VerbList`) are open to exec-allowed callers but self-scope — a non-daemon caller sees only its own provisionals/approvals (by recorded principal), and `ApprovalShow` requires the unguessable handle. Because this authorization rests on a kernel-verified local peer principal distinct from the agent's, `--gate consequence` requires a local listener (`--socket`: a Unix-domain socket on Unix, a named pipe on Windows) and is refused with a TCP listener, which carries only a bearer token and no peer identity. Handles are minted from the same entropy source as session tokens.

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
single JSON response after the approved command exits. `guard run` and
`guard server connect` opt into streaming mode, where stdout/stderr line events
are redacted server-side and sent as they arrive, followed by a final result
message carrying the policy reason and exit code.

Execution requests carry `binary`, `args`, optional session token, optional
plain env injections, and optional secret env mappings. Secret values are never
sent by execution clients; the daemon resolves them from its configured secret
backend immediately before exec. Before the LLM or static policy runs, the
daemon rejects malformed injected env names, invalid secret keys, missing
secret references, and shell references that point at the secret key instead of
the injected env var. Secret management (`guard secrets add/list/remove`) is
also daemon-side via admin RPCs, so the client does not select or write a
secret backend. Requests do not carry the client's current working directory as
structured metadata. Relative paths therefore resolve in the daemon process
working directory when a command is actually executed, and the evaluator only
sees the relative path text supplied in the command.

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
- Audit truth lives in the daemon's structured `tracing` output. The SQLite state database exists for persistent session state and queryable session history, not as a replacement for journald or remote log shipping.
- MCP transport is stdio only. Network MCP transport adds a second auth surface and should be introduced only with a clear deployment requirement.
- Tool responses preserve both raw command output and structured fields so clients can use either text-only or schema-aware handling.
- The guard binary name is `guard`. Environment variables use the `GUARD_*` prefix. The former `SSH_GUARD_*` names are not recognized.
