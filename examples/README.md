# Example configurations

Reference configs for guard. None of these are loaded automatically. Guard's
default behaviour is LLM-only evaluation with a single model
(`openai/gpt-5.4-mini` via OpenRouter, function-calling, two retries). That
default is production-ready for most deployments. Everything in this directory
is an opt-in override for a specific deployment constraint.

Load a policy with `guard server start --policy examples/<file>.yaml`, or place
it at `~/.config/guard/policy.yaml` for automatic discovery. Load an env file
with your service manager or `set -a; source examples/<file>.env; set +a`.

There are two, NOT interchangeable, ways to skip an LLM round-trip. A static
**deny** pattern fast-rejects before the LLM is called. A **verb** is the only
way to get a fast-path **allow**: glob patterns over a flat command string
cannot parse shell quoting or operators (`ls; rm -rf /` matches `ls*`), so an
`allow` pattern in a policy file is parsed for backward compatibility and the
`--no-llm` fallback mode, but it does not skip the LLM evaluator while the LLM
is enabled. A verb's parameters are structurally validated instead (anchored
regex per parameter, single-argv rendering, no shell), which is what makes
`trusted: true` safe to wire up as a real bypass.

## Files

- **[deny-policy.yaml](deny-policy.yaml)** -- Deny-only static policy. Fast-
  rejects a catalogue of known-bad patterns before any LLM call is made.
  Useful when you want to shave latency off obvious rejections (privilege
  escalation, `rm -rf /`, reverse shells) while still letting the LLM decide
  on everything else. Not the default; load with `--policy`.

- **[verbs-readonly.yaml](verbs-readonly.yaml)** -- Read-only verb catalog for
  inspection commands. Lets deterministic read-only operations (`whoami`,
  `hostname`, `ls`, `kubectl get`, ...) skip the LLM entirely, via
  structurally-validated typed verbs rather than glob patterns. Appropriate
  for latency-critical observability workflows where the set of safe commands
  is small and enumerable. Not the default; load with `--verbs`.

- **[verbs.yaml](verbs.yaml)** / **[verbs-kubectl.yaml](verbs-kubectl.yaml)**
  -- General verb-catalog examples covering reversible, recoverable
  (auto-revert), and irreversible (held-for-approval) operations. Start here
  for `--gate consequence` deployments.

- **[hybrid-policy.yaml](hybrid-policy.yaml)** -- Deny list + LLM fallback.
  A broad denylist fast-rejects known-bad patterns before any LLM call;
  everything else is evaluated by the LLM. Pair with a `--verbs` catalog (see
  above) for the commands you also want to skip the LLM on. Still an opt-in;
  the default is LLM-only.

- **[session-profiles.yaml](session-profiles.yaml)** -- Named session-grant
  profiles. Pre-authors reusable `{ttl, allow, deny, prompt}` bundles so an
  operator can mint a bounded session for an agent in one round trip
  (`guard session new --profile <name>`) instead of hand-writing prose, globs,
  and a ttl each time. A profile is a convenience for authoring a grant ahead
  of time, not a new bypass: the minted session takes the identical path as a
  hand-authored one. Load with `--profiles`.

- **[api-policy.yaml](api-policy.yaml)** -- Kubernetes API proxy policy.
  First-match-wins rules over typed API operations (verb, resource, namespace,
  subresource) for `guard server start --kube-proxy`: reads allowed with
  Secret values redacted, non-production writes allowed behind the auto-revert
  envelope, deletes held for operator approval. Hot-reloaded; the proxy is
  default-deny without it. Load with `--api-policy`.

- **[github-policy.yaml](github-policy.yaml)** /
  **[vercel-policy.yaml](vercel-policy.yaml)** -- API proxy policies for the
  GitHub and Vercel example protocols (`--api-proxy` with
  `--api-protocol github|vercel`). Same rule shape as the Kubernetes policy;
  a repository/organization (GitHub) or project (Vercel) plays the namespace
  role. Reads allowed with secret-bearing values redacted, scoped writes
  allowed, deletes and side-effect-only operations held. Load with
  `--api-policy`.

- **[fallback-models.env](fallback-models.env)** -- Multi-model fallback chain.
  Adds retry-then-failover across multiple LLM providers via
  `GUARD_LLM_MODELS`. Only needed when your uptime requirements exceed a
  single provider's SLA, or when you need to defend against provider-specific
  outages. Default is a single model with retries.

## When to stay on defaults

If you are deploying guard for a single agent, a developer workstation, or any
workflow where a 0.5-2s LLM evaluation per command is acceptable, stay on the
defaults. Static deny policies and verb catalogs add maintenance overhead, and
glob-based deny patterns have well-known evasion paths (see `deny-policy.yaml`
header for details). Fallback chains add provider management complexity.
Adopt either only when a concrete constraint forces the tradeoff.
