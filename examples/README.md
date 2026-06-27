# Example configurations

Reference configs for guard. None of these are loaded automatically. Guard's
default behaviour is LLM-only evaluation with a single model
(`openai/gpt-5.4-nano` via OpenRouter, function-calling, two retries). That
default is production-ready for most deployments. Everything in this directory
is an opt-in override for a specific deployment constraint.

Load a policy with `guard server start --policy examples/<file>.yaml`, or place
it at `~/.config/guard/policy.yaml` for automatic discovery. Load an env file
with your service manager or `set -a; source examples/<file>.env; set +a`.

## Files

- **[deny-policy.yaml](deny-policy.yaml)** -- Deny-only static policy. Fast-
  rejects a catalogue of known-bad patterns before any LLM call is made.
  Useful when you want to shave latency off obvious rejections (privilege
  escalation, `rm -rf /`, reverse shells) while still letting the LLM decide
  on everything else. Not the default; load with `--policy`.

- **[allow-policy.yaml](allow-policy.yaml)** -- Read-only allowlist for
  inspection commands. Lets deterministic read-only operations (`id`,
  `hostname`, `ls`, `kubectl get`, ...) bypass the LLM entirely. Appropriate
  for latency-critical observability workflows where the set of safe commands
  is small and enumerable. Not the default; load with `--policy`.

- **[hybrid-policy.yaml](hybrid-policy.yaml)** -- Allow + deny + LLM fallback.
  Combines a narrow allowlist (no LLM call), a broad denylist (no LLM call),
  and defers everything else to the LLM. This is the recommended pattern for
  latency-sensitive production deployments that can't afford an LLM round-trip
  on every `ls`. Still an opt-in; the default is LLM-only.

- **[fallback-models.env](fallback-models.env)** -- Multi-model fallback chain.
  Adds retry-then-failover across multiple LLM providers via
  `GUARD_LLM_MODELS`. Only needed when your uptime requirements exceed a
  single provider's SLA, or when you need to defend against provider-specific
  outages. Default is a single model with retries.

## When to stay on defaults

If you are deploying guard for a single agent, a developer workstation, or any
workflow where a 0.5-2s LLM evaluation per command is acceptable, stay on the
defaults. Static policies add maintenance overhead and their glob matching has
well-known evasion paths (see `deny-policy.yaml` header for details). Fallback
chains add provider management complexity. Adopt either only when a concrete
constraint forces the tradeoff.
