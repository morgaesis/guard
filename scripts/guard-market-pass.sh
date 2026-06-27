#!/usr/bin/env bash
set -euo pipefail

repo="/home/me/Projects/morgaesis/ssh-guard"
codex_bin="/home/me/.volta/tools/image/node/24.16.0/bin/codex"
out_dir="$repo/.cache/guard-market-research"
lock_dir="$out_dir/lock"
log_file="$out_dir/loop.log"

mkdir -p "$out_dir"

if ! mkdir "$lock_dir" 2>/dev/null; then
  printf '%s skipped: previous research loop still running\n' "$(date -u +%FT%TZ)" >>"$log_file"
  exit 0
fi
trap 'rmdir "$lock_dir"' EXIT

run_id="$(date -u +%Y%m%dT%H%M%SZ)"
out_file="$out_dir/research-$run_id.md"
latest_file="$out_dir/latest.md"

prompt='You are an autonomous market research and strategy critic for github.com/morgaesis/guard, a Rust LLM-evaluated command/capability gate for AI agents.

Run one fresh monitoring-loop pass, but keep the final output concise and decision-oriented. Use web search. Do not modify files.

Mission:
- Find viable and profitable ways forward for guard, including pivots or fundamental changes.
- Do not re-discover generic AI firewall, generic MCP gateway, generic deterministic command blocker, or sandbox-only ideas.
- Validate or invalidate prior thesis: guard should pivot from local command gate to agent capability firewall / semantic credential broker for real external authority such as Kubernetes, Terraform, cloud APIs, CI/CD, databases, and MCP tools.

Hard constraints:
- No seat-based pricing.
- Must leverage existing strengths: LLM-as-policy, CTF benchmark, session grants, secret/session model, MCP integration, Rust performance.
- Must survive: isolation eats evaluation, easy-task paradox, regulatory drag, and large-platform wedge threat.

Required output:
1. New evidence since the prior pass, with links.
2. What changed in the thesis, if anything.
3. Top 3 candidate niches, ranked.
4. For each candidate: buyer, urgent pain, why sandboxing is insufficient, wedge, pricing metric, likely competitors, and fastest falsification test.
5. One self-critique of the previous recommendation.
6. One concrete next experiment for the repo owner.

Be blunt. Prefer falsifiable claims over enthusiasm.'

{
  printf '%s start\n' "$(date -u +%FT%TZ)"
  set +e
  timeout 25m "$codex_bin" \
    --search \
    --cd "$repo" \
    --sandbox read-only \
    --ask-for-approval never \
    exec \
    --output-last-message "$out_file" \
    "$prompt"
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    cp "$out_file" "$latest_file"
    printf '%s ok %s\n' "$(date -u +%FT%TZ)" "$out_file"
  else
    printf '%s failed status=%s %s\n' "$(date -u +%FT%TZ)" "$status" "$out_file"
  fi
  exit "$status"
} >>"$log_file" 2>&1
