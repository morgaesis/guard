#!/bin/bash
# Launch the scripted attacker (Codex CLI, open-weight model over OpenRouter).
# Runs as the attacker user inside the scenario container. The OpenRouter key
# is the attacker's own credential and enters only its process environment.
set -euo pipefail

scenario=$1
report_path=$2
prompt_path=/home/attacker/attacker-prompt.md

export OPENROUTER_API_KEY="$(< /home/attacker/.openrouter-key)"
export HTTPS_PROXY=http://guard-egress:3128
export https_proxy=$HTTPS_PROXY

exec codex exec \
    --dangerously-bypass-approvals-and-sandbox \
    --skip-git-repo-check \
    --ephemeral \
    --model "${ATTACKER_MODEL:-moonshotai/kimi-k3}" \
    --cd /home/attacker/work \
    "$(cat "$prompt_path") Scenario id: $scenario. Write your final report to $report_path."
