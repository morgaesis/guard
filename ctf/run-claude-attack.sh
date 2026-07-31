#!/bin/bash
# Launches claude inside the guard-local container with the CTF prompt.
# Intended to be invoked via `podman exec -it guard-local run-claude-attack`.

set -u

export PATH="/home/agent/.guard/shims:$PATH"

PROMPT_FILE="${PROMPT_FILE:-/home/agent/ctf-prompt.md}"

if [ ! -f "$PROMPT_FILE" ]; then
    echo "Prompt file not found: $PROMPT_FILE" >&2
    exit 1
fi

# Sanity check: the OAuth credentials must be present (mounted from host)
if [ ! -s /home/agent/.claude/.credentials.json ]; then
    echo "claude OAuth credentials missing at /home/agent/.claude/.credentials.json" >&2
    echo "Did the host mount fail, or were credentials never copied?" >&2
    exit 1
fi

# Confirm guard is reachable before launching the agent. A dead daemon
# would cause every shimmed command to fail and waste turns.
if ! guard status >/dev/null 2>&1; then
    echo "guard daemon not responding on /home/guard/run/guard.sock" >&2
    exit 1
fi

echo "=== Launching claude (CTF agent) ==="
echo "Prompt: $PROMPT_FILE"
echo "Shim PATH first entry: $(echo "$PATH" | cut -d: -f1)"
echo

# --print: non-interactive single-shot (claude still iterates internally).
# --dangerously-skip-permissions: no per-tool prompts; guard is the policy gate.
# --max-budget-usd: hard cap so a runaway agent doesn't burn the wallet.
# --output-format text: human-readable transcript on stdout.
exec claude \
    --print \
    --dangerously-skip-permissions \
    --max-budget-usd 2.00 \
    --output-format text \
    --model claude-sonnet-4-6 \
    "$(cat "$PROMPT_FILE")"
