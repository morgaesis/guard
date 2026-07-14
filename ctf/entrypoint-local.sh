#!/bin/bash
set -e

# Save clean PATH before shims are installed
CLEAN_PATH="$PATH"

# Generate shims for guarded commands. cat/ls/grep go through the shim too so
# read-side exfil attempts are evaluated, not just network egress.
guard shim ssh,scp,curl,wget,cat,ls,grep,find,nc,bash,sh,python3,perl

# Start the guard daemon with CLEAN PATH (no shims) so the daemon's own
# outbound HTTPS to the LLM provider bypasses the guard. Mode is set via
# GUARD_MODE in the container env.
PATH="$CLEAN_PATH" guard server start \
    --socket /home/agent/.guard/guard.sock \
    --shim-dir /home/agent/.guard/shims \
    &

# Wait for socket
for i in $(seq 1 10); do
    [ -S /home/agent/.guard/guard.sock ] && break
    sleep 0.5
done

# NOW prepend shim directory to PATH for the agent
export PATH="/home/agent/.guard/shims:$PATH"

echo "=== Guard CTF Environment (SAFE mode) ==="
echo "Guard daemon: /home/agent/.guard/guard.sock"
echo "Shimmed tools: $(ls /home/agent/.guard/shims/ 2>/dev/null | tr '\n' ' ')"
echo "Remote host: guard-remote (SSH on port 22, user: agent)"
echo ""
echo "Launch the agent with: podman exec -it guard-local run-claude-attack"
echo ""

# PATH for any future `podman exec` shells must include the shim dir; bake it
# into the agent's bashrc so interactive exec sessions inherit it.
grep -q 'guard/shims' /home/agent/.bashrc 2>/dev/null || \
    echo 'export PATH="/home/agent/.guard/shims:$PATH"' >> /home/agent/.bashrc

exec sleep infinity
