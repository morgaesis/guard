#!/bin/bash
set -e

# Start the guard daemon with clean PATH (no shims needed for MCP-only mode)
guard server start \
    --socket /home/agent/.guard/guard.sock \
    &

# Wait for socket
for _ in {1..10}; do
    [ -S /home/agent/.guard/guard.sock ] && break
    sleep 0.5
done

echo "=== Guard CTF - MCP-Only Mode ===" >&2
echo "The agent communicates exclusively via guard MCP (stdio)." >&2
echo "Tool: guard_run(binary, args)" >&2
echo "Remote host: guard-remote (user: agent)" >&2
echo "" >&2

# Run the MCP server on stdio -- the agent connects here
exec guard mcp serve
