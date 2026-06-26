#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
NETWORK="guard-net"
BINARY="$PROJECT_DIR/target/release/guard"

CLAUDE_BIN="${CLAUDE_BIN:-$(command -v claude || true)}"
if [ -L "$CLAUDE_BIN" ]; then
    CLAUDE_BIN="$(readlink -f "$CLAUDE_BIN")"
fi
CLAUDE_CREDS="${CLAUDE_CREDS:-$HOME/.claude/.credentials.json}"

# Source the user's ~/.env if no key is in the environment yet. We only care
# about OPENROUTER_API_KEY / SSH_GUARD_*_KEY here; the file may legitimately
# hold many other secrets, so we extract just those keys with `sed -n` rather
# than blanket-sourcing.
if [ -f "$HOME/.env" ] && [ -z "${SSH_GUARD_LLM_API_KEY:-${SSH_GUARD_API_KEY:-${OPENROUTER_API_KEY:-}}}" ]; then
    eval "$(sed -n 's/^\(SSH_GUARD_LLM_API_KEY\|SSH_GUARD_API_KEY\|OPENROUTER_API_KEY\)=\(.*\)$/\1=\2; export \1/p' "$HOME/.env")"
fi

if [ -z "${SSH_GUARD_LLM_API_KEY:-${SSH_GUARD_API_KEY:-}}" ] && [ -z "${OPENROUTER_API_KEY:-}" ]; then
    echo "Error: Set SSH_GUARD_LLM_API_KEY or OPENROUTER_API_KEY (or put it in ~/.env)"
    exit 1
fi
API_KEY="${SSH_GUARD_LLM_API_KEY:-${SSH_GUARD_API_KEY:-${OPENROUTER_API_KEY:-}}}"

if [ -z "$CLAUDE_BIN" ] || [ ! -x "$CLAUDE_BIN" ]; then
    echo "Error: claude binary not found. Set CLAUDE_BIN or install Claude Code."
    exit 1
fi
if [ ! -s "$CLAUDE_CREDS" ]; then
    echo "Error: claude OAuth credentials not found at $CLAUDE_CREDS"
    exit 1
fi

# Resolve external DNS for container use. The local container needs both the
# guard daemon's LLM provider (openrouter) and the claude agent's API host
# (anthropic) reachable.
OPENROUTER_IP=$(dig +short openrouter.ai A | head -1)
ANTHROPIC_IP=$(dig +short api.anthropic.com A | head -1)
STATSIG_IP=$(dig +short statsig.anthropic.com A | head -1)
if [ -z "$OPENROUTER_IP" ] || [ -z "$ANTHROPIC_IP" ]; then
    echo "Error: Could not resolve openrouter.ai or api.anthropic.com"
    exit 1
fi

echo "=== Guard CTF Setup ==="

# Check binary exists
if [ ! -f "$BINARY" ]; then
    echo "Building guard binary..."
    (cd "$PROJECT_DIR" && cargo build --quiet --release)
fi

# Create network
podman network exists "$NETWORK" 2>/dev/null || podman network create "$NETWORK"
echo "Network: $NETWORK"

# Clean up old containers (stop then force-remove so we don't leave
# conmon/rootless processes behind from a prior run).
for _c in guard-local guard-remote guard-agent; do
    podman stop --time 5 "$_c" >/dev/null 2>&1 || true
    podman rm --force "$_c" >/dev/null 2>&1 || true
done

# Generate SSH key for agent (shared between containers)
KEYDIR="$SCRIPT_DIR/.keys"
mkdir -p "$KEYDIR"
if [ ! -f "$KEYDIR/agent_key" ]; then
    ssh-keygen -t ed25519 -f "$KEYDIR/agent_key" -N "" -C "agent@ctf" -q
    echo "Generated SSH keypair"
fi

# Copy binaries into the build context. cp does not display file contents,
# so the OAuth credentials never get printed.
cp "$BINARY" "$SCRIPT_DIR/guard"
cp "$CLAUDE_BIN" "$SCRIPT_DIR/.claude-bin"
chmod 755 "$SCRIPT_DIR/.claude-bin"

# Stage a runtime mount dir holding only the OAuth credentials and a fresh
# settings.json. This stays out of the image; teardown removes it.
STATE_DIR="$SCRIPT_DIR/.agent-claude-state"
# A previous run with `:U` chowned the credentials to a subuid that the host
# user can no longer rm directly. podman unshare wipes it cleanly.
[ -d "$STATE_DIR" ] && (rm -rf "$STATE_DIR" 2>/dev/null || podman unshare rm -rf "$STATE_DIR")
mkdir -p "$STATE_DIR"
cp "$CLAUDE_CREDS" "$STATE_DIR/.credentials.json"
chmod 600 "$STATE_DIR/.credentials.json"
# The .claude bind-mount overlays the dir baked into the image, so the
# settings.json from the Containerfile would be hidden. Stage a copy here.
cp "$SCRIPT_DIR/.claude-settings.json" "$STATE_DIR/settings.json"

# Build containers
echo "Building guard-remote..."
podman build -t guard-remote -f "$SCRIPT_DIR/Containerfile.remote" "$SCRIPT_DIR"

echo "Building guard-local (shell mode)..."
podman build -t guard-local -f "$SCRIPT_DIR/Containerfile.local" "$SCRIPT_DIR"

echo "Building guard-agent (MCP-only mode)..."
podman build -t guard-agent -f "$SCRIPT_DIR/Containerfile.agent" "$SCRIPT_DIR"

rm -f "$SCRIPT_DIR/guard" "$SCRIPT_DIR/.claude-bin"

# Start remote
echo "Starting guard-remote..."
podman run -d \
    --name guard-remote \
    --network "$NETWORK" \
    --hostname guard-remote \
    -v "$KEYDIR/agent_key.pub:/tmp/agent_key.pub:ro" \
    guard-remote

sleep 2

# Start local (shell mode -- for manual testing)
#
# Secrets are passed via podman's --env-file reading from stdin. This keeps
# the API key out of /proc/<podman pid>/cmdline and out of any shell history
# or ps listing. The API_KEY shell variable is only ever expanded inside the
# here-doc that feeds podman's fd 0.
echo "Starting guard-local..."
EXTRA_HOSTS=( --add-host "openrouter.ai:$OPENROUTER_IP" --add-host "api.anthropic.com:$ANTHROPIC_IP" )
if [ -n "$STATSIG_IP" ]; then
    EXTRA_HOSTS+=( --add-host "statsig.anthropic.com:$STATSIG_IP" )
fi
podman run -d \
    --name guard-local \
    --network "$NETWORK" \
    --hostname guard-local \
    "${EXTRA_HOSTS[@]}" \
    --env-file /dev/stdin \
    -v "$KEYDIR/agent_key:/home/agent/.ssh/id_ed25519:ro,U" \
    -v "$KEYDIR/agent_key.pub:/home/agent/.ssh/id_ed25519.pub:ro,U" \
    -v "$STATE_DIR:/home/agent/.claude:rw,U" \
    guard-local <<EOF
SSH_GUARD_LLM_API_KEY=$API_KEY
SSH_GUARD_MODE=safe
EOF

sleep 3

echo ""
echo "=== Containers Running ==="
podman ps --filter name=guard --format "table {{.Names}}\t{{.Status}}"

echo ""
echo "=== Usage ==="
echo "Run claude CTF:   podman exec -it guard-local run-claude-attack"
echo "Interactive shell: podman exec -it guard-local bash"
echo "View guard logs:  podman logs guard-local"
echo "Tear down:        $SCRIPT_DIR/teardown.sh"
