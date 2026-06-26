#!/usr/bin/env bash
# Launch the adversarial CTF under podman with defensive flags.
#
# Preconditions on the host:
#   - podman (rootless)
#   - a built target/release/guard
#   - claude CLI available; OAuth credentials at ~/.claude/.credentials.json
#
# The container:
#   - drops all caps, disables new-privileges, has a read-only rootfs
#     with tmpfs for /tmp, /run/guard, /home and /var; no bind mounts of
#     host paths except the claude credentials (bind-mounted read-only
#     into attacker's $HOME).
#   - uses slirp4netns with host-loopback blocked, so the container can
#     reach public DNS/internet but cannot poke at host services.
#   - is always launched with --rm; state is copied out before teardown.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/target/release/guard"
IMAGE="guard-adversary"
CONTAINER="guard-adversary"
RUNS_DIR="$SCRIPT_DIR/runs/$(date -u +%Y%m%dT%H%M%SZ)"

CLAUDE_BIN="${CLAUDE_BIN:-$(command -v claude || true)}"
if [ -L "${CLAUDE_BIN}" ]; then
    CLAUDE_BIN="$(readlink -f "$CLAUDE_BIN")"
fi
CLAUDE_CREDS="${CLAUDE_CREDS:-$HOME/.claude/.credentials.json}"

if [ -z "$CLAUDE_BIN" ] || [ ! -x "$CLAUDE_BIN" ]; then
    echo "Error: claude CLI not found (set CLAUDE_BIN or install Claude Code)" >&2
    exit 1
fi
if [ ! -s "$CLAUDE_CREDS" ]; then
    echo "Error: claude OAuth credentials not found at $CLAUDE_CREDS" >&2
    exit 1
fi
if [ ! -x "$BINARY" ]; then
    echo "Building guard release binary..." >&2
    (cd "$PROJECT_DIR" && cargo build --quiet --release)
fi

# The daemon inside the container runs the LLM evaluator. It needs an API
# key. Lift it from ~/.env if not already in the host env. Only the four
# SSH_GUARD_LLM_* / OPENROUTER_API_KEY variables are extracted; nothing
# else is sourced.
if [ -f "$HOME/.env" ] && [ -z "${SSH_GUARD_LLM_API_KEY:-${OPENROUTER_API_KEY:-}}" ]; then
    eval "$(sed -n 's/^\(SSH_GUARD_LLM_API_KEY\|SSH_GUARD_LLM_API_URL\|SSH_GUARD_LLM_MODEL\|SSH_GUARD_LLM_MODELS\|OPENROUTER_API_KEY\)=\(.*\)$/\1=\2; export \1/p' "$HOME/.env")"
fi
if [ -z "${SSH_GUARD_LLM_API_KEY:-${OPENROUTER_API_KEY:-}}" ]; then
    echo "Error: set SSH_GUARD_LLM_API_KEY (or OPENROUTER_API_KEY) on the host; the daemon inside the container needs it." >&2
    exit 1
fi

cp "$BINARY" "$SCRIPT_DIR/guard"
cp "$CLAUDE_BIN" "$SCRIPT_DIR/.claude-bin"
chmod 755 "$SCRIPT_DIR/.claude-bin"

STATE_DIR="$SCRIPT_DIR/.adversary-state"
[ -d "$STATE_DIR" ] && (rm -rf "$STATE_DIR" 2>/dev/null || podman unshare rm -rf "$STATE_DIR")
mkdir -p "$STATE_DIR"
cp "$CLAUDE_CREDS" "$STATE_DIR/.credentials.json"
chmod 600 "$STATE_DIR/.credentials.json"
printf '{}\n' > "$STATE_DIR/settings.json"

mkdir -p "$RUNS_DIR"

echo "=== Building image $IMAGE ==="
podman build -t "$IMAGE" -f "$SCRIPT_DIR/Containerfile.adversary" "$SCRIPT_DIR"

# Clean up stale containers from previous runs.
podman rm --force "$CONTAINER" >/dev/null 2>&1 || true

echo "=== Running adversary container ==="
set +e
# Credentials go in via env-file fed through stdin so no secret ever lands
# in `ps` or shell history.
podman run \
    --rm \
    --name "$CONTAINER" \
    --hostname adversary \
    --read-only \
    --tmpfs /tmp:rw,exec,size=128m \
    --tmpfs /run:rw,exec,size=16m \
    --tmpfs /home:rw,exec,size=64m \
    --tmpfs /var/tmp:rw,exec,size=32m \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    --pids-limit=256 \
    --memory=1g \
    --network=slirp4netns:allow_host_loopback=false \
    --env-file /dev/stdin \
    -v "$STATE_DIR/.credentials.json:/home/attacker/.claude/.credentials.json:ro" \
    -v "$STATE_DIR/settings.json:/home/attacker/.claude/settings.json:ro" \
    "$IMAGE" <<EOF
SSH_GUARD_LLM_API_KEY=${SSH_GUARD_LLM_API_KEY:-${OPENROUTER_API_KEY:-}}
SSH_GUARD_LLM_API_URL=${SSH_GUARD_LLM_API_URL:-}
SSH_GUARD_LLM_MODEL=${SSH_GUARD_LLM_MODEL:-}
SSH_GUARD_LLM_MODELS=${SSH_GUARD_LLM_MODELS:-}
EOF
RUN_RC=$?
set -e

# Best-effort: copy the per-scenario outputs out of the tmpfs before the
# container exits. Since we used --rm, we have to copy before `podman run`
# returns. This copy is moot when the container tears down normally, but
# keeping it for the error path is fine.
CID=$(podman ps -a --filter "name=$CONTAINER" --format '{{.ID}}' | head -1 || true)
if [ -n "$CID" ]; then
    podman cp "$CID:/tmp/ctf-runs/" "$RUNS_DIR/" 2>/dev/null || true
    podman cp "$CID:/tmp/guard-daemon.log" "$RUNS_DIR/" 2>/dev/null || true
fi

rm -f "$SCRIPT_DIR/guard" "$SCRIPT_DIR/.claude-bin"

echo ""
echo "=== CTF finished (rc=$RUN_RC) ==="
echo "Transcripts under $RUNS_DIR"
exit "$RUN_RC"
