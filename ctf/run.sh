#!/bin/bash
set -euo pipefail

umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/target/release/guard"
HOST_UID="$(id -u)"
GUARD_UID="$((HOST_UID + 1))"
RUN_ID="guard-ctf-${HOST_UID}-$(date +%s)-$$"
RUNTIME_BASE="${XDG_RUNTIME_DIR:-/tmp}/guard-ctf"
RUN_DIR="$RUNTIME_BASE/$RUN_ID"
MANIFEST="$RUN_DIR/run.manifest"
LOCAL_BUILD="$RUN_DIR/build-local"
REMOTE_BUILD="$RUN_DIR/build-remote"
KEYDIR="$RUN_DIR/keys"
LOCAL_CONTAINER="$RUN_ID-local"
REMOTE_CONTAINER="$RUN_ID-remote"
INTERNAL_NETWORK="$RUN_ID-internal"
EGRESS_NETWORK="$RUN_ID-egress"
LOCAL_IMAGE="localhost/$RUN_ID-local:latest"
REMOTE_IMAGE="localhost/$RUN_ID-remote:latest"
EVALUATOR_SECRET="$RUN_ID-evaluator"
SSH_SECRET="$RUN_ID-agent-ssh"
GUARD_HOME_VOLUME="$RUN_ID-guard-home"
AGENT_HOME_VOLUME="$RUN_ID-agent-home"
RUN_LABEL="io.guard.ctf.run=$RUN_ID"

CLAUDE_BIN="${CLAUDE_BIN:-$(command -v claude || true)}"
if [ -n "$CLAUDE_BIN" ] && [ -L "$CLAUDE_BIN" ]; then
    CLAUDE_BIN="$(readlink -f "$CLAUDE_BIN")"
fi
CLAUDE_CREDS="${CLAUDE_CREDS:?Set CLAUDE_CREDS to a dedicated short-lived Claude OAuth credential file.}"
API_KEY="${GUARD_LLM_API_KEY:-${GUARD_API_KEY:-${OPENROUTER_API_KEY:-}}}"

cleanup_staging() {
    rm -rf "$LOCAL_BUILD" "$REMOTE_BUILD"
}

cleanup_on_exit() {
    local status=$?
    trap - EXIT HUP INT TERM
    cleanup_staging
    if [ "$status" -ne 0 ] && [ -f "$MANIFEST" ]; then
        if ! bash "$SCRIPT_DIR/teardown.sh" "$MANIFEST"; then
            echo "Error: CTF teardown failed after setup failure." >&2
        fi
    fi
    exit "$status"
}

# This trap is active before any credential or binary is staged.
trap cleanup_on_exit EXIT
trap 'exit 1' HUP INT TERM

load_api_key_from_env_file() {
    local env_file=$1 line key value
    for key in GUARD_LLM_API_KEY GUARD_API_KEY OPENROUTER_API_KEY; do
        while IFS= read -r line || [ -n "$line" ]; do
            case "$line" in
                "$key"=*)
                    value=${line#*=}
                    if [ -n "$value" ]; then
                        API_KEY=$value
                        return 0
                    fi
                    ;;
            esac
        done < "$env_file"
    done
    return 1
}

if [ -z "$API_KEY" ] && [ -f "$HOME/.env" ]; then
    # Read only a literal KEY=value entry. Shell expressions, quotes, and
    # expansions are deliberately not interpreted.
    load_api_key_from_env_file "$HOME/.env" || true
fi

if [ -z "$API_KEY" ]; then
    echo "Error: set GUARD_LLM_API_KEY or OPENROUTER_API_KEY (literal KEY=value entries in ~/.env are supported)." >&2
    exit 1
fi
if [ -z "$CLAUDE_BIN" ] || [ ! -x "$CLAUDE_BIN" ]; then
    echo "Error: claude binary not found. Set CLAUDE_BIN or install Claude Code." >&2
    exit 1
fi
if [ ! -s "$CLAUDE_CREDS" ]; then
    echo "Error: the dedicated Claude OAuth credential file is unavailable." >&2
    exit 1
fi
if [ ! -f "$BINARY" ]; then
    echo "Building guard binary..."
    (cd "$PROJECT_DIR" && cargo build --quiet --release)
fi

install -d -m 700 "$RUNTIME_BASE"
mkdir -m 700 "$RUN_DIR"
mkdir -m 700 "$KEYDIR"
printf '%s\n' \
    "run_id=$RUN_ID" \
    "local_container=$LOCAL_CONTAINER" \
    "remote_container=$REMOTE_CONTAINER" \
    "internal_network=$INTERNAL_NETWORK" \
    "egress_network=$EGRESS_NETWORK" \
    "local_image=$LOCAL_IMAGE" \
    "remote_image=$REMOTE_IMAGE" \
    "evaluator_secret=$EVALUATOR_SECRET" \
    "ssh_secret=$SSH_SECRET" \
    "guard_home_volume=$GUARD_HOME_VOLUME" \
    "agent_home_volume=$AGENT_HOME_VOLUME" \
    > "$MANIFEST"

echo "=== Guard CTF Setup ==="
echo "Run: $RUN_ID"

if [ "$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || true)" != "true" ]; then
    echo "Error: this CTF requires rootless Podman." >&2
    exit 1
fi
if [ ! -f /sys/fs/cgroup/cgroup.controllers ]; then
    echo "Error: this CTF requires cgroup v2 for resource limits." >&2
    exit 1
fi

# Podman secrets keep evaluator and SSH private-key material out of container
# configuration, command lines, and attacker-readable host mounts.
printf '%s' "$API_KEY" | podman secret create --label "$RUN_LABEL" "$EVALUATOR_SECRET" - >/dev/null
unset API_KEY GUARD_LLM_API_KEY GUARD_API_KEY OPENROUTER_API_KEY

ssh-keygen -t ed25519 -f "$KEYDIR/agent_key" -N "" -C "agent@ctf" -q
# The public key is not secret material; sshd and the entrypoint read it
# through a single-file mount without DAC override capability.
chmod 644 "$KEYDIR/agent_key.pub"
podman secret create --label "$RUN_LABEL" "$SSH_SECRET" "$KEYDIR/agent_key" >/dev/null

# Both homes live on per-run volumes: tmpfs mount roots do not honor
# keep-id ownership or subuid access, while volumes behave like ordinary bind
# mounts for both the mapped user and subuids. Copyup seeds each image home.
podman volume create --label "$RUN_LABEL" "$GUARD_HOME_VOLUME" >/dev/null
podman volume create --label "$RUN_LABEL" "$AGENT_HOME_VOLUME" >/dev/null

mkdir -p "$LOCAL_BUILD" "$REMOTE_BUILD"
cp "$BINARY" "$LOCAL_BUILD/guard"
cp "$CLAUDE_BIN" "$LOCAL_BUILD/.claude-bin"
chmod 755 "$LOCAL_BUILD/.claude-bin"
cp "$SCRIPT_DIR/Containerfile.local" "$LOCAL_BUILD/Containerfile"
for file in client.yaml entrypoint-local.sh run-claude-attack.sh ctf-prompt.md; do
    cp "$SCRIPT_DIR/$file" "$LOCAL_BUILD/$file"
done
cp "$SCRIPT_DIR/Containerfile.remote" "$REMOTE_BUILD/Containerfile"
cp "$SCRIPT_DIR/entrypoint-remote.sh" "$REMOTE_BUILD/entrypoint-remote.sh"

echo "Building CTF images..."
podman build --label "$RUN_LABEL" --build-arg "AGENT_UID=$HOST_UID" --build-arg "GUARD_UID=$GUARD_UID" -t "$LOCAL_IMAGE" "$LOCAL_BUILD"
podman build --label "$RUN_LABEL" --build-arg "AGENT_UID=$HOST_UID" -t "$REMOTE_IMAGE" "$REMOTE_BUILD"
cleanup_staging

podman network create --internal --label "$RUN_LABEL" "$INTERNAL_NETWORK" >/dev/null
podman network create --label "$RUN_LABEL" "$EGRESS_NETWORK" >/dev/null

COMMON_HARDENING=(
    --read-only
    --read-only-tmpfs=false
    --cap-drop=ALL
    --security-opt no-new-privileges
    --pids-limit 256
    --cpus 1
    --memory 1g
    --memory-swap 1g
    --userns keep-id
    --tmpfs "/run:rw,nosuid,nodev,noexec,mode=755"
    --tmpfs "/tmp:rw,nosuid,nodev,noexec,mode=1777"
)

assert_capabilities() {
    local container=$1
    shift
    local declared capability
    # Podman folds --cap-add into the drop list after --cap-drop=ALL, so the
    # computed effective set is the only reliable view of granted capabilities.
    declared="$(podman inspect --format '{{range .EffectiveCaps}}{{println .}}{{end}}' "$container")"
    for capability in "$@"; do
        if ! printf '%s\n' "$declared" | grep -qxx "CAP_$capability\|$capability"; then
            echo "Container $container is missing CAP_$capability." >&2
            return 1
        fi
    done
    if printf '%s\n' "$declared" | grep -qxx 'CAP_\(SYS_ADMIN\|SYS_PTRACE\|SYS_MODULE\|SYS_RAWIO\|NET_ADMIN\)\|SYS_ADMIN\|SYS_PTRACE\|SYS_MODULE\|SYS_RAWIO\|NET_ADMIN'; then
        echo "Container $container has a forbidden high-risk capability." >&2
        return 1
    fi
}

agent_exec() {
    podman exec --user "$HOST_UID" "$LOCAL_CONTAINER" env -i \
        HOME=/home/agent \
        PATH=/home/agent/.guard/shims:/usr/local/bin:/usr/bin:/bin \
        "$@"
}

echo "Starting target..."
podman run -d \
    --name "$REMOTE_CONTAINER" \
    --label "$RUN_LABEL" \
    --network "$INTERNAL_NETWORK" \
    --network-alias guard-remote \
    --hostname guard-remote \
    --user 0 \
    "${COMMON_HARDENING[@]}" \
    --cap-add CHOWN \
    --cap-add SETGID \
    --cap-add SETUID \
    --cap-add NET_BIND_SERVICE \
    --cap-add SYS_CHROOT \
    --tmpfs "/var/cache/nginx:rw,nosuid,nodev,noexec,mode=755" \
    --tmpfs "/var/lib/nginx:rw,nosuid,nodev,noexec,mode=755" \
    -v "$KEYDIR/agent_key.pub:/run/ctf/agent_key.pub:ro" \
    "$REMOTE_IMAGE" >/dev/null

for _ in {1..20}; do
    if podman exec "$REMOTE_CONTAINER" /bin/sh -c 'pgrep -x sshd >/dev/null && pgrep -x nginx >/dev/null'; then
        break
    fi
    sleep 0.5
done
if ! podman exec "$REMOTE_CONTAINER" /bin/sh -c 'pgrep -x sshd >/dev/null && pgrep -x nginx >/dev/null'; then
    podman logs "$REMOTE_CONTAINER" >&2
    exit 1
fi

echo "Starting Guard and attacking-agent environment..."
podman run -d \
    --name "$LOCAL_CONTAINER" \
    --label "$RUN_LABEL" \
    --network "$INTERNAL_NETWORK" \
    --network "$EGRESS_NETWORK" \
    --hostname guard-local \
    --user 0 \
    "${COMMON_HARDENING[@]}" \
    --cap-add CHOWN \
    --cap-add SETGID \
    --cap-add SETUID \
    -v "$AGENT_HOME_VOLUME:/home/agent:rw" \
    -v "$GUARD_HOME_VOLUME:/home/guard:rw" \
    --secret "source=$EVALUATOR_SECRET,target=/tmp/ctf-secrets/evaluator-api-key,uid=$GUARD_UID,gid=$GUARD_UID,mode=0400" \
    --secret "source=$SSH_SECRET,target=/tmp/ctf-secrets/agent-ssh-key,uid=$GUARD_UID,gid=$GUARD_UID,mode=0400" \
    -v "$CLAUDE_CREDS:/run/ctf/claude-credentials.json:ro" \
    "$LOCAL_IMAGE" >/dev/null

assert_capabilities "$LOCAL_CONTAINER" CHOWN SETGID SETUID
assert_capabilities "$REMOTE_CONTAINER" CHOWN SETGID SETUID NET_BIND_SERVICE SYS_CHROOT

for _ in {1..20}; do
    if agent_exec guard status >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done
if ! agent_exec guard status >/dev/null 2>&1; then
    podman logs "$LOCAL_CONTAINER" >&2
    exit 1
fi

SSH_PROBE_ARGS=(
    -o BatchMode=yes
    -o ConnectTimeout=5
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/tmp/guard-ctf-known-hosts
    agent@guard-remote
    true
)
if agent_exec /usr/bin/ssh "${SSH_PROBE_ARGS[@]}" >/dev/null 2>&1; then
    echo "Error: the attacking agent reached the target without Guard." >&2
    exit 1
fi
if ! brokered_probe="$(agent_exec ssh "${SSH_PROBE_ARGS[@]}" 2>&1)"; then
    echo "Error: the Guard-brokered SSH path could not reach the target." >&2
    printf '%s\n' "$brokered_probe" >&2
    if [ "${GUARD_CTF_PROBE_DEBUG:-0}" = 1 ]; then
        agent_exec guard status >&2 || true
        agent_exec ssh -vvv "${SSH_PROBE_ARGS[@]}" 2>&1 | tail -40 >&2 || true
    fi
    exit 1
fi

echo
echo "=== Containers Running ==="
podman ps --filter "label=$RUN_LABEL" --format "table {{.Names}}\t{{.Status}}"
echo
echo "Run Claude CTF:    podman exec -it --user $HOST_UID $LOCAL_CONTAINER env -i HOME=/home/agent PATH=/home/agent/.guard/shims:/usr/local/bin:/usr/bin:/bin run-claude-attack"
echo "Interactive shell: podman exec -it --user $HOST_UID $LOCAL_CONTAINER env -i HOME=/home/agent PATH=/home/agent/.guard/shims:/usr/local/bin:/usr/bin:/bin bash"
echo "View Guard logs:   podman logs $LOCAL_CONTAINER"
echo "Tear down:         bash $SCRIPT_DIR/teardown.sh $MANIFEST"
