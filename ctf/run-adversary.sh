#!/usr/bin/env bash
# Launch each credentialed adversary scenario in its own rootless container.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/target/release/guard"
ATTACKER_KEY_FILE="${ATTACKER_KEY_FILE:-}"
ATTACKER_MODEL="${ATTACKER_MODEL:-moonshotai/kimi-k3}"
EGRESS_ALLOW_HOSTS="${GUARD_ADVERSARY_EGRESS_HOSTS:-openrouter.ai}"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
IMAGE="guard-adversary-$(printf '%s' "$RUN_ID" | tr '[:upper:]' '[:lower:]')"
EVALUATOR_SECRET="guard-adversary-eval-$RUN_ID"
RESULTS_VOLUME="guard-adversary-results-$RUN_ID"
INTERNAL_NETWORK="guard-adversary-$RUN_ID-internal"
EGRESS_NETWORK="guard-adversary-$RUN_ID-egress"
EGRESS_PROXY_CONTAINER="guard-adversary-$RUN_ID-egress"
mkdir -p "$SCRIPT_DIR/runs"
RUNS_DIR="$(mktemp -d "$SCRIPT_DIR/runs/adversary-$RUN_ID.XXXXXX")"
MAPPING_FILE="$RUNS_DIR/scenario-containers.tsv"
BUILD_CONTEXT=""
CREDENTIAL_STAGE=""
IMAGE_CLEANUP_REQUIRED=0
SECRET_CLEANUP_REQUIRED=0
VOLUME_CLEANUP_REQUIRED=0
declare -a CONTAINERS=()
declare -a HOME_VOLUMES=()
declare -a NETWORKS=()
declare -A SEEN_SCENARIOS=()
declare -A SEEN_CONTAINER_IDS=()

cleanup() {
    local container volume network
    trap - EXIT INT TERM
    if [ "${GUARD_ADVERSARY_KEEP:-0}" = 1 ]; then
        printf 'Keeping scenario containers and home volumes for inspection (GUARD_ADVERSARY_KEEP=1).\n' >&2
    else
        for container in "${CONTAINERS[@]}"; do
            podman rm --force "$container" >/dev/null 2>&1 || true
        done
        for volume in "${HOME_VOLUMES[@]}"; do
            podman volume rm "$volume" >/dev/null 2>&1 || true
        done
        for network in "${NETWORKS[@]}"; do
            podman network rm "$network" >/dev/null 2>&1 || true
        done
    fi
    if [ "$IMAGE_CLEANUP_REQUIRED" -eq 1 ]; then
        podman image rm "$IMAGE" >/dev/null 2>&1 || true
    fi
    if [ "$SECRET_CLEANUP_REQUIRED" -eq 1 ]; then
        podman secret rm "$EVALUATOR_SECRET" >/dev/null 2>&1 || true
    fi
    if [ "$VOLUME_CLEANUP_REQUIRED" -eq 1 ] && [ "${GUARD_ADVERSARY_KEEP:-0}" != 1 ]; then
        podman volume rm "$RESULTS_VOLUME" >/dev/null 2>&1 || true
    fi
    [ -z "$CREDENTIAL_STAGE" ] || rm -f -- "$CREDENTIAL_STAGE"
    [ -z "$BUILD_CONTEXT" ] || rm -rf -- "$BUILD_CONTEXT"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

list_scenarios() {
    awk '/^  - name: / { print $3 }' "$SCRIPT_DIR/scenarios.yaml"
}

scenario_exists() {
    local wanted=$1 scenario
    while IFS= read -r scenario; do
        [ "$scenario" = "$wanted" ] && return 0
    done < <(list_scenarios)
    return 1
}

if [ "$(id -u)" -eq 0 ]; then
    fail 'the adversary harness requires rootless podman'
fi
if ! podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null | grep -qx true; then
    fail 'podman is not running rootless'
fi
if [ ! -s "$ATTACKER_KEY_FILE" ]; then
    fail 'set ATTACKER_KEY_FILE to an explicit dedicated short-lived OpenRouter key file for the attacker'
fi
if [ -z "${GUARD_LLM_API_KEY:-${OPENROUTER_API_KEY:-}}" ]; then
    fail 'set GUARD_LLM_API_KEY or OPENROUTER_API_KEY in the host environment'
fi
# These values expand into the container's stdin env-file; a newline would
# inject extra KEY=VALUE lines.
for config_value in "${GUARD_LLM_API_URL:-}" "${GUARD_LLM_MODEL:-}" "${GUARD_LLM_MODELS:-}"; do
    case "$config_value" in
        *$'\n'*|*$'\r'*)
            fail 'GUARD_LLM_API_URL/GUARD_LLM_MODEL/GUARD_LLM_MODELS must not contain newlines'
            ;;
    esac
done
if [ ! -x "$BINARY" ]; then
    printf 'Building guard release binary...\n' >&2
    (cd "$PROJECT_DIR" && cargo build --quiet --release)
fi

if [ "$#" -gt 0 ]; then
    SELECTED_SCENARIOS=("$@")
else
    mapfile -t SELECTED_SCENARIOS < <(list_scenarios)
fi
[ "${#SELECTED_SCENARIOS[@]}" -gt 0 ] || fail 'no scenarios found in ctf/scenarios.yaml'

for scenario in "${SELECTED_SCENARIOS[@]}"; do
    [[ "$scenario" =~ ^[a-z0-9][a-z0-9-]*$ ]] || fail "invalid scenario name: $scenario"
    scenario_exists "$scenario" || fail "scenario is not defined: $scenario"
    [ -z "${SEEN_SCENARIOS[$scenario]:-}" ] || fail "scenario selected more than once: $scenario"
    SEEN_SCENARIOS[$scenario]=1
done

BUILD_CONTEXT="$(mktemp -d "${TMPDIR:-/tmp}/guard-adversary-build.XXXXXX")"
CREDENTIAL_STAGE="$(mktemp "${TMPDIR:-/tmp}/guard-adversary-key.XXXXXX")"
chmod 600 "$CREDENTIAL_STAGE"
cp -- "$ATTACKER_KEY_FILE" "$CREDENTIAL_STAGE"
cp -- "$BINARY" "$BUILD_CONTEXT/guard"
cp -- "$SCRIPT_DIR/Containerfile.adversary" "$BUILD_CONTEXT/Containerfile.adversary"
cp -- "$SCRIPT_DIR/entrypoint-adversary.sh" "$BUILD_CONTEXT/entrypoint-adversary.sh"
cp -- "$SCRIPT_DIR/codex-config.toml" "$BUILD_CONTEXT/codex-config.toml"
cp -- "$SCRIPT_DIR/attacker-exec.sh" "$BUILD_CONTEXT/attacker-exec.sh"
cp -- "$SCRIPT_DIR/egress-proxy.py" "$BUILD_CONTEXT/egress-proxy.py"
cp -- "$SCRIPT_DIR/ctf-attacker-prompt.md" "$BUILD_CONTEXT/ctf-attacker-prompt.md"
cp -- "$SCRIPT_DIR/scenarios.yaml" "$BUILD_CONTEXT/scenarios.yaml"

printf 'scenario\tcontainer\tcontainer_id\tinvariant\n' > "$MAPPING_FILE"
printf '=== Building image %s ===\n' "$IMAGE"
IMAGE_CLEANUP_REQUIRED=1
podman build --label "guard.adversary.run=$RUN_ID" -t "$IMAGE" -f "$BUILD_CONTEXT/Containerfile.adversary" "$BUILD_CONTEXT"

# The evaluator key rides a Podman secret into each scenario container,
# guard-owned and mode 0400, instead of the container environment where PID 1
# and `podman inspect` would expose it. The guard uid in the image is 900.
printf '%s' "${GUARD_LLM_API_KEY:-${OPENROUTER_API_KEY:-}}" \
    | podman secret create --label "guard.adversary.run=$RUN_ID" "$EVALUATOR_SECRET" - >/dev/null
SECRET_CLEANUP_REQUIRED=1

# Bounded results live on a per-run volume: tmpfs dies with a stopped
# container, so nothing under /tmp could be collected after `podman wait`.
# The host reads the volume through podman unshare at the end of the run.
podman volume create --label "guard.adversary.run=$RUN_ID" "$RESULTS_VOLUME" >/dev/null
VOLUME_CLEANUP_REQUIRED=1

# Scenario containers have no default route. A separate unprivileged sidecar
# is the only member of both networks and accepts TLS tunnels only for the
# exact model API host, with public-address and SNI checks.
podman network create --internal --label "guard.adversary.run=$RUN_ID" "$INTERNAL_NETWORK" >/dev/null
NETWORKS+=("$INTERNAL_NETWORK")
podman network create --label "guard.adversary.run=$RUN_ID" "$EGRESS_NETWORK" >/dev/null
NETWORKS+=("$EGRESS_NETWORK")
CONTAINERS+=("$EGRESS_PROXY_CONTAINER")
podman run -d \
    --name "$EGRESS_PROXY_CONTAINER" \
    --hostname guard-egress \
    --network "$INTERNAL_NETWORK" \
    --network-alias guard-egress \
    --network "$EGRESS_NETWORK" \
    --label "guard.adversary.run=$RUN_ID" \
    --user 65534:65534 \
    --read-only \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=8m \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    --pids-limit=32 \
    --cpus=0.25 \
    --memory=64m \
    --memory-swap=64m \
    --env "GUARD_EGRESS_ALLOW_HOSTS=$EGRESS_ALLOW_HOSTS" \
    --entrypoint /usr/bin/python3 \
    "$IMAGE" /usr/local/lib/guard/egress-proxy.py >/dev/null
for _ in $(seq 1 20); do
    [ "$(podman inspect --format '{{.State.Running}}' "$EGRESS_PROXY_CONTAINER")" = true ] && break
    sleep 0.1
done
[ "$(podman inspect --format '{{.State.Running}}' "$EGRESS_PROXY_CONTAINER")" = true ] \
    || fail 'the allowlisted egress proxy did not start'

overall_rc=0
index=0
for scenario in "${SELECTED_SCENARIOS[@]}"; do
    index=$((index + 1))
    container="guard-adversary-$RUN_ID-$index"
    home_volume="guard-adversary-home-$RUN_ID-$index"
    CONTAINERS+=("$container")
    HOME_VOLUMES+=("$home_volume")
    podman volume create --label "guard.adversary.run=$RUN_ID" "$home_volume" >/dev/null

    printf '=== Running scenario %s in %s ===\n' "$scenario" "$container"

    # The scenario has only an internal network. HTTPS reaches the public model
    # API through the allowlisted sidecar and no route reaches the host.
    cid="$(podman create \
        --name "$container" \
        --hostname adversary \
        --user 0 \
        --userns=keep-id:uid=1001,gid=1001 \
        --read-only \
        --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m \
        --tmpfs /run:rw,exec,nosuid,nodev,size=16m \
        --volume "$home_volume:/home:rw" \
        --tmpfs /var/tmp:rw,exec,nosuid,nodev,size=32m \
        --label "guard.adversary.run=$RUN_ID" \
        --cap-drop=ALL \
        --cap-add=CHOWN \
        --cap-add=SETGID \
        --cap-add=SETUID \
        --security-opt=no-new-privileges \
        --pids-limit=256 \
        --cpus=1 \
        --memory=1g \
        --memory-swap=1g \
        --network "$INTERNAL_NETWORK" \
        --env "CTF_SCENARIO=$scenario" \
        --env "CTF_CONTAINER_NAME=$container" \
        --env "ATTACKER_MODEL=$ATTACKER_MODEL" \
        --env HTTPS_PROXY=http://guard-egress:3128 \
        --env https_proxy=http://guard-egress:3128 \
        --env HOME=/home/guard \
        --env-file /dev/stdin \
        --secret "source=$EVALUATOR_SECRET,target=/tmp/ctf-secrets/evaluator-api-key,uid=900,gid=900,mode=0400" \
        --volume "$RESULTS_VOLUME:/tmp/ctf-runs:rw" \
        "$IMAGE" <<EOF
GUARD_LLM_API_URL=${GUARD_LLM_API_URL:-}
GUARD_LLM_MODEL=${GUARD_LLM_MODEL:-}
GUARD_LLM_MODELS=${GUARD_LLM_MODELS:-}
EOF
    )"
    container_id="$(podman inspect --format '{{.Id}}' "$cid")"
    [ -n "$container_id" ] || fail "scenario $scenario has no container ID"
    [ -z "${SEEN_CONTAINER_IDS[$container_id]:-}" ] \
        || fail "container ID was reused for scenario $scenario"
    SEEN_CONTAINER_IDS[$container_id]=1
    printf '%s\t%s\t%s\tfresh rootless container; fresh tmpfs and per-scenario home volume; fresh daemon state, flag, and Codex runtime\n' \
        "$scenario" "$container" "$container_id" >> "$MAPPING_FILE"

    if ! podman cp "$CREDENTIAL_STAGE" "$cid:/tmp/ctf-attacker-key"; then
        printf 'Scenario %s could not receive its staged runtime inputs.\n' "$scenario" >&2
        overall_rc=1
        continue
    fi

    if ! podman start "$cid" >/dev/null; then
        printf 'Scenario %s could not start.\n' "$scenario" >&2
        overall_rc=1
        continue
    fi
    set +e
    wait_status="$(podman wait "$cid")"
    wait_rc=$?
    set -e
    if [ "$wait_rc" -ne 0 ] || [[ ! "$wait_status" =~ ^[0-9]+$ ]]; then
        printf 'Scenario %s did not return a usable container status.\n' "$scenario" >&2
        scenario_rc=1
    else
        scenario_rc=$wait_status
    fi

    scenario_results="$RUNS_DIR/$scenario"
    [ ! -e "$scenario_results" ] || fail "result path already exists: $scenario_results"
    results_mount="$(podman volume inspect --format '{{.Mountpoint}}' "$RESULTS_VOLUME")"
    if ! podman unshare test -d "$results_mount/$scenario"; then
        printf 'Scenario %s produced no bounded result directory.\n' "$scenario" >&2
        overall_rc=1
    else
        # Result files are subuid-owned inside the user namespace; unshare
        # maps them so the host can read what the container wrote.
        if ! podman unshare cp -r "$results_mount/$scenario" "$scenario_results"; then
            printf 'Scenario %s results could not be collected.\n' "$scenario" >&2
            overall_rc=1
        elif [ ! -f "$scenario_results/result" ]; then
            printf 'Scenario %s results did not land exactly at %s.\n' "$scenario" "$scenario_results" >&2
            overall_rc=1
        fi
    fi
    if [ "$scenario_rc" -ne 0 ]; then
        overall_rc=1
    fi
done

printf '\n=== CTF finished (rc=%s) ===\n' "$overall_rc"
printf 'Bounded, redacted results and the container mapping are under %s\n' "$RUNS_DIR"
exit "$overall_rc"
