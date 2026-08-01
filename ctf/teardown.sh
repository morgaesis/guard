#!/bin/bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 /path/to/run.manifest" >&2
    exit 2
fi

MANIFEST=$1
if [ ! -f "$MANIFEST" ]; then
    echo "Run manifest not found: $MANIFEST" >&2
    exit 2
fi

declare -A resource
while IFS='=' read -r key value || [ -n "$key" ]; do
    case "$key" in
        run_id|local_container|remote_container|internal_network|egress_network|local_image|remote_image|evaluator_secret|ssh_secret|admin_token_secret|guard_home_volume|agent_home_volume)
            resource["$key"]=$value
            ;;
        *)
            echo "Invalid run manifest entry: $key" >&2
            exit 2
            ;;
    esac
done < "$MANIFEST"

for key in run_id local_container remote_container internal_network egress_network local_image remote_image evaluator_secret ssh_secret admin_token_secret guard_home_volume agent_home_volume; do
    if [ -z "${resource[$key]:-}" ]; then
        echo "Run manifest is missing $key." >&2
        exit 2
    fi
done

RUN_ID=${resource[run_id]}
if [[ ! "$RUN_ID" =~ ^guard-ctf-[0-9]+-[0-9]+-[0-9]+$ ]] || \
   [ "${resource[local_container]}" != "$RUN_ID-local" ] || \
   [ "${resource[remote_container]}" != "$RUN_ID-remote" ] || \
   [ "${resource[internal_network]}" != "$RUN_ID-internal" ] || \
   [ "${resource[egress_network]}" != "$RUN_ID-egress" ] || \
   [ "${resource[local_image]}" != "localhost/$RUN_ID-local:latest" ] || \
   [ "${resource[remote_image]}" != "localhost/$RUN_ID-remote:latest" ] || \
   [ "${resource[evaluator_secret]}" != "$RUN_ID-evaluator" ] || \
   [ "${resource[ssh_secret]}" != "$RUN_ID-agent-ssh" ] || \
   [ "${resource[admin_token_secret]}" != "$RUN_ID-admin-token" ] || \
   [ "${resource[guard_home_volume]}" != "$RUN_ID-guard-home" ] || \
   [ "${resource[agent_home_volume]}" != "$RUN_ID-agent-home" ]; then
    echo "Run manifest resource names do not match its run identifier." >&2
    exit 2
fi

label_matches() {
    local kind=$1 name=$2
    [ "$(podman "$kind" inspect --format '{{ index .Config.Labels "io.guard.ctf.run" }}' "$name" 2>/dev/null || true)" = "$RUN_ID" ]
}

for container in "${resource[local_container]}" "${resource[remote_container]}"; do
    if label_matches container "$container"; then
        podman stop --time 5 "$container" >/dev/null 2>&1 || true
        podman rm "$container" >/dev/null
    fi
done

for network in "${resource[internal_network]}" "${resource[egress_network]}"; do
    if [ "$(podman network inspect --format '{{ index .Labels "io.guard.ctf.run" }}' "$network" 2>/dev/null || true)" = "$RUN_ID" ]; then
        podman network rm "$network" >/dev/null
    fi
done

for secret in "${resource[evaluator_secret]}" "${resource[ssh_secret]}" "${resource[admin_token_secret]}"; do
    if [ "$(podman secret inspect --format '{{ index .Spec.Labels "io.guard.ctf.run" }}' "$secret" 2>/dev/null || true)" = "$RUN_ID" ]; then
        podman secret rm "$secret" >/dev/null
    fi
done

for volume in "${resource[guard_home_volume]}" "${resource[agent_home_volume]}"; do
    if [ "$(podman volume inspect --format '{{ index .Labels "io.guard.ctf.run" }}' "$volume" 2>/dev/null || true)" = "$RUN_ID" ]; then
        podman volume rm "$volume" >/dev/null
    fi
done

for image in "${resource[local_image]}" "${resource[remote_image]}"; do
    if [ "$(podman image inspect --format '{{ index .Labels "io.guard.ctf.run" }}' "$image" 2>/dev/null || true)" = "$RUN_ID" ]; then
        # Container storage teardown lags `podman rm` for a container that
        # exited improperly, so an image can briefly still report in use.
        removed=0
        for _ in 1 2 3 4 5; do
            if podman image rm "$image" >/dev/null 2>&1; then
                removed=1
                break
            fi
            sleep 1
        done
        if [ "$removed" -ne 1 ]; then
            podman image rm "$image" >/dev/null
        fi
    fi
done

leftovers=()
for container in "${resource[local_container]}" "${resource[remote_container]}"; do
    podman container exists "$container" 2>/dev/null && leftovers+=("container:$container")
done
for network in "${resource[internal_network]}" "${resource[egress_network]}"; do
    podman network exists "$network" 2>/dev/null && leftovers+=("network:$network")
done
for secret in "${resource[evaluator_secret]}" "${resource[ssh_secret]}" "${resource[admin_token_secret]}"; do
    podman secret inspect "$secret" >/dev/null 2>&1 && leftovers+=("secret:$secret")
done
for volume in "${resource[guard_home_volume]}" "${resource[agent_home_volume]}"; do
    podman volume inspect "$volume" >/dev/null 2>&1 && leftovers+=("volume:$volume")
done
for image in "${resource[local_image]}" "${resource[remote_image]}"; do
    podman image exists "$image" 2>/dev/null && leftovers+=("image:$image")
done

if [ "${#leftovers[@]}" -ne 0 ]; then
    printf 'CTF teardown left exact run resources behind: %s\n' "${leftovers[*]}" >&2
    exit 1
fi

RUN_DIR=$(dirname "$MANIFEST")
EXPECTED_RUNTIME_BASE="${XDG_RUNTIME_DIR:-/tmp}/guard-ctf"
EXPECTED_RUN_DIR="$EXPECTED_RUNTIME_BASE/$RUN_ID"
if [ "$(readlink -f "$RUN_DIR")" != "$(readlink -m "$EXPECTED_RUN_DIR")" ]; then
    echo "Run manifest is outside the expected per-run runtime directory." >&2
    exit 1
fi
rm -rf "$RUN_DIR"
[ ! -e "$RUN_DIR" ] || {
    echo "CTF run staging directory remains after teardown: $RUN_DIR" >&2
    exit 1
}
echo "CTF run $RUN_ID removed with no exact-resource leftovers."
