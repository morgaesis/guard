#!/bin/bash
# Build the consequence-gating harness image and run the adversarial attack.
# Docker or Podman. Run from the repo root or anywhere:
#   ./ctf/gating/run.sh            # adversarial attack
#   ./ctf/gating/run.sh test       # full cargo test suite (authoritative, Linux)
#   ./ctf/gating/run.sh static     # shell and cross-file boundary validation
#   ./ctf/gating/run.sh synthetic-user [SU-01 ...]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE="guard-gating-run-$$"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
CONTAINER_MEMORY="${CTF_CONTAINER_MEMORY:-8g}"
CONTAINER_MEMORY_SWAP="${CTF_CONTAINER_MEMORY_SWAP:-8g}"
CONTAINER_CPU_PERIOD="${CTF_CONTAINER_CPU_PERIOD:-100000}"
CONTAINER_CPU_QUOTA="${CTF_CONTAINER_CPU_QUOTA:-200000}"
CONTAINER_CPUS="${CTF_CONTAINER_CPUS:-2}"
CONTAINER_PIDS_LIMIT="${CTF_CONTAINER_PIDS_LIMIT:-512}"
ENGINE="${CONTAINER_ENGINE:-}"
if [ -z "$ENGINE" ]; then
  if command -v podman >/dev/null 2>&1; then
    ENGINE=podman
  else
    ENGINE=docker
  fi
fi
cleanup_image() {
  "$ENGINE" image rm "$IMAGE" >/dev/null 2>&1 || true
}
trap cleanup_image EXIT

BUILD_FLAGS=(
  --memory "$CONTAINER_MEMORY"
  --memory-swap "$CONTAINER_MEMORY_SWAP"
  --cpu-period "$CONTAINER_CPU_PERIOD"
  --cpu-quota "$CONTAINER_CPU_QUOTA"
  --build-arg "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS"
)
if [ "$ENGINE" = "podman" ]; then
  BUILD_FLAGS+=(--jobs 1)
fi

RUN_FLAGS=(
  --memory "$CONTAINER_MEMORY"
  --memory-swap "$CONTAINER_MEMORY_SWAP"
  --cpus "$CONTAINER_CPUS"
  --pids-limit "$CONTAINER_PIDS_LIMIT"
)

ATTACK_RUN_FLAGS=(
  --read-only
  --network none
  --cap-drop ALL
  --cap-add CHOWN
  --cap-add SETGID
  --cap-add SETUID
  --security-opt no-new-privileges
  --tmpfs "/tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777"
  --tmpfs "/work:rw,nosuid,nodev,noexec,size=16m,mode=0755"
  --tmpfs "/fakebin:rw,exec,nosuid,nodev,size=16m,mode=0755"
  --tmpfs "/shim:rw,exec,nosuid,nodev,size=16m,mode=0755"
  --tmpfs "/run:rw,nosuid,nodev,noexec,size=16m,mode=0755"
  --tmpfs "/var/lib/guard:rw,nosuid,nodev,noexec,size=16m,mode=0755"
  --tmpfs "/var/log:rw,nosuid,nodev,noexec,size=16m,mode=0755"
  --tmpfs "/home/guarddaemon:rw,nosuid,nodev,noexec,size=1m,mode=0700"
  --tmpfs "/home/agent:rw,nosuid,nodev,noexec,size=1m,mode=0700"
)
if [ "$ENGINE" = podman ]; then
  # Disable Podman's implicit writable /var/tmp and other scratch mounts.
  ATTACK_RUN_FLAGS+=(--read-only-tmpfs=false)
fi
ATTACK_CONTAINER_ARGUMENTS=(--rm "${RUN_FLAGS[@]}" "${ATTACK_RUN_FLAGS[@]}" "$IMAGE")

validate_attack_container_arguments() {
  local -a arguments=("$@")
  local -a expected_capabilities=(CHOWN SETGID SETUID)
  local -a observed_capabilities=()
  local -a expected_tmpfs=(
    "/tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777"
    "/work:rw,nosuid,nodev,noexec,size=16m,mode=0755"
    "/fakebin:rw,exec,nosuid,nodev,size=16m,mode=0755"
    "/shim:rw,exec,nosuid,nodev,size=16m,mode=0755"
    "/run:rw,nosuid,nodev,noexec,size=16m,mode=0755"
    "/var/lib/guard:rw,nosuid,nodev,noexec,size=16m,mode=0755"
    "/var/log:rw,nosuid,nodev,noexec,size=16m,mode=0755"
    "/home/guarddaemon:rw,nosuid,nodev,noexec,size=1m,mode=0700"
    "/home/agent:rw,nosuid,nodev,noexec,size=1m,mode=0700"
  )
  local -a observed_tmpfs=()
  local read_only_count=0
  local network_none_count=0
  local cap_drop_all_count=0
  local no_new_privileges_count=0
  local podman_implicit_tmpfs_disabled_count=0
  local index argument value

  for ((index = 0; index < ${#arguments[@]}; index++)); do
    argument="${arguments[index]}"
    case "$argument" in
      --read-only)
        read_only_count=$((read_only_count + 1))
        ;;
      --read-only=false|--read-only=true|--read-write|--privileged)
        echo "fixed attack contains a root-filesystem permission override: $argument" >&2
        return 1
        ;;
      --read-only-tmpfs=false)
        podman_implicit_tmpfs_disabled_count=$((podman_implicit_tmpfs_disabled_count + 1))
        ;;
      --read-only-tmpfs|--read-only-tmpfs=true|--read-only-tmpfs=*)
        echo "fixed attack must not enable implicit writable scratch mounts: $argument" >&2
        return 1
        ;;
      --network|--cap-drop|--cap-add|--security-opt|--tmpfs)
        index=$((index + 1))
        if ((index >= ${#arguments[@]})); then
          echo "fixed attack argument $argument has no value" >&2
          return 1
        fi
        value="${arguments[index]}"
        case "$argument" in
          --network)
            if [ "$value" != none ]; then
              echo "fixed attack must disable container networking" >&2
              return 1
            fi
            network_none_count=$((network_none_count + 1))
            ;;
          --cap-drop)
            if [ "$value" != ALL ]; then
              echo "fixed attack must drop every capability before adding the required set" >&2
              return 1
            fi
            cap_drop_all_count=$((cap_drop_all_count + 1))
            ;;
          --cap-add)
            observed_capabilities+=("$value")
            ;;
          --security-opt)
            if [ "$value" != no-new-privileges ]; then
              echo "fixed attack contains an unexpected security option: $value" >&2
              return 1
            fi
            no_new_privileges_count=$((no_new_privileges_count + 1))
            ;;
          --tmpfs)
            observed_tmpfs+=("$value")
            ;;
        esac
        ;;
      --network=*|--cap-drop=*|--cap-add=*|--security-opt=*|--tmpfs=*)
        echo "fixed attack hardening arguments must use separately parsed values: $argument" >&2
        return 1
        ;;
      --volume|--volume=*|-v|--mount|--mount=*|--device|--device=*)
        echo "fixed attack may not attach host storage or devices: $argument" >&2
        return 1
        ;;
    esac
  done

  if [ "$read_only_count" -ne 1 ]; then
    echo "fixed attack must enable a read-only root filesystem exactly once" >&2
    return 1
  fi
  if [ "$network_none_count" -ne 1 ]; then
    echo "fixed attack must disable container networking exactly once" >&2
    return 1
  fi
  if [ "$cap_drop_all_count" -ne 1 ] \
    || [ "$no_new_privileges_count" -ne 1 ]; then
    echo "fixed attack must apply one complete capability drop and one no-new-privileges boundary" >&2
    return 1
  fi
  if [ "${observed_capabilities[*]}" != "${expected_capabilities[*]}" ]; then
    echo "fixed attack capability additions differ from CHOWN, SETGID, and SETUID" >&2
    return 1
  fi
  if [ "${observed_tmpfs[*]}" != "${expected_tmpfs[*]}" ]; then
    echo "fixed attack writable tmpfs arguments differ from the bounded fixture set" >&2
    return 1
  fi
  if [ "$ENGINE" = podman ]; then
    if [ "$podman_implicit_tmpfs_disabled_count" -ne 1 ]; then
      echo "fixed attack must disable Podman's implicit writable scratch mounts" >&2
      return 1
    fi
  elif [ "$podman_implicit_tmpfs_disabled_count" -ne 0 ]; then
    echo "fixed attack contains a Podman-only option for a different container engine" >&2
    return 1
  fi
}

run_attack_container() {
  validate_attack_container_arguments "$@"
  "$ENGINE" run "$@"
}

static_validate() {
  local shell_file
  while IFS= read -r shell_file; do
    bash -n "$shell_file"
  done < <(find "$REPO_ROOT/ctf" -type f -name '*.sh' -print | LC_ALL=C sort)
  validate_attack_container_arguments "${ATTACK_CONTAINER_ARGUMENTS[@]}"
  echo "PASS: fixed attack uses a read-only root, no network, and bounded writable tmpfs mounts"
  python3 - "$REPO_ROOT" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
catalog = (root / "ctf/gating/verbs.yaml").read_text(encoding="utf-8")
profiles = (root / "src/gating/verb.rs").read_text(encoding="utf-8")
proxy_server = (root / "src/proxy/server.rs").read_text(encoding="utf-8")
proxy_kubeconfig = (root / "src/proxy/kubeconfig.rs").read_text(encoding="utf-8")
cli_server = (root / "src/cli_server.rs").read_text(encoding="utf-8")
attack = (root / "ctf/gating/attack.sh").read_text(encoding="utf-8")
synthetic = (root / "ctf/gating/synthetic-user.sh").read_text(encoding="utf-8")
runner = (root / "ctf/gating/synthetic-user-runner.sh").read_text(encoding="utf-8")
adversary = (root / "ctf/entrypoint-adversary.sh").read_text(encoding="utf-8")
ctf_text = "\n".join(
    path.read_text(encoding="utf-8")
    for path in sorted((root / "ctf").rglob("*"))
    if path.is_file()
)

checks = {
    "capability contract uses the closed whoami profile": "binary: whoami\n    args: [child-contract]" in catalog and '"whoami"' in profiles,
    "credential contract uses the closed true profile": "binary: true" in catalog and '"true"' in profiles,
    "fixed attack starts an active Kubernetes proxy": "--kube-proxy" in attack and "--brokered-kubeconfig-out" in attack,
    "synthetic fixed mode starts an active Kubernetes proxy": "--kube-proxy" in synthetic and "--brokered-kubeconfig-out" in synthetic,
    "fixed kubectl success requires the brokered kubeconfig": "guarded-kubectl" in attack and 'grep -q \'guard-proxy\' "$KUBECONFIG"' in attack,
    "fixed Helm and Ansible denials are asserted": "fixed identity denied Helm before process start" in attack and "fixed identity denied Ansible before process start" in attack,
    "caller denies every typed profile tool": all(
        marker in synthetic
        for marker in (
            "expect_profile_tool_denial caller ansible-check",
            "expect_profile_tool_denial caller helm-list-direct",
            "expect_profile_tool_denial caller kubernetes-list",
        )
    ),
    "daemon capability mask is checked": "= c0" in attack and "= c0" in runner and "= c0" in synthetic,
    "daemon launch strips the bounding set to SETGID and SETUID": "--bounding-set=-all,+setgid,+setuid" in attack and "--bounding-set=-all,+setgid,+setuid" in synthetic,
    "children prove zero effective capabilities": "child-capability-contract" in attack and "assert_child_capability_contract 1003" in synthetic and "assert_child_capability_contract 1001" in synthetic,
    "world-writable Guard sockets are absent": re.search(r"chmod\s+0?666\s+[^\n]*guard(?:\.sock|/guard\.sock)", ctf_text) is None,
    "production socket group and mode are checked": "660:guard-clients" in attack and "660:guard-clients" in runner and "--socket-group guard-clients" in synthetic,
    "loopback API proxy requires authenticated client context": "a proxy transport or session bearer is required" in proxy_server and "ProxyTransportAuth" in proxy_server,
    "brokered proxy bearer is generated instead of hardcoded": "guard-anonymous" not in proxy_kubeconfig and "transport_bearer_bytes" in proxy_server,
    "brokered kubeconfig is restricted to one safe fixed-worker file": "mode != 0o640" in cli_server and "metadata.nlink() != 1" in cli_server and "output parent must be a daemon-owned directory" in cli_server,
    "broker group rejects unrelated local accounts": "contains an additional account" in cli_server and "broker_group_member_is_authorized" in cli_server,
    "generic API clients receive protected generated authentication": all(
        marker in cli_server
        for marker in (
            "api_client_config_out",
            "protected proxy client output is unsupported on Windows",
            "Windows rejects API proxy configuration",
        )
    ) and "brokered_client_config" in proxy_server,
    "fixture credential values are generated": all(
        marker in source
        for marker, source in (
            ('generate_fixture_value > "$ADMIN_TOKEN_FILE"', attack),
            ("write_generated_fixture_value /scenario/run/admin.token", synthetic),
            ('guard secrets add OPNSENSE_API_KEY <<< "$(generated_fixture_value)"', adversary),
            ('guard secrets add OPN_KEY_PAIR <<< "$(generated_fixture_value)"', adversary),
        )
    ),
}
failed = [name for name, passed in checks.items() if not passed]
for name, passed in checks.items():
    print(f"{'PASS' if passed else 'FAIL'}: {name}")
if failed:
    raise SystemExit(1)
PY
}

mode="${1:-attack}"
if [ "$mode" = static ]; then
  static_validate
  echo "CTF static validation passed"
  exit 0
fi

echo "=== Building $IMAGE (compiles guard for Linux) ==="
"$ENGINE" build "${BUILD_FLAGS[@]}" -t "$IMAGE" -f "$SCRIPT_DIR/Containerfile" "$REPO_ROOT"

case "$mode" in
  attack)
    echo "=== Running adversarial gating attack ==="
    run_attack_container "${ATTACK_CONTAINER_ARGUMENTS[@]}"
    ;;
  test)
    echo "=== Running full cargo test suite in Linux ==="
    # PATH is expanded by the shell inside the container.
    # shellcheck disable=SC2016
    "$ENGINE" run --rm "${RUN_FLAGS[@]}" --entrypoint bash "$IMAGE" \
      -c 'export PATH=/usr/local/cargo/bin:$PATH && cd /src && CARGO_INCREMENTAL=0 AGENT=1 cargo test --release --locked --quiet'
    ;;
  synthetic-user)
    shift
    GUARD_SU_IMAGE="$IMAGE" "$SCRIPT_DIR/synthetic-user-runner.sh" "$@"
    ;;
  static) ;;
  *)
    echo "usage: $0 [attack|test|static|synthetic-user [SCENARIO...]]" >&2
    exit 2
    ;;
esac
