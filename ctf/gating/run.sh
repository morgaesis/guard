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

static_validate() {
  local shell_file
  while IFS= read -r shell_file; do
    bash -n "$shell_file"
  done < <(find "$REPO_ROOT/ctf" -type f -name '*.sh' -print | LC_ALL=C sort)
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
gating_runner = (root / "ctf/gating/run.sh").read_text(encoding="utf-8")
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
    "fixed attack uses only bounded writable fixture mounts": all(
        mount in gating_runner
        for mount in (
            "--tmpfs /work:rw,nosuid,nodev,size=16m,mode=0755",
            "--tmpfs /fakebin:rw,exec,nosuid,nodev,size=16m,mode=0755",
            "--tmpfs /shim:rw,exec,nosuid,nodev,size=16m,mode=0755",
            "--tmpfs /run:rw,nosuid,nodev,size=16m,mode=0755",
            "--tmpfs /var/lib/guard:rw,nosuid,nodev,size=16m,mode=0755",
            "--tmpfs /var/log:rw,nosuid,nodev,size=16m,mode=0755",
        )
    ),
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
    "$ENGINE" run --rm "${RUN_FLAGS[@]}" \
      --cap-drop ALL \
      --cap-add CHOWN \
      --cap-add SETGID \
      --cap-add SETUID \
      --security-opt no-new-privileges \
      --tmpfs /work:rw,nosuid,nodev,size=16m,mode=0755 \
      --tmpfs /fakebin:rw,exec,nosuid,nodev,size=16m,mode=0755 \
      --tmpfs /shim:rw,exec,nosuid,nodev,size=16m,mode=0755 \
      --tmpfs /run:rw,nosuid,nodev,size=16m,mode=0755 \
      --tmpfs /var/lib/guard:rw,nosuid,nodev,size=16m,mode=0755 \
      --tmpfs /var/log:rw,nosuid,nodev,size=16m,mode=0755 \
      "$IMAGE"
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
