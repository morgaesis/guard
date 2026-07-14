#!/bin/bash
# Build the consequence-gating harness image and run the adversarial attack.
# Docker or Podman. Run from the repo root or anywhere:
#   ./ctf/gating/run.sh            # adversarial attack
#   ./ctf/gating/run.sh test       # full cargo test suite (authoritative, Linux)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE=guard-gating
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
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

echo "=== Building $IMAGE (compiles guard for Linux) ==="
"$ENGINE" build "${BUILD_FLAGS[@]}" -t "$IMAGE" -f "$SCRIPT_DIR/Containerfile" "$REPO_ROOT"

mode="${1:-attack}"
case "$mode" in
  attack)
    echo "=== Running adversarial gating attack ==="
    "$ENGINE" run --rm "${RUN_FLAGS[@]}" "$IMAGE"
    ;;
  test)
    echo "=== Running full cargo test suite in Linux ==="
    "$ENGINE" run --rm "${RUN_FLAGS[@]}" --entrypoint bash "$IMAGE" \
      -c 'export PATH=/usr/local/cargo/bin:$PATH && cd /src && CARGO_INCREMENTAL=0 AGENT=1 cargo test --locked --quiet'
    ;;
  *)
    echo "usage: $0 [attack|test]" >&2
    exit 2
    ;;
esac
