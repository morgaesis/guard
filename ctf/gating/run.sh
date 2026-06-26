#!/bin/bash
# Build the consequence-gating harness image and run the adversarial attack.
# Docker only (podman not required). Run from the repo root or anywhere:
#   ./ctf/gating/run.sh            # adversarial attack
#   ./ctf/gating/run.sh test       # full cargo test suite (authoritative, Linux)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE=guard-gating

echo "=== Building $IMAGE (compiles guard for Linux) ==="
docker build -t "$IMAGE" -f "$SCRIPT_DIR/Containerfile" "$REPO_ROOT"

mode="${1:-attack}"
case "$mode" in
  attack)
    echo "=== Running adversarial gating attack ==="
    docker run --rm "$IMAGE"
    ;;
  test)
    echo "=== Running full cargo test suite in Linux ==="
    docker run --rm --entrypoint bash "$IMAGE" \
      -c 'export PATH=/usr/local/cargo/bin:$PATH && cd /src && AGENT=1 cargo test --quiet'
    ;;
  *)
    echo "usage: $0 [attack|test]" >&2
    exit 2
    ;;
esac
