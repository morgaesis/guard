#!/bin/bash
# Run each synthetic-user contract in a separate rootless Podman container.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE="${GUARD_SU_IMAGE:-guard-gating}"
EVIDENCE_ROOT="$REPO_ROOT/.cache/synthetic-user"
RESULTS_DIR="$EVIDENCE_ROOT/scenarios"
STATUS_FILE="$EVIDENCE_ROOT/status.md"
MEMORY="${GUARD_SU_MEMORY:-2g}"
CPUS="${GUARD_SU_CPUS:-2}"
PIDS="${GUARD_SU_PIDS:-256}"
PREFIX="guard-su"
ACTIVE_CONTAINER=""
ACTIVE_VOLUME=""
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
RUN_DIR=""
MANIFEST=""
PRESERVED_FIXTURES=0
HOST_FAILURE_PHASE=""
HOST_FAILURE_CATEGORY=""
HOST_FAILURE_EXEC_STATUS=""
HOST_FAILURE_EVIDENCE=""

write_status() {
  local scenario="$1" container="$2" volume="$3" result="$4" issue="$5" next="$6"
  {
    echo "# Synthetic-user status"
    echo
    echo "- Worktree: \`$REPO_ROOT\`"
    echo "- Branch: \`$(git -C "$REPO_ROOT" branch --show-current)\`"
    if [ -n "$RUN_DIR" ]; then
      echo "- Run evidence: \`${RUN_DIR#"$REPO_ROOT/"}\`"
    fi
    echo "- Current scenario: $scenario"
    echo "- Containers: $container"
    echo "- Networks: none (\`--network none\`)"
    echo "- Volumes: $volume"
    echo "- Result: $result"
    echo "- Confirmed issue: $issue"
    echo "- Next action: $next"
    if [ -n "$HOST_FAILURE_PHASE" ]; then
      echo "- Host-side failure: phase \`$HOST_FAILURE_PHASE\`, category \`$HOST_FAILURE_CATEGORY\`, podman exec status \`$HOST_FAILURE_EXEC_STATUS\`"
      echo "- Host-side failure evidence: \`$HOST_FAILURE_EVIDENCE\`"
    fi
  } >"$STATUS_FILE"
}

redact_host_field() {
  printf '%s' "$1" | sed -E \
    -e 's/[[:cntrl:]]/ /g' \
    -e 's/gr-[A-Za-z0-9_-]+/[redacted-handle]/g' \
    -e 's#/(scenario|tmp)/[^[:space:]]*#[redacted-path]#g'
}

record_host_failure() {
  local scenario="$1" phase="$2" category="$3" exec_status="$4"
  local evidence="$RESULTS_DIR/$scenario.host-failure.md"
  HOST_FAILURE_PHASE="$(redact_host_field "$phase")"
  HOST_FAILURE_CATEGORY="$(redact_host_field "$category")"
  case "$exec_status" in
    ''|*[!0-9]*) HOST_FAILURE_EXEC_STATUS="[redacted-status]" ;;
    *) HOST_FAILURE_EXEC_STATUS="$exec_status" ;;
  esac
  HOST_FAILURE_EVIDENCE="scenarios/$(basename "$evidence")"
  {
    echo "# Synthetic-user host failure"
    echo
    echo "- Scenario: \`$(redact_host_field "$scenario")\`"
    echo "- Phase: \`$HOST_FAILURE_PHASE\`"
    echo "- Command category: \`$HOST_FAILURE_CATEGORY\`"
    echo "- Podman exec status: \`$HOST_FAILURE_EXEC_STATUS\`"
  } >"$evidence"
}

command_category_for_phase() {
  case "$1" in
    *help*) echo help ;;
    *request*|*approve*|*deny*|*hold*|*revoke*|*extend*|*list*|*show*|*inspect*|*verify*) echo access ;;
    *use*|*consume*|*replay*|*execute*|*race*|*after*|*contract*) echo execution ;;
    *) echo scenario ;;
  esac
}

copy_scenario_result() {
  local container="$1" scenario="$2"
  if [ "${GUARD_SU_TEST_COPY_FAILURE:-0}" = 1 ]; then
    return 1
  fi
  podman cp "$container:/scenario/results/$scenario.md" "$RESULTS_DIR/$scenario.md"
}

write_missing_result_evidence() {
  local scenario="$1"
  {
    echo "# $scenario"
    echo
    echo "- Result: failed"
    echo "- Classification: fixture defect"
    echo "- Evidence: the isolated scenario did not produce a copyable sanitized result"
    echo "- Isolation: rootless container, private daemon/socket/database/fixtures/principal/network namespace, network disabled"
    echo "- Raw transcript: retained only in the ephemeral scenario volume"
  } >"$RESULTS_DIR/$scenario.md"
}

assert_isolated_container() {
  local container="$1" mounts
  [ "$(podman inspect --format '{{.HostConfig.NetworkMode}}' "$container")" = none ]
  [ "$(podman inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container")" = true ]
  [ "$(podman inspect --format '{{.Config.User}}' "$container")" = 1000:1000 ]
  podman inspect --format '{{json .HostConfig.SecurityOpt}}' "$container" | grep -Fq 'no-new-privileges'
  podman inspect --format '{{json .HostConfig.CapDrop}}' "$container" | grep -Fq 'ALL'
  mounts="$(podman inspect --format '{{range .Mounts}}{{printf "%s %s\n" .Type .Destination}}{{end}}' "$container")"
  [ "$mounts" = 'volume /scenario' ]
}

self_test() {
  local test_dir test_evidence
  test_dir="$(mktemp -d)"
  RESULTS_DIR="$test_dir"
  record_host_failure SU-TEST 'phase-gr-test-handle /scenario/private' access 125
  test_evidence="$RESULTS_DIR/SU-TEST.host-failure.md"
  grep -Fq 'Phase: `phase-[redacted-handle] [redacted-path]`' "$test_evidence"
  grep -Fq 'Command category: `access`' "$test_evidence"
  grep -Fq 'Podman exec status: `125`' "$test_evidence"
  if grep -Fq 'gr-test-handle' "$test_evidence"; then
    return 1
  fi
  if grep -Fq '/scenario/private' "$test_evidence"; then
    return 1
  fi
  [ "$(command_category_for_phase hold)" = access ]
  GUARD_SU_TEST_COPY_FAILURE=1
  export GUARD_SU_TEST_COPY_FAILURE
  if copy_scenario_result ignored SU-TEST; then
    return 1
  fi
  unset GUARD_SU_TEST_COPY_FAILURE
  rm -r "$test_dir"
}

if [ "${1:-}" = --self-test ]; then
  self_test
  echo "synthetic-user runner self-test: passed"
  exit 0
fi

if [ "$(id -u)" -eq 0 ]; then
  echo "synthetic-user scenarios require rootless Podman" >&2
  exit 2
fi
if ! command -v podman >/dev/null 2>&1; then
  echo "synthetic-user scenarios require Podman" >&2
  exit 2
fi
if [ "$(podman info --format '{{.Host.Security.Rootless}}')" != "true" ]; then
  echo "synthetic-user scenarios require rootless Podman" >&2
  exit 2
fi
mkdir -p "$EVIDENCE_ROOT"
exec 9>"$EVIDENCE_ROOT/runner.lock"
if ! flock -n 9; then
  echo "another synthetic-user run is active in this worktree" >&2
  exit 2
fi

CATALOG=(SU-01 SU-02 SU-03 SU-04 SU-05 SU-06 SU-07 SU-08 SU-09 SU-10 SU-11
  SU-12-ssh SU-12-cloudstack SU-12-kubernetes SU-12-helm SU-12-ansible
  SU-12-host-maintenance SU-12-api SU-13 SU-14 SU-15 SU-16 SU-17 SU-18)
if [ "$#" -eq 0 ]; then
  set -- "${CATALOG[@]}"
fi
TOTAL="$#"
SELECTED=("$@")
FULL_CATALOG=false
if [ "${SELECTED[*]}" = "${CATALOG[*]}" ]; then
  FULL_CATALOG=true
fi
RUN_DIR="$EVIDENCE_ROOT/runs/$RUN_ID"
RESULTS_DIR="$RUN_DIR/scenarios"
MANIFEST="$RUN_DIR/manifest.md"
mkdir -p "$RESULTS_DIR"
SOURCE_MANIFEST="$RUN_DIR/source-files.sha256"
(
  cd "$REPO_ROOT"
  find Cargo.toml Cargo.lock build.rs deny.toml src config tests examples \
    ctf/gating/verbs.yaml ctf/gating/attack.sh ctf/gating/synthetic-user.sh \
    ctf/gating/fake-llm.rs -type f -print0 |
    LC_ALL=C sort -z |
    xargs -0 sha256sum
) > "$SOURCE_MANIFEST"
SOURCE_DIGEST="$(sha256sum "$SOURCE_MANIFEST" | cut -d ' ' -f 1)"
printf '%s\n' "runs/$RUN_ID" > "$EVIDENCE_ROOT/latest-run"
{
  echo "# Synthetic-user run manifest"
  echo
  echo "- Run: \`$RUN_ID\`"
  echo "- Commit: \`$(git -C "$REPO_ROOT" rev-parse HEAD)\`"
  echo "- Source manifest: \`source-files.sha256\`"
  echo "- Source digest: \`$SOURCE_DIGEST\`"
  echo "- Image: \`$(podman image inspect "$IMAGE" --format '{{.Id}}')\`"
  echo "- Complete catalog: \`$FULL_CATALOG\`"
  echo "- Selected scenarios: \`${SELECTED[*]}\`"
  echo "- Status: running"
} > "$MANIFEST"

cleanup_one() {
  local container="$1" volume="$2"
  podman stop --time 5 "$container" >/dev/null 2>&1 || true
  podman rm "$container" >/dev/null 2>&1 || true
  podman volume rm "$volume" >/dev/null 2>&1 || true
}

cleanup_active() {
  if [ -n "$ACTIVE_CONTAINER" ] && [ -n "$ACTIVE_VOLUME" ]; then
    cleanup_one "$ACTIVE_CONTAINER" "$ACTIVE_VOLUME"
  fi
}

trap cleanup_active EXIT
trap 'exit 130' INT TERM

run_one() {
  local scenario="$1"
  local slug container volume result exec_status
  HOST_FAILURE_PHASE=""
  HOST_FAILURE_CATEGORY=""
  HOST_FAILURE_EXEC_STATUS=""
  HOST_FAILURE_EVIDENCE=""
  if [ -f "$RESULTS_DIR/$scenario.host-failure.md" ]; then
    rm -- "$RESULTS_DIR/$scenario.host-failure.md"
  fi
  slug="$(printf '%s' "$scenario" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-')"
  container="$PREFIX-$slug-$RUN_ID"
  volume="$PREFIX-$slug-$RUN_ID-data"
  ACTIVE_CONTAINER="$container"
  ACTIVE_VOLUME="$volume"
  result="blocked"
  trap 'cleanup_one "$container" "$volume"' RETURN

  write_status "$scenario" "$container" "$volume" "starting" "none established" "create the isolated fixture"
  podman volume create "$volume" >/dev/null

  {
    printf '%s\n' 'GUARD_SWEEPER_GRACE_SECS=1'
    if [ "$scenario" = SU-18 ]; then
      printf '%s\n' 'GUARD_ACCESS_TTL_SECS=3'
    fi
  } |
  if podman create \
    --name "$container" \
    --user 1000:1000 \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --memory "$MEMORY" \
    --memory-swap "$MEMORY" \
    --cpus "$CPUS" \
    --pids-limit "$PIDS" \
    --tmpfs /tmp:rw,nosuid,nodev,size=256m,mode=1777 \
    --tmpfs /var/log:rw,nosuid,nodev,size=32m,mode=0700 \
    --volume "$volume:/scenario:rw,U" \
    --env-file /dev/stdin \
    --entrypoint /synthetic-user.sh \
    "$IMAGE" daemon "$scenario" >/dev/null; then
    :
  else
    exec_status=$?
    record_host_failure "$scenario" container-create container-create "$exec_status"
    return 1
  fi

  if assert_isolated_container "$container"; then
    :
  else
    record_host_failure "$scenario" container-hardening container-create 1
    return 1
  fi

  if podman start "$container" >/dev/null; then
    :
  else
    exec_status=$?
    record_host_failure "$scenario" container-start container-start "$exec_status"
    return 1
  fi
  local ready=false
  for _ in $(seq 1 100); do
    if podman exec "$container" test -S /scenario/run/guard.sock >/dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 0.1
  done
  if [ "$ready" != true ]; then
    record_host_failure "$scenario" daemon-readiness container-readiness 1
    echo "$scenario: isolated Guard daemon did not become ready" >&2
    return 1
  fi
  if ! podman exec --user 1000:1000 "$container" chmod 0711 /scenario/run \
    || ! podman exec --user 1000:1000 "$container" chmod 0666 /scenario/run/guard.sock
  then
    record_host_failure "$scenario" daemon-socket-permissions container-setup 1
    return 1
  fi

  write_status "$scenario" "$container" "$volume" "running" "under evaluation" "run the deterministic contract"
  if run_scenario "$container" "$scenario"; then
    result="passed"
  else
    result="failed"
    podman exec --user 1000:1000 "$container" /synthetic-user.sh failure "$scenario" || true
  fi
  if [ "$result" = passed ] && [ "$scenario" = SU-12-api ]; then
    if ! podman exec --user 1000:1000 "$container" /synthetic-user.sh postcheck "$scenario"; then
      result="failed"
    fi
  fi

  if ! copy_scenario_result "$container" "$scenario"; then
    record_host_failure "$scenario" result-copy evidence-copy 1
    write_missing_result_evidence "$scenario"
    result="failed"
  fi
  if [ "$result" = failed ] && [ "${GUARD_SU_KEEP_FAILED:-0}" = 1 ]; then
    echo "$scenario: preserving failed fixture container=$container volume=$volume" >&2
    PRESERVED_FIXTURES=$((PRESERVED_FIXTURES + 1))
    ACTIVE_CONTAINER=""
    ACTIVE_VOLUME=""
    trap - RETURN
    return 1
  fi
  cleanup_one "$container" "$volume"
  ACTIVE_CONTAINER=""
  ACTIVE_VOLUME=""
  trap - RETURN
  write_status "$scenario" "none" "none" "$result" "see scenarios/$scenario.md" "continue with the next isolated scenario"
  [ "$result" = passed ]
}

run_phase() {
  local container="$1" scenario="$2" uid="$3" phase="$4" command_category exec_status
  command_category="$(command_category_for_phase "$phase")"
  if podman exec \
    --user "$uid:$uid" \
    --env HOME="/tmp/synthetic-home-$uid" \
    --env XDG_CONFIG_HOME="/tmp/synthetic-config-$uid" \
    --env XDG_DATA_HOME="/tmp/synthetic-data-$uid" \
    "$container" timeout 120 /synthetic-user.sh phase "$scenario" "$phase"
  then
    return 0
  else
    exec_status=$?
  fi
  record_host_failure "$scenario" "$phase" "$command_category" "$exec_status"
  return "$exec_status"
}

restart_daemon() {
  local container="$1" scenario="$2"
  if ! podman restart "$container" >/dev/null; then
    record_host_failure "$scenario" daemon-restart container-restart 1
    return 1
  fi
  local ready=false
  for _ in $(seq 1 100); do
    if podman exec "$container" test -S /scenario/run/guard.sock >/dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 0.1
  done
  if [ "$ready" != true ]; then
    record_host_failure "$scenario" restart-readiness container-readiness 1
    return 1
  fi
  if ! podman exec --user 1000:1000 "$container" chmod 0711 /scenario/run \
    || ! podman exec --user 1000:1000 "$container" chmod 0666 /scenario/run/guard.sock
  then
    record_host_failure "$scenario" restart-socket-permissions container-setup 1
    return 1
  fi
}

run_scenario() {
  local container="$1" scenario="$2"
  case "$scenario" in
    SU-13)
      run_phase "$container" "$scenario" 1001 request || return
      run_phase "$container" "$scenario" 1000 approve || return
      run_phase "$container" "$scenario" 1001 use || return
      run_phase "$container" "$scenario" 1000 approve-execution || return
      run_phase "$container" "$scenario" 1002 isolate || return
      restart_daemon "$container" "$scenario" || return
      run_phase "$container" "$scenario" 1001 after-restart || return
      run_phase "$container" "$scenario" 1000 revoke || return
      run_phase "$container" "$scenario" 1001 after-revoke || return
      run_phase "$container" "$scenario" 1000 verify || return
      ;;
    SU-14)
      run_phase "$container" "$scenario" 1001 request || return
      run_phase "$container" "$scenario" 1000 approve || return
      run_phase "$container" "$scenario" 1002 replay || return
      run_phase "$container" "$scenario" 1001 consume || return
      restart_daemon "$container" "$scenario" || return
      run_phase "$container" "$scenario" 1001 after-restart || return
      run_phase "$container" "$scenario" 1000 verify || return
      ;;
    SU-15)
      run_phase "$container" "$scenario" 1001 deny || return
      run_phase "$container" "$scenario" 1000 approve || return
      run_phase "$container" "$scenario" 1001 hold || return
      run_phase "$container" "$scenario" 1000 verify || return
      ;;
    SU-16)
      run_phase "$container" "$scenario" 1001 request-primary || return
      run_phase "$container" "$scenario" 1002 request-secondary || return
      run_phase "$container" "$scenario" 1000 approve-primary-scope || return
      run_phase "$container" "$scenario" 1001 reject-primary-cross-scope || return
      run_phase "$container" "$scenario" 1002 reject-secondary-cross-scope || return
      run_phase "$container" "$scenario" 1000 approve-batch || return
      run_phase "$container" "$scenario" 1002 consume-secondary || return
      run_phase "$container" "$scenario" 1001 race-and-fail || return
      restart_daemon "$container" "$scenario" || return
      run_phase "$container" "$scenario" 1001 after-restart || return
      run_phase "$container" "$scenario" 1000 verify || return
      ;;
    SU-17)
      run_phase "$container" "$scenario" 1001 request || return
      run_phase "$container" "$scenario" 1000 approve-and-extend || return
      run_phase "$container" "$scenario" 1001 consume-extension || return
      run_phase "$container" "$scenario" 1000 retry-extension || return
      run_phase "$container" "$scenario" 1001 consume-maintenance || return
      run_phase "$container" "$scenario" 1000 verify || return
      ;;
    SU-18)
      run_phase "$container" "$scenario" 1001 help-and-request || return
      run_phase "$container" "$scenario" 1000 inspect || return
      run_phase "$container" "$scenario" 1001 consume-before-expiry || return
      sleep 4
      restart_daemon "$container" "$scenario" || return
      run_phase "$container" "$scenario" 1001 after-expiry || return
      run_phase "$container" "$scenario" 1000 revoke || return
      restart_daemon "$container" "$scenario" || return
      run_phase "$container" "$scenario" 1001 after-revoke || return
      run_phase "$container" "$scenario" 1000 verify || return
      ;;
    *)
      run_phase "$container" "$scenario" 1001 contract || return
      ;;
  esac
}

failures=0
for scenario in "$@"; do
  if ! run_one "$scenario"; then
    failures=$((failures + 1))
  fi
done

HOST_FAILURE_PHASE=""
HOST_FAILURE_CATEGORY=""
HOST_FAILURE_EXEC_STATUS=""
HOST_FAILURE_EVIDENCE=""

leftovers="$(podman ps -a --format '{{.Names}}' | grep -c -- "-$RUN_ID$" || true)"
leftover_volumes="$(podman volume ls --format '{{.Name}}' | grep -c -- "-$RUN_ID-data$" || true)"
leftover_networks=0
if [ "$leftovers" -ne "$PRESERVED_FIXTURES" ] \
  || [ "$leftover_volumes" -ne "$PRESERVED_FIXTURES" ] \
  || [ "$leftover_networks" -ne 0 ]; then
  echo "synthetic-user cleanup invariant failed" >&2
  exit 1
fi

write_status "complete" "none" "none" "$((TOTAL - failures)) passed, $failures failed" \
  "see per-scenario evidence" "review the report and integrated diff"
{
  echo
  echo "## Outcomes"
  for scenario in "${SELECTED[@]}"; do
    evidence="$RESULTS_DIR/$scenario.md"
    outcome=$(sed -n 's/^- Result: //p' "$evidence" | head -n 1)
    digest=$(sha256sum "$evidence" | cut -d ' ' -f 1)
    echo "- \`$scenario\`: $outcome, evidence \`$digest\`"
  done
  if [ "$FULL_CATALOG" = true ] && [ "$failures" -eq 0 ]; then
    echo "- Status: complete catalog passed"
  else
    echo "- Status: incomplete or failed catalog"
  fi
} >> "$MANIFEST"
exit "$failures"
