#!/bin/bash
# Build the consequence-gating harness image and run the adversarial attack.
# Docker or Podman. Run from the repo root or anywhere:
#   ./ctf/gating/run.sh            # adversarial attack
#   ./ctf/gating/run.sh test       # full cargo test suite (authoritative, Linux)
#   ./ctf/gating/run.sh static     # shell and cross-file boundary validation
#   ./ctf/gating/run.sh mutation   # fixed-attack argv mutation validation
#   ./ctf/gating/run.sh synthetic-user [SU-01 ...]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE="localhost/guard-gating-run-$$"
ATTACK_CONTAINER="guard-gating-attack-$$"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
CONTAINER_MEMORY="${CTF_CONTAINER_MEMORY:-8g}"
CONTAINER_MEMORY_SWAP="${CTF_CONTAINER_MEMORY_SWAP:-8g}"
CONTAINER_CPU_PERIOD="${CTF_CONTAINER_CPU_PERIOD:-100000}"
CONTAINER_CPU_QUOTA="${CTF_CONTAINER_CPU_QUOTA:-200000}"
CONTAINER_CPUS="${CTF_CONTAINER_CPUS:-2}"
CONTAINER_PIDS_LIMIT="${CTF_CONTAINER_PIDS_LIMIT:-512}"
BUILD_TIMEOUT_SECS="${CTF_BUILD_TIMEOUT_SECS:-1200}"
ATTACK_TIMEOUT_SECS="${CTF_ATTACK_TIMEOUT_SECS:-300}"
CLEANUP_TIMEOUT_SECS="${CTF_CLEANUP_TIMEOUT_SECS:-20}"
DIAGNOSTIC_TIMEOUT_SECS="${CTF_DIAGNOSTIC_TIMEOUT_SECS:-5}"
KILL_GRACE_SECS="${CTF_KILL_GRACE_SECS:-5}"
ENGINE="${CONTAINER_ENGINE:-}"
if [ -z "$ENGINE" ]; then
  if command -v podman >/dev/null 2>&1; then
    ENGINE=podman
  else
    ENGINE=docker
  fi
fi

ACTIVE_PHASE=setup
DIAGNOSTIC_DIR="${CTF_DIAGNOSTIC_DIR:-}"
DIAGNOSTIC_FILE=""
CLEANUP_STARTED=0
BUILD_ATTEMPTED=0
ATTACK_ATTEMPTED=0
CONTAINER_STATE_RECORDED=0

validate_timeout_seconds() {
  local phase="$1" value="$2" maximum
  case "$phase" in
    build) maximum=1200 ;;
    attack) maximum=300 ;;
    cleanup) maximum=30 ;;
    diagnostic) maximum=10 ;;
    kill-grace) maximum=5 ;;
    *)
      echo "unknown fixed-identity timeout phase: $phase" >&2
      return 1
      ;;
  esac
  if ! [[ "$value" =~ ^[1-9][0-9]*$ ]] || ((value > maximum)); then
    echo "fixed-identity $phase timeout must be a whole number from 1 through $maximum seconds" >&2
    return 1
  fi
}

validate_timeout_configuration() {
  validate_timeout_seconds build "$BUILD_TIMEOUT_SECS"
  validate_timeout_seconds attack "$ATTACK_TIMEOUT_SECS"
  validate_timeout_seconds cleanup "$CLEANUP_TIMEOUT_SECS"
  validate_timeout_seconds diagnostic "$DIAGNOSTIC_TIMEOUT_SECS"
  validate_timeout_seconds kill-grace "$KILL_GRACE_SECS"
  command -v timeout >/dev/null 2>&1 || {
    echo "fixed-identity adversarial gate requires GNU timeout for bounded execution" >&2
    return 1
  }
}

prepare_diagnostics() {
  if [ -z "$DIAGNOSTIC_DIR" ]; then
    DIAGNOSTIC_DIR="$(mktemp -d "${TMPDIR:-/tmp}/guard-adversarial-diagnostics.XXXXXX")"
  else
    mkdir -p -- "$DIAGNOSTIC_DIR"
  fi
  chmod 0700 "$DIAGNOSTIC_DIR"
  DIAGNOSTIC_FILE="$DIAGNOSTIC_DIR/summary.txt"
  umask 077
  printf '%s\n' \
    'format=guard-adversarial-diagnostic-v1' \
    'content=controlled-phase-and-container-state-only' > "$DIAGNOSTIC_FILE"
}

record_phase_result() {
  local phase="$1" outcome="$2" exit_status="$3" elapsed="$4"
  [ -n "$DIAGNOSTIC_FILE" ] || return 0
  printf 'phase=%s outcome=%s exit_status=%s elapsed_seconds=%s\n' \
    "$phase" "$outcome" "$exit_status" "$elapsed" >> "$DIAGNOSTIC_FILE"
}

run_bounded_phase() {
  local phase="$1" deadline="$2" started status outcome elapsed
  shift 2
  started=$SECONDS
  # Keep GNU timeout's default process-group isolation so TERM and the
  # follow-up KILL reach every descendant.
  if timeout --signal=TERM --kill-after="$KILL_GRACE_SECS" "$deadline" "$@"; then
    status=0
  else
    status=$?
  fi
  elapsed=$((SECONDS - started))
  if [ "$status" -eq 0 ]; then
    record_phase_result "$phase" success "$status" "$elapsed"
    return 0
  fi
  if [ "$status" -eq 124 ]; then
    outcome=timed-out
  elif [ "$status" -eq 137 ]; then
    outcome=killed-or-timed-out
  else
    outcome=failed
  fi
  record_phase_result "$phase" "$outcome" "$status" "$elapsed"
  echo "FAIL: fixed-identity adversarial gate $phase phase $outcome after ${elapsed}s (exit $status)" >&2
  return "$status"
}

record_sanitized_container_state() {
  local state exit_code
  [ -n "${ATTACK_CONTAINER:-}" ] || return 0
  CONTAINER_STATE_RECORDED=1
  state="$(timeout --signal=TERM --kill-after="$KILL_GRACE_SECS" "$DIAGNOSTIC_TIMEOUT_SECS" \
    "$ENGINE" container inspect --format '{{.State.Status}}' "$ATTACK_CONTAINER" 2>/dev/null || true)"
  case "$state" in
    created|running|paused|restarting|removing|exited|dead) ;;
    *) state=unavailable ;;
  esac
  exit_code="$(timeout --signal=TERM --kill-after="$KILL_GRACE_SECS" "$DIAGNOSTIC_TIMEOUT_SECS" \
    "$ENGINE" container inspect --format '{{.State.ExitCode}}' "$ATTACK_CONTAINER" 2>/dev/null || true)"
  if ! [[ "$exit_code" =~ ^[0-9]+$ ]]; then
    exit_code=unavailable
  fi
  printf 'container_state=%s container_exit_code=%s\n' "$state" "$exit_code" >> "$DIAGNOSTIC_FILE"
}

bounded_engine_cleanup() {
  timeout --signal=TERM --kill-after="$KILL_GRACE_SECS" "$CLEANUP_TIMEOUT_SECS" \
    "$ENGINE" "$@" >/dev/null 2>&1
}

cleanup() {
  local cleanup_status=0
  if [ "$CLEANUP_STARTED" -ne 0 ]; then
    return 0
  fi
  CLEANUP_STARTED=1
  if [ "$ATTACK_ATTEMPTED" -ne 0 ] && [ -n "${ATTACK_CONTAINER:-}" ]; then
    if [ "$CONTAINER_STATE_RECORDED" -eq 0 ]; then
      record_sanitized_container_state
    fi
    if bounded_engine_cleanup container rm -f "$ATTACK_CONTAINER"; then
      ATTACK_CONTAINER=""
    else
      cleanup_status=1
    fi
  fi
  if [ "$BUILD_ATTEMPTED" -ne 0 ] && ! bounded_engine_cleanup image rm "$IMAGE"; then
    cleanup_status=1
  fi
  if [ -n "$DIAGNOSTIC_FILE" ]; then
    if [ "$cleanup_status" -eq 0 ]; then
      printf '%s\n' 'cleanup=success' >> "$DIAGNOSTIC_FILE"
    else
      printf '%s\n' 'cleanup=failed-or-timed-out' >> "$DIAGNOSTIC_FILE"
    fi
  fi
  return "$cleanup_status"
}
trap cleanup EXIT

handle_signal() {
  local signal="$1"
  trap - INT TERM
  if [ -n "$DIAGNOSTIC_FILE" ]; then
    record_phase_result "$ACTIVE_PHASE" "interrupted-signal-$signal" 0 0
  fi
  cleanup || true
  kill -s "$signal" "$$"
}
trap 'handle_signal INT' INT
trap 'handle_signal TERM' TERM

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
ATTACK_CONTAINER_ARGUMENTS=(--name "$ATTACK_CONTAINER" "${RUN_FLAGS[@]}" "${ATTACK_RUN_FLAGS[@]}" "$IMAGE")

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
  local -A option_counts=()
  local -a required_single_options=(
    --name
    --memory
    --memory-swap
    --cpus
    --pids-limit
    --read-only
    --network
    --cap-drop
    --security-opt
  )
  local image_count=0
  local podman_implicit_tmpfs_disabled_count=0
  local index argument value expected_value required_option

  for ((index = 0; index < ${#arguments[@]}; index++)); do
    argument="${arguments[index]}"
    case "$argument" in
      --read-only)
        option_counts["$argument"]=$(( ${option_counts[$argument]:-0} + 1 ))
        ;;
      --read-only-tmpfs=false)
        if [ "$ENGINE" != podman ]; then
          echo "fixed attack contains the Podman-only option $argument for $ENGINE" >&2
          return 1
        fi
        podman_implicit_tmpfs_disabled_count=$((podman_implicit_tmpfs_disabled_count + 1))
        ;;
      --name|--memory|--memory-swap|--cpus|--pids-limit|--network|--cap-drop|--cap-add|--security-opt|--tmpfs)
        index=$((index + 1))
        if ((index >= ${#arguments[@]})); then
          echo "fixed attack argument $argument has no value" >&2
          return 1
        fi
        value="${arguments[index]}"
        option_counts["$argument"]=$(( ${option_counts[$argument]:-0} + 1 ))
        case "$argument" in
          --name)
            expected_value="$ATTACK_CONTAINER"
            ;;
          --memory)
            expected_value="$CONTAINER_MEMORY"
            ;;
          --memory-swap)
            expected_value="$CONTAINER_MEMORY_SWAP"
            ;;
          --cpus)
            expected_value="$CONTAINER_CPUS"
            ;;
          --pids-limit)
            expected_value="$CONTAINER_PIDS_LIMIT"
            ;;
          --network)
            expected_value=none
            ;;
          --cap-drop)
            expected_value=ALL
            ;;
          --cap-add)
            observed_capabilities+=("$value")
            continue
            ;;
          --security-opt)
            expected_value=no-new-privileges
            ;;
          --tmpfs)
            observed_tmpfs+=("$value")
            continue
            ;;
        esac
        if [ "$value" != "$expected_value" ]; then
          echo "fixed attack argument $argument must equal $expected_value" >&2
          return 1
        fi
        ;;
      --*)
        echo "fixed attack contains an unknown option: $argument" >&2
        return 1
        ;;
      *)
        if [ "$argument" != "$IMAGE" ]; then
          echo "fixed attack contains an unexpected positional argument: $argument" >&2
          return 1
        fi
        image_count=$((image_count + 1))
        if ((index != ${#arguments[@]} - 1)); then
          echo "fixed attack image must be the final argument with no command override" >&2
          return 1
        fi
        ;;
    esac
  done

  for required_option in "${required_single_options[@]}"; do
    if [ "${option_counts[$required_option]:-0}" -ne 1 ]; then
      echo "fixed attack must contain $required_option exactly once" >&2
      return 1
    fi
  done
  if [ "${observed_capabilities[*]}" != "${expected_capabilities[*]}" ]; then
    echo "fixed attack capability additions differ from CHOWN, SETGID, and SETUID" >&2
    return 1
  fi
  if [ "${observed_tmpfs[*]}" != "${expected_tmpfs[*]}" ]; then
    echo "fixed attack writable tmpfs arguments differ from the bounded fixture set" >&2
    return 1
  fi
  if [ "$image_count" -ne 1 ]; then
    echo "fixed attack must contain exactly one expected image argument" >&2
    return 1
  fi
  if [[ "$IMAGE" != localhost/* ]]; then
    echo "fixed attack image must use a localhost-qualified local reference" >&2
    return 1
  fi
  if [ "$ENGINE" = podman ] && [ "$podman_implicit_tmpfs_disabled_count" -ne 1 ]; then
    echo "fixed attack must disable Podman's implicit writable scratch mounts" >&2
    return 1
  fi
}

expect_attack_argument_rejection() {
  local mutation="$1"
  shift
  if validate_attack_container_arguments "$@" >/dev/null 2>&1; then
    echo "FAIL: fixed attack argv mutation was accepted: $mutation" >&2
    return 1
  fi
  echo "PASS: fixed attack argv rejected $mutation"
}

expect_timeout_rejection() {
  local mutation="$1" phase="$2" value="$3"
  if validate_timeout_seconds "$phase" "$value" >/dev/null 2>&1; then
    echo "FAIL: fixed-identity timeout mutation was accepted: $mutation" >&2
    return 1
  fi
  echo "PASS: fixed-identity timeout rejected $mutation"
}

process_identity_is_running() {
  local process_id="$1" expected_start="$2"
  local -a process_stat=()
  if ! [[ "$process_id" =~ ^[1-9][0-9]*$ ]] || [ ! -r "/proc/$process_id/stat" ]; then
    return 1
  fi
  IFS=' ' read -r -a process_stat < "/proc/$process_id/stat" || return 1
  [ "${process_stat[21]:-}" = "$expected_start" ] \
    && [ "${process_stat[2]:-}" != Z ]
}

cleanup_process_tree_probe() {
  local probe_dir="$1" identity_file="$2" result_file="$3" process_id process_start
  if [ -r "$identity_file" ] \
    && read -r process_id process_start < "$identity_file" \
    && [[ "$process_id" =~ ^[1-9][0-9]*$ ]] \
    && [[ "$process_start" =~ ^[1-9][0-9]*$ ]] \
    && process_identity_is_running "$process_id" "$process_start"; then
    kill -KILL "$process_id" 2>/dev/null || true
  fi
  [ -e "$identity_file" ] && unlink "$identity_file"
  [ -e "$result_file" ] && unlink "$result_file"
  rmdir "$probe_dir"
}

run_timeout_mutation_tests() {
  local status previous_kill previous_diagnostic probe_dir probe_identity_file phase_result_file
  local descendant_id descendant_start descendant_survived=1
  validate_timeout_configuration
  expect_timeout_rejection "zero build deadline" build 0
  expect_timeout_rejection "non-numeric attack deadline" attack forever
  expect_timeout_rejection "unbounded build deadline" build 1201
  expect_timeout_rejection "unbounded attack deadline" attack 301
  expect_timeout_rejection "unbounded cleanup deadline" cleanup 31
  expect_timeout_rejection "unbounded diagnostic deadline" diagnostic 11
  expect_timeout_rejection "unbounded kill grace" kill-grace 6

  probe_dir="$(mktemp -d "${TMPDIR:-/tmp}/guard-timeout-tree.XXXXXX")"
  probe_identity_file="$probe_dir/descendant.identity"
  phase_result_file="$probe_dir/phase-result"
  previous_kill="$KILL_GRACE_SECS"
  previous_diagnostic="$DIAGNOSTIC_FILE"
  KILL_GRACE_SECS=1
  DIAGNOSTIC_FILE="$phase_result_file"
  # The probe script expands these expressions in the child shell.
  # shellcheck disable=SC2016
  if run_bounded_phase process-tree-probe 1 bash -c '
    set -u
    identity_file="$1"
    trap "" TERM
    (
      trap "" TERM
      process_stat=()
      IFS=" " read -r -a process_stat < "/proc/$BASHPID/stat"
      start_time="${process_stat[21]}"
      printf "%s %s\n" "$BASHPID" "$start_time" > "$identity_file"
      while :; do sleep 1; done
    ) &
    while [ ! -s "$identity_file" ]; do sleep 0.05; done
    while :; do sleep 1; done
  ' bash "$probe_identity_file" \
    >/dev/null 2>&1; then
    echo "FAIL: fixed-identity bounded phase accepted a process tree that ignored TERM" >&2
    KILL_GRACE_SECS="$previous_kill"
    DIAGNOSTIC_FILE="$previous_diagnostic"
    cleanup_process_tree_probe "$probe_dir" "$probe_identity_file" "$phase_result_file"
    return 1
  else
    status=$?
  fi
  KILL_GRACE_SECS="$previous_kill"
  DIAGNOSTIC_FILE="$previous_diagnostic"
  case "$status" in
    124)
      grep -Eq '^phase=process-tree-probe outcome=timed-out exit_status=124 ' "$phase_result_file" \
        || {
          echo "FAIL: fixed-identity timeout status was not classified as timed-out" >&2
          cleanup_process_tree_probe "$probe_dir" "$probe_identity_file" "$phase_result_file"
          return 1
        }
      ;;
    137)
      grep -Eq '^phase=process-tree-probe outcome=killed-or-timed-out exit_status=137 ' "$phase_result_file" \
        || {
          echo "FAIL: fixed-identity kill status was not classified as ambiguous" >&2
          cleanup_process_tree_probe "$probe_dir" "$probe_identity_file" "$phase_result_file"
          return 1
        }
      ;;
    *)
      echo "FAIL: fixed-identity bounded phase returned unexpected timeout status $status" >&2
      cleanup_process_tree_probe "$probe_dir" "$probe_identity_file" "$phase_result_file"
      return 1
      ;;
  esac
  echo "PASS: fixed-identity bounded phase classified forced process-tree termination"
  if ! read -r descendant_id descendant_start < "$probe_identity_file" \
    || ! [[ "$descendant_id" =~ ^[1-9][0-9]*$ ]] \
    || ! [[ "$descendant_start" =~ ^[1-9][0-9]*$ ]]; then
    echo "FAIL: fixed-identity process-tree probe did not record a valid descendant identity" >&2
    cleanup_process_tree_probe "$probe_dir" "$probe_identity_file" "$phase_result_file"
    return 1
  fi
  for _ in $(seq 1 20); do
    if process_identity_is_running "$descendant_id" "$descendant_start"; then
      sleep 0.05
    else
      descendant_survived=0
      break
    fi
  done
  if [ "$descendant_survived" -ne 0 ]; then
    echo "FAIL: fixed-identity timeout left a TERM-ignoring descendant running" >&2
    cleanup_process_tree_probe "$probe_dir" "$probe_identity_file" "$phase_result_file"
    return 1
  fi
  cleanup_process_tree_probe "$probe_dir" "$probe_identity_file" "$phase_result_file"
  echo "PASS: fixed-identity timeout left no TERM-ignoring descendant alive"
}

run_attack_argument_mutation_tests() {
  local image_index=$(( ${#ATTACK_CONTAINER_ARGUMENTS[@]} - 1 ))
  local -a before_image=("${ATTACK_CONTAINER_ARGUMENTS[@]:0:image_index}")
  local -a without_read_only=()
  local argument

  for argument in "${ATTACK_CONTAINER_ARGUMENTS[@]}"; do
    if [ "$argument" != --read-only ]; then
      without_read_only+=("$argument")
    fi
  done

  validate_attack_container_arguments "${ATTACK_CONTAINER_ARGUMENTS[@]}"
  echo "PASS: fixed attack argv accepted the real invocation"

  expect_attack_argument_rejection "a missing read-only root" \
    "${without_read_only[@]}"
  expect_attack_argument_rejection "an entrypoint override" \
    "${before_image[@]}" --entrypoint /bin/true "$IMAGE"
  expect_attack_argument_rejection "privileged mode" \
    "${before_image[@]}" --privileged "$IMAGE"
  expect_attack_argument_rejection "a privileged boolean override" \
    "${before_image[@]}" --privileged=true "$IMAGE"
  expect_attack_argument_rejection "a host-network alias" \
    "${before_image[@]}" --net host "$IMAGE"
  expect_attack_argument_rejection "host networking" \
    "${before_image[@]}" --network host "$IMAGE"
  expect_attack_argument_rejection "a changed security option" \
    "${before_image[@]}" --security-opt no-new-privileges=false "$IMAGE"
  expect_attack_argument_rejection "a host volume" \
    "${before_image[@]}" --volume /:/host:ro "$IMAGE"
  expect_attack_argument_rejection "a host storage mount" \
    "${before_image[@]}" --mount type=bind,source=/,target=/host,readonly "$IMAGE"
  expect_attack_argument_rejection "a host device" \
    "${before_image[@]}" --device /dev/null "$IMAGE"
  expect_attack_argument_rejection "inherited container volumes" \
    "${before_image[@]}" --volumes-from fixture "$IMAGE"
  expect_attack_argument_rejection "an extra positional before the image" \
    "${before_image[@]}" unexpected-positional "$IMAGE"
  expect_attack_argument_rejection "a command after the image" \
    "${ATTACK_CONTAINER_ARGUMENTS[@]}" /bin/true
  expect_attack_argument_rejection "a missing image" \
    "${before_image[@]}"
  expect_attack_argument_rejection "a duplicate image" \
    "${ATTACK_CONTAINER_ARGUMENTS[@]}" "$IMAGE"
  expect_attack_argument_rejection "an unknown option" \
    "${before_image[@]}" --future-unsafe-option "$IMAGE"
  expect_attack_argument_rejection "a changed memory limit" \
    "${before_image[@]}" --memory 16g "$IMAGE"
  expect_attack_argument_rejection "an additional capability" \
    "${before_image[@]}" --cap-add SYS_ADMIN "$IMAGE"
  expect_attack_argument_rejection "an additional writable tmpfs" \
    "${before_image[@]}" --tmpfs /extra:rw,size=1m "$IMAGE"
  run_timeout_mutation_tests
}

validate_attack_container_config() {
  run_bounded_phase inspect "$DIAGNOSTIC_TIMEOUT_SECS" python3 - "$ENGINE" "$1" "$DIAGNOSTIC_TIMEOUT_SECS" <<'PY'
import json
import subprocess
import sys


engine, container_name, timeout_seconds = sys.argv[1:]
container = json.loads(
    subprocess.check_output(
        [engine, "container", "inspect", container_name],
        text=True,
        timeout=int(timeout_seconds),
    )
)[0]
host = container.get("HostConfig", {})
config = container.get("Config", {})
expected_caps = {"CHOWN", "SETGID", "SETUID"}
expected_tmpfs = {
    "/tmp": {"rw", "nosuid", "nodev", "noexec", "size=32m", "mode=1777"},
    "/work": {"rw", "nosuid", "nodev", "noexec", "size=16m", "mode=0755"},
    "/fakebin": {"rw", "exec", "nosuid", "nodev", "size=16m", "mode=0755"},
    "/shim": {"rw", "exec", "nosuid", "nodev", "size=16m", "mode=0755"},
    "/run": {"rw", "nosuid", "nodev", "noexec", "size=16m", "mode=0755"},
    "/var/lib/guard": {"rw", "nosuid", "nodev", "noexec", "size=16m", "mode=0755"},
    "/var/log": {"rw", "nosuid", "nodev", "noexec", "size=16m", "mode=0755"},
    "/home/guarddaemon": {"rw", "nosuid", "nodev", "noexec", "size=1m", "mode=0700"},
    "/home/agent": {"rw", "nosuid", "nodev", "noexec", "size=1m", "mode=0700"},
}


def fail(message):
    raise SystemExit(f"FAIL: fixed attack container configuration: {message}")


def caps(values):
    return {str(value).upper().removeprefix("CAP_") for value in values}


if host.get("ReadonlyRootfs") is not True:
    fail("root filesystem is writable")
if host.get("NetworkMode") != "none":
    fail(f"network mode is {host.get('NetworkMode')!r}, not 'none'")
if host.get("Privileged"):
    fail("container is privileged")
if host.get("Binds"):
    fail("container has host bind mounts")
if host.get("Devices"):
    fail("container has host devices")

effective_caps = container.get("EffectiveCaps")
if effective_caps is not None:
    if caps(effective_caps) != expected_caps:
        fail(f"effective capabilities are {sorted(caps(effective_caps))}, not {sorted(expected_caps)}")
else:
    if caps(host.get("CapAdd", [])) != expected_caps or "ALL" not in caps(host.get("CapDrop", [])):
        fail("capability drop/add configuration is not the minimal fixed set")

security_options = {str(value).split(":", 1)[0] for value in host.get("SecurityOpt", [])}
if "no-new-privileges" not in security_options:
    fail("no-new-privileges is absent")

tmpfs = host.get("Tmpfs") or {}
if set(tmpfs) != set(expected_tmpfs):
    fail(f"tmpfs targets are {sorted(tmpfs)}, not {sorted(expected_tmpfs)}")
for target, required_options in expected_tmpfs.items():
    actual_options = {option for option in str(tmpfs[target]).split(",") if option}
    if "exec" in required_options:
        # Engines may omit the default executable flag, but must not make the
        # fixture directories non-executable.
        required_options = required_options - {"exec"}
        if "noexec" in actual_options:
            fail(f"{target} is unexpectedly noexec")
    if not required_options <= actual_options:
        fail(f"{target} lacks {sorted(required_options - actual_options)}")

create_command = config.get("CreateCommand")
if create_command:
    for flag, value in (("--network", "none"), ("--cap-drop", "ALL"), ("--security-opt", "no-new-privileges")):
        if not any(create_command[index:index + 2] == [flag, value] for index in range(len(create_command) - 1)):
            fail(f"engine create command omits {flag} {value}")
    if create_command.count("--read-only") != 1:
        fail("engine create command does not contain exactly one --read-only")

print("PASS: engine inspection confirmed fixed attack root, network, capabilities, and bounded tmpfs")
PY
}

run_attack_container() {
  local attack_status=0 configuration_status=0 cleanup_status=0
  validate_attack_container_arguments "$@"
  ACTIVE_PHASE=attack
  ATTACK_ATTEMPTED=1
  if run_bounded_phase attack "$ATTACK_TIMEOUT_SECS" "$ENGINE" run "$@"; then
    :
  else
    attack_status=$?
  fi
  record_sanitized_container_state
  if validate_attack_container_config "$ATTACK_CONTAINER"; then
    :
  else
    configuration_status=$?
  fi
  if ! cleanup; then
    cleanup_status=1
  fi
  if [ "$attack_status" -ne 0 ]; then
    return "$attack_status"
  fi
  if [ "$configuration_status" -ne 0 ]; then
    return "$configuration_status"
  fi
  return "$cleanup_status"
}

static_validate() {
  local shell_file
  while IFS= read -r shell_file; do
    bash -n "$shell_file"
  done < <(find "$REPO_ROOT/ctf" -type f -name '*.sh' -print | LC_ALL=C sort)
  validate_attack_container_arguments "${ATTACK_CONTAINER_ARGUMENTS[@]}"
  echo "PASS: fixed attack invocation uses a read-only root, no network, and bounded writable tmpfs mounts"
  run_attack_argument_mutation_tests
  python3 - "$REPO_ROOT" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
catalog = (root / "ctf/gating/verbs.yaml").read_text(encoding="utf-8")
containerfile = (root / "ctf/gating/Containerfile").read_text(encoding="utf-8")
dockerignore_rules = {
    line.strip()
    for line in (root / ".dockerignore").read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.lstrip().startswith("#")
}
profiles = (root / "src/gating/verb.rs").read_text(encoding="utf-8")
approval = (root / "src/gating/approval.rs").read_text(encoding="utf-8")
execution = (root / "src/server/execute.rs").read_text(encoding="utf-8")
proxy_server = (root / "src/proxy/server.rs").read_text(encoding="utf-8")
proxy_kubeconfig = (root / "src/proxy/kubeconfig.rs").read_text(encoding="utf-8")
cli_server = (root / "src/cli_server.rs").read_text(encoding="utf-8")
attack = (root / "ctf/gating/attack.sh").read_text(encoding="utf-8")
runner_script = (root / "ctf/gating/run.sh").read_text(encoding="utf-8")
ci_workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
synthetic = (root / "ctf/gating/synthetic-user.sh").read_text(encoding="utf-8")
runner = (root / "ctf/gating/synthetic-user-runner.sh").read_text(encoding="utf-8")
adversary = (root / "ctf/entrypoint-adversary.sh").read_text(encoding="utf-8")
ctf_text = "\n".join(
    path.read_text(encoding="utf-8")
    for path in sorted((root / "ctf").rglob("*"))
    if path.is_file()
)

workflow_fixtures = {
    ".github/dependabot.yml",
    ".github/workflows/dependabot-automerge.yml",
    ".github/workflows/dependabot-enable-automerge.yml",
}
workflow_copy_sources = {
    source
    for line in containerfile.splitlines()
    if line.startswith("COPY ")
    for source in line.split()[1:-1]
    if source.startswith(".github/")
}
workflow_ignore_rules = {
    "!.github/",
    "!.github/dependabot.yml",
    "!.github/workflows/",
    "!.github/workflows/dependabot-automerge.yml",
    "!.github/workflows/dependabot-enable-automerge.yml",
}
workflow_context_rules = {
    rule for rule in dockerignore_rules if rule.startswith("!.github")
}

checks = {
    "capability contract uses the closed whoami profile": "binary: whoami\n    args: [child-contract]" in catalog and '"whoami"' in profiles,
    "credential contract uses the closed true profile": 'binary: "true"' in catalog and '"true"' in profiles,
    "fixture API reuses closed systemd authority under caller identity with protected credentials": all(
        marker in source
        for marker, source in (
            ('binary: systemctl\n    args: ["status", "fixture-api.service"]', catalog),
            ('systemctl:\n    secrets:\n      FIXTURE_API_TOKEN: fixture/api-token', synthetic),
            ('observed_digest="$(printf \'%s\' "$FIXTURE_API_TOKEN" | sha256sum', synthetic),
            ("printf 'fixture-api:healthy uid=%s token=%s\\n'", synthetic),
            ("run_journey fixture-api-status 'fixture-api:healthy uid=1001'", synthetic),
            ('grep -Fq \'[REDACTED]\' "$RAW"', synthetic),
            ('! grep -Fq -f "$FIXTURE_API_TOKEN_FILE" "$RAW"', synthetic),
            ('! grep -Fq -f "$FIXTURE_API_TOKEN_FILE" /scenario/data/audit.jsonl', synthetic),
            ("fixture/api-token", synthetic),
            ('"systemctl" => Some(DelayedAuthorityProfile::SystemdControl)', profiles),
            ('expect_failure fixture-api-raw guard run --json fixture-api status', synthetic),
            ('systemctl status fixture-api.service --output=json', synthetic),
            ('chmod 0600 "$FIXTURE_API_TOKEN_FILE"', synthetic),
            ('chmod 0444 "$FIXTURE_API_TOKEN_DIGEST_FILE"', synthetic),
            ('/synthetic-user.sh provision-api-secret', runner),
        )
    ) and "FixtureApi" not in approval + profiles + execution
      and "binary: fixture-api" not in catalog
      and "/scenario/bin/fixture-api" not in synthetic,
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
    "fixed synthetic daemons carry the child private group": "--group-add 1003" in runner and "daemon_group_arguments" in runner and 'GUARD_SU_DAEMON_MODE' in runner,
    "caller synthetic scenarios start the daemon as root": "SU-12-api|SU-12-ansible) return 0" in runner and '--user "$daemon_user"' in runner and '"$(id -u)" -eq 0' in synthetic,
    "synthetic daemon groups are exact in inspection and runtime and mutation-tested": "HostConfig.GroupAdd" in runner and "GUARD_SU_EXPECTED_GROUPS" in runner and all(
        marker in runner
        for marker in (
            "validate_supplementary_groups",
            "missing fixed private group",
            "unexpected fixed root group",
            "unexpected caller root group",
        )
    ),
    "caller daemon paths and token are explicitly prepared": "assert_daemon_path_contract" in synthetic and "1000:0:440" in synthetic and "chown 0:guard-clients /scenario/run" in synthetic,
    "synthetic catalog uses an anchored read-only directory and one writable lock bind": all(
        marker in runner
        for marker in (
            'CATALOG_DIRECTORY_DESTINATION=/authority',
            '--volume "$authority_volume:/authority:rw"',
            '--volume "$catalog_directory_source:$CATALOG_DIRECTORY_DESTINATION:ro"',
            '--volume "$catalog_lock_source:$CATALOG_LOCK_DESTINATION:rw"',
            'validate_container_mounts',
            "a writable catalog-directory bind",
            "a read-only learning-lock bind",
            "a missing learning-lock bind",
            "a redirected catalog-directory source",
            "a redirected learning-lock source",
            "an additional writable catalog child",
            "an additional host bind",
        )
    ) and "expected_lock=0:0:600" in synthetic and "0555 /authority" in containerfile,
    "catalog mutation remains blocked after reachable owner transitions": all(
        marker in synthetic
        for marker in (
            "assert_catalog_mutation_rejected_after_identity_transition",
            "0 0 root-identity",
            "1000 1000 fixed-daemon-identity",
            "65534 65534 alternate-identity",
            "capture_exact_mount_identity",
            'chmod 0700 "$directory"',
            'mv "$directory" "$directory-replaced"',
            "mkdir /authority-sibling",
            "mv / /tmp/root-replaced",
            'mv "$lock" "$lock-replaced"',
            'expected_catalog_mount',
            'expected_lock_mount',
            'expected_root_mount',
        )
    ) and "/scenario/journey/protected-catalog" not in runner and "/scenario/journey/protected-catalog" not in synthetic,
    "synthetic evidence is private and omits local worktree metadata": (
        "umask 077" in runner
        and "ensure_private_directory" in runner
        and "ensure_private_file" in runner
        and 'echo "- Worktree:' not in runner
        and 'echo "- Branch:' not in runner
    ),
    "synthetic readiness failures retain bounded sanitized startup diagnostics": all(
        marker in runner
        for marker in (
            "collect_startup_diagnostics",
            "sanitize_startup_diagnostics",
            "timeout --kill-after=1s 5s podman logs",
            "timeout --kill-after=1s 5s podman cp",
            "| tar -xOf -",
        )
    ) and "timeout --kill-after=1s 5s podman exec" not in runner,
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
    "fixed-identity workflow has cleanup and artifact headroom": bool(
        re.search(r"adversarial_gate:.*?timeout-minutes:\s*45", ci_workflow, re.DOTALL)
    ) and all(
        marker in ci_workflow
        for marker in (
            'CTF_BUILD_TIMEOUT_SECS: "1200"',
            'CTF_ATTACK_TIMEOUT_SECS: "300"',
            'CTF_CLEANUP_TIMEOUT_SECS: "20"',
            'CTF_DIAGNOSTIC_TIMEOUT_SECS: "5"',
        )
    ),
    "fixed-identity workflow uploads only the controlled summary": (
        "Upload sanitized adversarial diagnostics" in ci_workflow
        and "path: ${{ runner.temp }}/guard-adversarial-diagnostics/summary.txt" in ci_workflow
        and "path: ${{ runner.temp }}/guard-adversarial-diagnostics\n" not in ci_workflow
    ),
    "fixed attack bounds build, attack, inspection, and cleanup": all(
        marker in runner_script
        for marker in (
            "run_bounded_phase build",
            "run_bounded_phase attack",
            "run_bounded_phase inspect",
            "bounded_engine_cleanup",
            "--kill-after=\"$KILL_GRACE_SECS\"",
        )
    ) and ("--" + "foreground") not in runner_script,
    "fixed attack handles termination and records controlled diagnostics": all(
        marker in runner_script
        for marker in (
            "trap 'handle_signal INT' INT",
            "trap 'handle_signal TERM' TERM",
            "record_sanitized_container_state",
            "content=controlled-phase-and-container-state-only",
        )
    ),
    "fixed attack cleanup is bounded, forceful, and idempotent": all(
        marker in runner_script
        for marker in (
            "CLEANUP_STARTED",
            "bounded_engine_cleanup container rm -f",
            "bounded_engine_cleanup image rm",
            "cleanup || true",
        )
    ),
    "fixed attack mutation kills TERM-ignoring descendants": all(
        marker in runner_script
        for marker in (
            "process-tree-probe",
            "process_identity_is_running",
            "left no TERM-ignoring descendant alive",
        )
    ),
    "signal 137 remains an ambiguous forced termination": (
        "outcome=killed-or-timed-out" in runner_script
        and "elif [ \"$status\" -eq 137 ]" in runner_script
    ),
    "container build context includes only Dependabot workflow fixtures": (
        workflow_context_rules == workflow_ignore_rules
        and workflow_copy_sources == workflow_fixtures
        and all((root / fixture).is_file() for fixture in workflow_fixtures)
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
if [ "$mode" = mutation ]; then
  run_attack_argument_mutation_tests
  echo "CTF fixed-attack argv mutation validation passed"
  exit 0
fi

validate_timeout_configuration
prepare_diagnostics
echo "Sanitized fixed-identity diagnostics: $DIAGNOSTIC_FILE"

echo "=== Building $IMAGE (compiles guard for Linux) ==="
ACTIVE_PHASE=build
BUILD_ATTEMPTED=1
run_bounded_phase build "$BUILD_TIMEOUT_SECS" \
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
    echo "usage: $0 [attack|test|static|mutation|synthetic-user [SCENARIO...]]" >&2
    exit 2
    ;;
esac
