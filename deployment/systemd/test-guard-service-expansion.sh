#!/bin/bash
# Verify packaged systemd units and exercise their privileged integration paths.
set -euo pipefail

script_source="${BASH_SOURCE[0]}"
case "$script_source" in
  */*) script_parent="${script_source%/*}" ;;
  *) script_parent=. ;;
esac
script_dir="$(cd -- "$script_parent" && pwd -P)"
unit_sources=(
  "$script_dir/guard.service"
  "$script_dir/guard-exec-as-caller.service"
)

static_required_commands=(basename grep mktemp rm sed systemd-analyze)
full_required_commands=(
  basename chmod cut env getent grep groupadd groupdel id install mktemp od paste ps
  rm runuser sed seq sh sleep sort stat systemctl systemd-analyze timeout tr true useradd
  userdel usermod
)

validated_guard_binary=""
created_units=()
created_paths=()
created_users=()
created_groups=()
identity_daemon_pid=""
identity_test_dir=""

current_uid() {
  printf '%s\n' "$EUID"
}

pid_one_command() {
  ps -p 1 -o comm= | tr -d '[:space:]'
}

find_guard_binary() {
  local candidate
  for candidate in \
    "$script_dir/../../guard" \
    "$script_dir/../../target/debug/guard" \
    "$script_dir/../../target/release/guard"; do
    if [ -f "$candidate" ] && [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

check_required_commands() {
  local purpose="$1"
  shift
  local required_command
  for required_command in "$@"; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
      printf '%s requires command %q; install it before running this mode.\n' \
        "$purpose" "$required_command" >&2
      return 1
    fi
  done
}

verify_unit_files() (
  local unit_source verification_dir verification_unit
  local verification_units=()

  for unit_source in "${unit_sources[@]}"; do
    if grep -Eqi '^[[:space:]]*PrivateTmp[[:space:]]*=[[:space:]]*(true|yes|on|1)[[:space:]]*$' "$unit_source"; then
      grep -Eni '^[[:space:]]*PrivateTmp[[:space:]]*=[[:space:]]*(true|yes|on|1)[[:space:]]*$' "$unit_source" >&2
      echo "$unit_source must share the host /tmp namespace with brokered children" >&2
      return 1
    fi
  done

  if ! grep -Fxq 'AmbientCapabilities=CAP_SETUID CAP_SETGID' "$script_dir/guard.service"; then
    echo 'the fixed-identity unit must retain only the identity-switch capabilities' >&2
    return 1
  fi
  if ! grep -Fxq 'SupplementaryGroups=guard-clients guard-exec' "$script_dir/guard.service"; then
    echo 'the fixed-identity unit must retain its client and execution groups' >&2
    return 1
  fi
  if grep -Eq '^AmbientCapabilities=.*CAP_(CHOWN|FOWNER|DAC_READ_SEARCH)' "$script_dir/guard.service"; then
    echo 'the fixed-identity unit carries filesystem capabilities it does not need' >&2
    return 1
  fi

  if ! verification_dir="$(mktemp -d)"; then
    echo 'could not create a temporary directory for systemd unit verification' >&2
    return 1
  fi
  trap 'rm -r -- "$verification_dir"' EXIT
  for unit_source in "${unit_sources[@]}"; do
    verification_unit="$verification_dir/$(basename "$unit_source")"
    if ! sed 's|^ExecStart=/usr/local/bin/guard |ExecStart=/bin/true |' \
      "$unit_source" > "$verification_unit"; then
      echo "could not prepare $unit_source for systemd verification" >&2
      return 1
    fi
    verification_units+=("$verification_unit")
  done
  if ! systemd-analyze verify "${verification_units[@]}"; then
    echo 'systemd unit verification failed' >&2
    return 1
  fi
)

validate_full_prerequisites() {
  if [ "$(current_uid)" -ne 0 ]; then
    echo 'full systemd integration requires root; run with sudo or use --verify-only for unit verification' >&2
    return 1
  fi

  if ! check_required_commands 'full systemd integration' "${full_required_commands[@]}"; then
    return 1
  fi

  if [ "$(pid_one_command)" != systemd ]; then
    echo 'full systemd integration requires systemd as PID 1; use --verify-only for unit verification' >&2
    return 1
  fi

  if ! validated_guard_binary="$(find_guard_binary)"; then
    echo 'full systemd integration requires an executable Guard binary in the package root or Cargo target directory; build Guard first or use --verify-only for unit verification' >&2
    return 1
  fi
}

stop_identity_daemon() {
  if [ -n "$identity_daemon_pid" ]; then
    kill "$identity_daemon_pid" >/dev/null 2>&1 || true
    wait "$identity_daemon_pid" >/dev/null 2>&1 || true
    identity_daemon_pid=""
  fi
}

cleanup() {
  local index
  stop_identity_daemon
  for unit_name in "${created_units[@]}"; do
    systemctl stop "$unit_name" >/dev/null 2>&1 || true
  done
  if [ "${#created_paths[@]}" -gt 0 ]; then
    rm -f "${created_paths[@]}"
  fi
  for ((index = ${#created_users[@]} - 1; index >= 0; index--)); do
    userdel "${created_users[$index]}" >/dev/null 2>&1 || true
  done
  for ((index = ${#created_groups[@]} - 1; index >= 0; index--)); do
    groupdel "${created_groups[$index]}" >/dev/null 2>&1 || true
  done
  if [ -n "$identity_test_dir" ] && [ -d "$identity_test_dir" ]; then
    rm -r -- "$identity_test_dir"
  fi
  systemctl daemon-reload >/dev/null 2>&1 || true
}
trap cleanup EXIT

run_expansion_test() {
  local unit_source="$1"
  local label="$2"
  local test_id="guard-expansion-${label}-$$"
  local unit_name="$test_id.service"
  local unit_path="/run/systemd/system/$unit_name"
  local capture="/usr/local/libexec/$test_id-capture"
  # Use the host /tmp namespace: a private service tmp namespace would let the
  # child write successfully while hiding the file from this caller.
  local output="/tmp/$test_id-output"
  local environment="/run/$test_id-environment"
  local generated
  generated="$(mktemp)"
  created_units+=("$unit_name")
  created_paths+=("$unit_path" "$capture" "$output" "$environment" "$generated")

  sed \
    -e "s|^Description=.*|Description=Guard ExecStart expansion regression|" \
    -e '/^After=/d' \
    -e '/^Wants=/d' \
    -e 's|^User=guard$|User=root|' \
    -e 's|^Group=.*$|Group=root|' \
    -e '/^SupplementaryGroups=/d' \
    -e 's|^WorkingDirectory=.*|WorkingDirectory=/|' \
    -e "s|^EnvironmentFile=.*|EnvironmentFile=$environment|" \
    -e '/^StateDirectory=/d' \
    -e '/^StateDirectoryMode=/d' \
    -e '/^RuntimeDirectory=/d' \
    -e '/^RuntimeDirectoryMode=/d' \
    -e '/^StandardInput=/d' \
    -e '/^ExecStartPre=/d' \
    -e "s|^ExecStart=/usr/local/bin/guard |ExecStart=$capture |" \
    -e 's|^Restart=.*|Restart=no|' \
    -e '/^AmbientCapabilities=/d' \
    -e "s|^ReadWritePaths=.*|ReadWritePaths=$output|" \
    -e '/^\[Install\]/,$d' \
    "$unit_source" > "$generated"

  install -o root -g root -m 0644 "$generated" "$unit_path"
  install -d -o root -g root -m 0755 /usr/local/libexec
  install -o root -g root -m 0600 /dev/null "$output"
  printf '%s\n' 'GUARD_ALLOWED_UIDS=1001,1002' > "$environment"
  printf '%s\n' '#!/bin/sh' "printf '%s\\n' \"\$@\" > '$output'" > "$capture"
  chmod 0700 "$capture"
  systemctl daemon-reload
  systemctl start "$unit_name"
  systemctl is-failed --quiet "$unit_name" && {
    systemctl status "$unit_name" --no-pager >&2
    return 1
  }
  for _ in $(seq 1 50); do
    test -s "$output" && break
    sleep 0.1
  done
  test -s "$output" || {
    systemctl status "$unit_name" --no-pager >&2
    return 1
  }

  mapfile -t arguments < "$output"
  local users_index=-1
  local index
  for index in "${!arguments[@]}"; do
    if [ "${arguments[$index]}" = "--users" ]; then
      users_index=$index
      break
    fi
  done
  test "$users_index" -ge 0
  test "${arguments[$((users_index + 1))]}" = "1001,1002"
  test "${arguments[$((users_index + 2))]:-}" != "1002"
  case "$label" in
    standard)
      local exec_user_index=-1
      for index in "${!arguments[@]}"; do
        if [ "${arguments[$index]}" = "--exec-user" ]; then
          exec_user_index=$index
          break
        fi
      done
      if [ "$exec_user_index" -lt 0 ] ||
        [ "${arguments[$((exec_user_index + 1))]:-}" != guard-exec ]; then
        echo 'fixed-identity unit did not expand --exec-user guard-exec' >&2
        return 1
      fi
      ;;
    exec-as-caller)
      local exec_as_caller_count=0
      for index in "${!arguments[@]}"; do
        if [ "${arguments[$index]}" = "--exec-as-caller" ]; then
          exec_as_caller_count=$((exec_as_caller_count + 1))
        fi
      done
      if [ "$exec_as_caller_count" -ne 1 ]; then
        echo 'caller-identity unit did not expand exactly one --exec-as-caller flag' >&2
        return 1
      fi
      ;;
    *)
      echo "unknown systemd expansion test label: $label" >&2
      return 1
      ;;
  esac
}

normalize_group_list() {
  printf '%s\n' "$1" | tr ' ,' '\n' | sed '/^$/d' | sort -n | paste -sd, -
}

assert_child_identity() {
  local label="$1"
  local account="$2"
  local supplementary_group="$3"
  local output="$4"
  local actual_uid actual_gid actual_groups expected_uid expected_gid expected_groups supplementary_gid

  actual_uid="$(printf '%s\n' "$output" | sed -n 's/^euid=//p')"
  actual_gid="$(printf '%s\n' "$output" | sed -n 's/^egid=//p')"
  actual_groups="$(normalize_group_list "$(printf '%s\n' "$output" | sed -n 's/^groups=//p')")"
  expected_uid="$(id -u "$account")"
  expected_gid="$(id -g "$account")"
  expected_groups="$(normalize_group_list "$(id -G "$account")")"
  supplementary_gid="$(getent group "$supplementary_group" | cut -d: -f3)"

  if [ "$actual_uid" != "$expected_uid" ] || [ "$actual_gid" != "$expected_gid" ] ||
    [ "$actual_groups" != "$expected_groups" ]; then
    printf 'FAIL: %s child identity: expected euid=%s egid=%s groups=%s, got:\n%s\n' \
      "$label" "$expected_uid" "$expected_gid" "$expected_groups" "$output" >&2
    return 1
  fi
  case ",$actual_groups," in
    *",$supplementary_gid,"*) ;;
    *)
      echo "FAIL: $label child identity omitted supplementary group $supplementary_gid" >&2
      return 1
      ;;
  esac
  printf 'PASS: %s child identity euid=%s egid=%s groups=%s\n' \
    "$label" "$actual_uid" "$actual_gid" "$actual_groups"
}

run_identity_switch_integration() {
  local guard_binary="$1"

  identity_test_dir="$(mktemp -d /run/guard-identity-switch.XXXXXX)"
  chmod 0755 "$identity_test_dir"
  local installed_guard="/usr/local/libexec/guard-identity-switch-$$"
  install -d -o root -g root -m 0755 /usr/local/libexec
  install -o root -g root -m 0755 "$guard_binary" "$installed_guard"
  created_paths+=("$installed_guard")
  guard_binary="$installed_guard"

  local unconfigured_output="$identity_test_dir/unconfigured.out"
  local unconfigured_status=0
  timeout 5s env -i HOME="$identity_test_dir" PATH=/usr/local/bin:/usr/bin:/bin \
    "$guard_binary" server start \
    --no-llm \
    --socket "$identity_test_dir/unconfigured.sock" \
    --state-db "$identity_test_dir/unconfigured.db" \
    > "$unconfigured_output" 2>&1 || unconfigured_status=$?
  if [ "$unconfigured_status" -eq 0 ] || [ "$unconfigured_status" -eq 124 ] ||
    ! grep -Fq 'requires exactly one identity mode' "$unconfigured_output"; then
    echo 'Guard accepted an unconfigured Unix execution identity' >&2
    sed -n '1,120p' "$unconfigured_output" >&2
    return 1
  fi
  echo 'PASS: startup rejected an unconfigured Unix execution identity'

  local suffix fixed_user caller_user
  local fixed_primary_group fixed_supplementary_group caller_primary_group
  local caller_supplementary_group caller_changed_group caller_socket_group account_shell
  suffix="$(printf '%x%x' "$$" "$RANDOM")"
  fixed_user="grdf$suffix"
  caller_user="grdc$suffix"
  fixed_primary_group="grdfp$suffix"
  fixed_supplementary_group="grdfs$suffix"
  caller_primary_group="grdcp$suffix"
  caller_supplementary_group="grdcs$suffix"
  caller_changed_group="grdcx$suffix"
  caller_socket_group="grdct$suffix"
  account_shell=/usr/sbin/nologin
  [ -x "$account_shell" ] || account_shell=/bin/false

  local group_name
  for group_name in \
    "$fixed_primary_group" \
    "$fixed_supplementary_group" \
    "$caller_primary_group" \
    "$caller_supplementary_group" \
    "$caller_changed_group" \
    "$caller_socket_group"; do
    groupadd "$group_name"
    created_groups+=("$group_name")
  done

  local fixed_home="$identity_test_dir/fixed-home"
  local caller_home="$identity_test_dir/caller-home"
  local daemon_home="$identity_test_dir/daemon-home"
  local operator_home="$identity_test_dir/operator-home"
  useradd -M -d "$fixed_home" -s "$account_shell" -g "$fixed_primary_group" \
    -G "$fixed_supplementary_group" "$fixed_user"
  created_users+=("$fixed_user")
  useradd -M -d "$caller_home" -s "$account_shell" -g "$caller_primary_group" \
    -G "$caller_supplementary_group,$caller_socket_group" "$caller_user"
  created_users+=("$caller_user")
  install -d -o "$fixed_user" -g "$fixed_primary_group" -m 0700 "$fixed_home"
  install -d -o "$caller_user" -g "$caller_primary_group" -m 0700 "$caller_home"
  install -d -o root -g root -m 0700 "$daemon_home" "$operator_home"

  local verb_catalog="$identity_test_dir/verbs.yaml"
  local admin_token_file="$identity_test_dir/admin.token"
  printf '%s\n' \
    'platform: unix' \
    'verbs:' \
    '  - name: identity-uid' \
    '    description: Report the brokered child process user ID' \
    '    binary: id' \
    '    args: ["-u"]' \
    '    consequence: reversible' \
    '    trusted: true' \
    '  - name: identity-gid' \
    '    description: Report the brokered child process primary group ID' \
    '    binary: id' \
    '    args: ["-g"]' \
    '    consequence: reversible' \
    '    trusted: true' \
    '  - name: identity-groups' \
    '    description: Report the brokered child process group IDs' \
    '    binary: id' \
    '    args: ["-G"]' \
    '    consequence: reversible' \
    '    trusted: true' \
    '  - name: identity-held' \
    '    description: Exercise held execution across caller group changes' \
    '    binary: true' \
    '    consequence: irreversible' \
    '    trusted: true' > "$verb_catalog"
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "$admin_token_file"
  printf '\n' >> "$admin_token_file"
  chmod 0400 "$admin_token_file"

  local caller_uid
  caller_uid="$(id -u "$caller_user")"
  local identity_socket=""
  local daemon_log=""

  start_identity_daemon() {
    local mode="$1"
    local mode_directory="$identity_test_dir/$mode"
    local state_directory="$identity_test_dir/$mode-state"
    local mode_args=()
    stop_identity_daemon
    install -d -o root -g root -m 0755 "$mode_directory"
    install -d -o root -g root -m 0700 "$state_directory"
    identity_socket="$mode_directory/guard.sock"
    daemon_log="$mode_directory/daemon.log"
    if [ "$mode" = fixed-user ]; then
      mode_args=(--exec-user "$fixed_user")
    else
      mode_args=(--exec-as-caller)
    fi
    (
      cd "$daemon_home"
      exec env -i HOME="$daemon_home" PATH=/usr/local/bin:/usr/bin:/bin \
        "$guard_binary" server start \
        --no-llm \
        --gate consequence \
        --socket "$identity_socket" \
        --socket-group "$caller_socket_group" \
        --state-db "$state_directory/state.db" \
        --verbs "$verb_catalog" \
        --users "$caller_uid" \
        --admin-token-stdin \
        "${mode_args[@]}"
    ) < "$admin_token_file" > "$daemon_log" 2>&1 &
    identity_daemon_pid=$!

    local attempt
    for ((attempt = 0; attempt < 100; attempt++)); do
      if [ -S "$identity_socket" ]; then
        return 0
      fi
      if ! kill -0 "$identity_daemon_pid" >/dev/null 2>&1; then
        echo "Guard $mode identity test daemon exited before creating its socket" >&2
        sed -n '1,160p' "$daemon_log" >&2
        return 1
      fi
      sleep 0.1
    done
    echo "Guard $mode identity test daemon did not create its socket" >&2
    sed -n '1,160p' "$daemon_log" >&2
    return 1
  }

  run_guard_as_caller() {
    (
      # This test exercises identity propagation, so keep the working directory
      # outside the caller's mutable authority rather than testing profile input.
      cd /
      runuser -u "$caller_user" -- env -i \
        HOME="$caller_home" USER="$caller_user" LOGNAME="$caller_user" \
        PATH=/usr/local/bin:/usr/bin:/bin \
        "$guard_binary" "$@"
    )
  }

  collect_child_identity() {
    local effective_uid effective_gid groups
    effective_uid="$(run_guard_as_caller verb run identity-uid --socket "$identity_socket")" || return
    effective_gid="$(run_guard_as_caller verb run identity-gid --socket "$identity_socket")" || return
    groups="$(run_guard_as_caller verb run identity-groups --socket "$identity_socket")" || return
    if ! [[ "$effective_uid" =~ ^[0-9]+$ && "$effective_gid" =~ ^[0-9]+$ &&
      "$groups" =~ ^[0-9]+([[:space:]][0-9]+)*$ ]]; then
      printf 'could not parse brokered child identity: uid=%q gid=%q groups=%q\n' \
        "$effective_uid" "$effective_gid" "$groups" >&2
      return 1
    fi
    printf 'euid=%s\negid=%s\ngroups=%s\n' "$effective_uid" "$effective_gid" "$groups"
  }

  local identity_output
  start_identity_daemon fixed-user
  identity_output="$(collect_child_identity)"
  assert_child_identity fixed-user "$fixed_user" "$fixed_supplementary_group" "$identity_output"
  stop_identity_daemon

  start_identity_daemon exec-as-caller
  identity_output="$(collect_child_identity)"
  assert_child_identity exec-as-caller "$caller_user" "$caller_supplementary_group" "$identity_output"

  local held_output="$identity_test_dir/held-request.out"
  local held_status=0
  run_guard_as_caller verb run identity-held --socket "$identity_socket" > "$held_output" 2>&1 || held_status=$?
  if [ "$held_status" -ne 127 ]; then
    echo "held identity command returned $held_status instead of Guard's held status" >&2
    sed -n '1,160p' "$held_output" >&2
    return 1
  fi
  local held_handles=()
  mapfile -t held_handles < <(sed -n -E 's/.*handle:[[:space:]]*([[:alnum:]-]+).*/\1/p' "$held_output")
  if [ "${#held_handles[@]}" -lt 1 ]; then
    echo 'held identity command did not report an approval handle' >&2
    sed -n '1,160p' "$held_output" >&2
    return 1
  fi
  local held_handle="${held_handles[0]}"

  usermod -G "$caller_changed_group,$caller_socket_group" "$caller_user"
  if ! runuser -u "$caller_user" -- test -w "$identity_socket"; then
    echo 'changed caller identity lost write access to the stable test transport' >&2
    id "$caller_user" >&2
    runuser -u "$caller_user" -- id >&2
    stat -c 'socket mode=%a owner=%U:%u group=%G:%g' "$identity_socket" >&2
    return 1
  fi
  env -i HOME="$operator_home" PATH=/usr/local/bin:/usr/bin:/bin \
    GUARD_ADMIN_TOKEN_FILE="$admin_token_file" \
    "$guard_binary" access approve "$held_handle" --once --yes --socket "$identity_socket" \
    > "$identity_test_dir/held-approval.out"

  local resume_output="$identity_test_dir/held-resume.out"
  local resume_status=0
  run_guard_as_caller approval resume "$held_handle" --socket "$identity_socket" \
    > "$resume_output" 2>&1 || resume_status=$?
  if [ "$resume_status" -eq 0 ] ||
    ! grep -Fq 'approved process authority changed before process start' "$resume_output"; then
    echo 'held execution did not reject changed caller group authority before process start' >&2
    sed -n '1,160p' "$resume_output" >&2
    return 1
  fi
  echo 'PASS: held execution rejected changed caller group authority before resume'

  identity_output="$(collect_child_identity)"
  assert_child_identity exec-as-caller-updated "$caller_user" "$caller_changed_group" "$identity_output"
  stop_identity_daemon
}

run_privileged_integration() {
  created_units=()
  created_paths=()
  created_users=()
  created_groups=()
  identity_daemon_pid=""
  identity_test_dir=""
  trap cleanup EXIT

  run_expansion_test "${unit_sources[0]}" standard
  run_expansion_test "${unit_sources[1]}" exec-as-caller
  run_identity_switch_integration "$validated_guard_binary"
}

run_verify_only_mode() {
  if ! check_required_commands 'systemd unit verification' "${static_required_commands[@]}"; then
    return 1
  fi
  if ! verify_unit_files; then
    return 1
  fi
}

run_full_mode() {
  if ! validate_full_prerequisites; then
    return 1
  fi
  if ! verify_unit_files; then
    return 1
  fi
  run_privileged_integration
}

run_contract_self_tests() (
  if ! check_required_commands 'systemd integration contract self-test' grep mktemp rm; then
    return 1
  fi

  local test_directory marker output_file error_file
  test_directory="$(mktemp -d)"
  trap 'rm -r -- "$test_directory"' EXIT
  marker="$test_directory/mutation"
  output_file="$test_directory/output"
  error_file="$test_directory/error"

  # These test-only overrides are invoked indirectly through dispatch_mode.
  # shellcheck disable=SC2317
  if (
    current_uid() { printf '%s\n' 1000; }
    verify_unit_files() { : > "$marker"; }
    run_privileged_integration() { : > "$marker"; }
    dispatch_mode
  ) > "$output_file" 2> "$error_file"; then
    echo 'default invocation unexpectedly succeeded without root' >&2
    return 1
  fi
  grep -Fq 'full systemd integration requires root' "$error_file"
  if [ -e "$marker" ]; then
    echo 'default invocation mutated state before rejecting a non-root caller' >&2
    return 1
  fi

  # These test-only overrides are invoked indirectly through dispatch_mode.
  # shellcheck disable=SC2317
  if (
    current_uid() { printf '%s\n' 0; }
    check_required_commands() { return 0; }
    pid_one_command() { printf '%s\n' systemd; }
    find_guard_binary() { return 1; }
    verify_unit_files() { : > "$marker"; }
    run_privileged_integration() { : > "$marker"; }
    dispatch_mode
  ) > "$output_file" 2> "$error_file"; then
    echo 'default invocation unexpectedly succeeded without a Guard binary' >&2
    return 1
  fi
  grep -Fq 'full systemd integration requires an executable Guard binary' "$error_file"
  if [ -e "$marker" ]; then
    echo 'default invocation mutated state before rejecting a missing Guard binary' >&2
    return 1
  fi

  (
    check_required_commands() { printf '%s\n' prerequisites >> "$marker"; }
    verify_unit_files() { printf '%s\n' verification >> "$marker"; }
    run_verify_only_mode
  )
  if [ "$(< "$marker")" != $'prerequisites\nverification' ]; then
    echo '--verify-only did not complete prerequisite and unit checks in order' >&2
    return 1
  fi

  if (
    check_required_commands() { return 0; }
    verify_unit_files() { return 1; }
    run_verify_only_mode
  ); then
    echo '--verify-only unexpectedly succeeded after a failed unit check' >&2
    return 1
  fi

  echo 'PASS: systemd integration invocation contracts'
)

usage() {
  echo 'usage: test-guard-service-expansion.sh [--verify-only|--self-test]' >&2
}

dispatch_mode() {
  if [ "$#" -eq 0 ]; then
    run_full_mode
    return
  fi
  if [ "$#" -ne 1 ]; then
    usage
    return 2
  fi
  case "$1" in
    --verify-only) run_verify_only_mode ;;
    --self-test) run_contract_self_tests ;;
    *)
      usage
      return 2
      ;;
  esac
}

dispatch_mode "$@"
