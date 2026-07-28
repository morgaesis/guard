#!/bin/bash
# Exercise the packaged ExecStart lines with systemd's own environment expansion.
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
unit_sources=(
  "$script_dir/guard.service"
  "$script_dir/guard-exec-as-caller.service"
)

verification_dir="$(mktemp -d)"
cleanup_verification() {
  if [ -n "$verification_dir" ] && [ -d "$verification_dir" ]; then
    rm -r -- "$verification_dir"
  fi
}
trap cleanup_verification EXIT
verification_units=()
for unit_source in "${unit_sources[@]}"; do
  verification_unit="$verification_dir/$(basename "$unit_source")"
  sed 's|^ExecStart=/usr/local/bin/guard |ExecStart=/bin/true |' \
    "$unit_source" > "$verification_unit"
  verification_units+=("$verification_unit")
done
systemd-analyze verify "${verification_units[@]}"
cleanup_verification
verification_dir=""
trap - EXIT

if [ "${1:-}" = "--verify-only" ]; then
  exit 0
fi

test "$(id -u)" -eq 0 || {
  echo "actual systemd expansion test requires root" >&2
  exit 1
}
test "$(ps -p 1 -o comm=)" = systemd || {
  echo "actual systemd expansion test requires systemd as PID 1" >&2
  exit 1
}

created_units=()
created_paths=()
cleanup() {
  for unit_name in "${created_units[@]}"; do
    systemctl stop "$unit_name" >/dev/null 2>&1 || true
  done
  if [ "${#created_paths[@]}" -gt 0 ]; then
    rm -f "${created_paths[@]}"
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
  local output="/run/$test_id-output"
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
    -e 's|^Group=guard$|Group=root|' \
    -e '/^SupplementaryGroups=/d' \
    -e 's|^WorkingDirectory=.*|WorkingDirectory=/|' \
    -e "s|^EnvironmentFile=.*|EnvironmentFile=$environment|" \
    -e '/^StateDirectory=/d' \
    -e '/^StateDirectoryMode=/d' \
    -e '/^RuntimeDirectory=/d' \
    -e '/^RuntimeDirectoryMode=/d' \
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
}

run_expansion_test "${unit_sources[0]}" standard
run_expansion_test "${unit_sources[1]}" exec-as-caller
