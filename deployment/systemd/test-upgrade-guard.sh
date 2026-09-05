#!/usr/bin/env bash
# Exercise every deployment replacement boundary in an isolated root.
set -Eeuo pipefail
IFS=$'\n\t'

script_directory="$(cd "$(dirname "$0")" && pwd)"
upgrade_script="$script_directory/upgrade-guard"
test_directory="$(mktemp -d)"
root_directory="$test_directory/root"
release_source="$test_directory/release-source"
release_directory="$release_source/guard-test-x86_64-unknown-linux-gnu"
release_archive="$test_directory/guard-test-x86_64-unknown-linux-gnu.tar.gz"
mock_directory="$test_directory/mock"
mock_state="$test_directory/systemctl-state"
mock_enabled_state="$test_directory/systemctl-enabled-state"
mock_start_log="$test_directory/systemctl-start.log"
mock_sync_log="$test_directory/sync.log"
state_db_setting="/srv/guard-state/guard.sqlite"
state_db="$root_directory$state_db_setting"
authority_key="$(dirname "$state_db")/authority.hmac"
socket_setting="/srv/guard-run/guard.sock"
api_directory="$(dirname "$state_db")/api-proxy-reverts"
decoy_state_db="$root_directory/var/lib/guard/state.db"
decoy_authority_key="$root_directory/var/lib/guard/authority.hmac"
decoy_api_directory="$root_directory/var/lib/guard/api-proxy-reverts"
default_exec_start="{ path=/usr/local/bin/guard ; argv[]=/usr/local/bin/guard server start --socket $socket_setting --state-db $state_db_setting --users 1000 ; ignore_errors=no ; }"

cleanup() {
  local status=$?
  rm -r -- "$test_directory"
  exit "$status"
}
trap cleanup EXIT

mkdir -p \
  "$root_directory/usr/local/bin" \
  "$root_directory/usr/local/sbin" \
  "$root_directory/etc/systemd/system" \
  "$root_directory/etc/guard" \
  "$api_directory" \
  "$decoy_api_directory" \
  "$(dirname "$state_db")" \
  "$root_directory/var/lib/guard-exec/.ssh" \
  "$root_directory/var/backups" \
  "$release_source" \
  "$release_directory/deployment/systemd" \
  "$mock_directory"
chmod 0700 "$root_directory/var/lib/guard-exec" "$root_directory/var/lib/guard-exec/.ssh"
chmod 0755 "$root_directory/var/backups"
head -c 32 /dev/urandom | sha256sum | cut -d ' ' -f 1 > "$root_directory/etc/guard/admin.token"
chmod 0400 "$root_directory/etc/guard/admin.token"

cd "$test_directory"

make_guard() {
  local destination="$1"
  local label="$2"
  printf '%s\n' '#!/usr/bin/env sh' > "$destination"
  if [[ "$label" == release ]]; then
    printf '%s\n' "if [ \"\$1\" = status ] && [ \"\${GUARD_UPGRADE_TEST_STATUS_FAIL:-}\" = 1 ]; then exit 1; fi" >> "$destination"
  fi
  # shellcheck disable=SC2016
  printf '%s\n' \
    'if [ "$1" = state-db ] && [ "$2" = check ]; then' \
    '  if [ "${GUARD_UPGRADE_TEST_CANDIDATE_MALFORMED:-}" = 1 ]; then printf "%s\\n" not-json; exit 0; fi' \
    '  if [ "${GUARD_UPGRADE_TEST_EXPECT_LIVE_WAL:-}" = 1 ] && [ ! -e "$4-wal" ]; then exit 3; fi' \
    "  if [ \"\${GUARD_UPGRADE_TEST_CANDIDATE_INCOMPATIBLE:-}\" = 1 ]; then printf '%s\\n' '{\"type\":\"state_db_compatibility\",\"compatible\":false,\"simulated_open\":true,\"simulated_startup\":{\"succeeded\":false}}'; exit 0; fi" \
    "  printf '%s\\n' '{\"type\":\"state_db_compatibility\",\"compatible\":true,\"simulated_open\":true,\"simulated_startup\":{\"succeeded\":true}}'" \
    '  exit 0' \
    'fi' \
    'if [ "$1" = status ] && [ -n "${GUARD_UPGRADE_TEST_EXPECTED_SOCKET:-}" ]; then' \
    "  case \" \$* \" in *\" status --socket \${GUARD_UPGRADE_TEST_EXPECTED_SOCKET} --json \"*) ;; *) exit 2 ;; esac" \
    '  [ "${GUARD_ADMIN_TOKEN_FILE:-}" = "${GUARD_UPGRADE_TEST_EXPECTED_ADMIN_TOKEN_FILE:?}" ] || exit 4' \
    'fi' >> "$destination"
  printf '%s\n' \
    "status_state_database=\"\${GUARD_UPGRADE_TEST_STATUS_STATE_DB:?}\"" \
    "status_socket=\"\${GUARD_UPGRADE_TEST_STATUS_SOCKET:?}\"" \
    "if [ -n \"\${GUARD_UPGRADE_TEST_STATUS_STATE_DB_ONCE:-}\" ] && [ ! -e \"\${GUARD_UPGRADE_TEST_STATUS_STATE_DB_ONCE_MARKER:?}\" ]; then" \
    "  : > \"\${GUARD_UPGRADE_TEST_STATUS_STATE_DB_ONCE_MARKER}\"" \
    "  status_state_database=\"\$GUARD_UPGRADE_TEST_STATUS_STATE_DB_ONCE\"" \
    'fi' \
    "if [ -n \"\${GUARD_UPGRADE_TEST_STATUS_SOCKET_ONCE:-}\" ] && [ ! -e \"\${GUARD_UPGRADE_TEST_STATUS_SOCKET_ONCE_MARKER:?}\" ]; then" \
    "  : > \"\${GUARD_UPGRADE_TEST_STATUS_SOCKET_ONCE_MARKER}\"" \
    "  status_socket=\"\$GUARD_UPGRADE_TEST_STATUS_SOCKET_ONCE\"" \
    'fi' \
    "printf '{\"status\":\"$label\",\"server\":{\"reachable\":true,\"full\":{\"state_db_path\":\"%s\",\"socket_path\":\"%s\"}}}\\n' \"\$status_state_database\" \"\$status_socket\"" >> "$destination"
  chmod 0755 "$destination"
  sh -n "$destination"
}

make_guard "$root_directory/usr/local/bin/guard" original
printf '%s\n' original-operator > "$root_directory/usr/local/sbin/guard-operator"
printf '%s\n' original-unit > "$root_directory/etc/systemd/system/guard.service"
printf '%s\n' original-caller-unit > "$root_directory/etc/systemd/system/guard-exec-as-caller.service"
printf '%s\n' original-config > "$root_directory/etc/guard/config.yaml"
printf '%s\n' original-api > "$api_directory/body.json"
printf '%s\n' untouched-api > "$decoy_api_directory/body.json"
sqlite3 "$state_db" 'create table state(value text); insert into state values("original");'
sqlite3 "$decoy_state_db" 'create table state(value text); insert into state values("untouched");'
printf '%s\n' original-authority > "$authority_key"
printf '%s\n' untouched-authority > "$decoy_authority_key"

make_guard "$release_directory/guard" release
printf '%s\n' release-operator > "$release_directory/deployment/systemd/guard-operator"
printf '%s\n' release-unit > "$release_directory/deployment/systemd/guard.service"
printf '%s\n' release-caller-unit > "$release_directory/deployment/systemd/guard-exec-as-caller.service"
cp "$upgrade_script" "$release_directory/deployment/systemd/upgrade-guard"
(cd "$release_directory" && sha256sum guard > BINARY-SHA256)
(
  cd "$release_directory"
  sha256sum \
    guard \
    deployment/systemd/guard-operator \
    deployment/systemd/guard.service \
    deployment/systemd/guard-exec-as-caller.service \
    deployment/systemd/upgrade-guard \
    > INSTALL-SHA256
)
tar -C "$release_source" -czf "$release_archive" "$(basename "$release_directory")"
release_sha256="$(sha256sum "$release_archive" | cut -d ' ' -f 1)"

make_hostile_archive() {
  local kind="$1"
  local archive="$test_directory/hostile-$kind.tar.gz"
  local release_name
  release_name="$(basename "$release_directory")"
  case "$kind" in
    absolute)
      tar --absolute-names -C "$release_source" \
        --transform="s|^$release_name|/hostile-release|" \
        -czf "$archive" "$release_name"
      ;;
    dotdot)
      tar -C "$release_source" \
        --transform="s|^$release_name|../hostile-release|" \
        -czf "$archive" "$release_name"
      ;;
    link)
      mkdir -p "$test_directory/hostile-link/$release_name"
      ln -s destination "$test_directory/hostile-link/$release_name/redirect"
      tar -C "$test_directory/hostile-link" -czf "$archive" "$release_name"
      ;;
    device)
      tar -C / -czf "$archive" dev/null
      ;;
    layout)
      printf '%s\n' orphan > "$test_directory/orphan"
      tar -C "$test_directory" -czf "$archive" orphan
      ;;
    *)
      echo "unknown hostile archive kind: $kind" >&2
      exit 1
      ;;
  esac
  printf '%s\n' "$archive"
}

cat > "$mock_directory/systemctl" <<'MOCK'
#!/usr/bin/env bash
set -Eeuo pipefail
state_file="${GUARD_UPGRADE_TEST_SYSTEMCTL_STATE:?}"
enabled_state_file="${GUARD_UPGRADE_TEST_SYSTEMCTL_ENABLED_STATE:?}"
state="$(<"$state_file")"
case "$1" in
  is-active)
    case "$2" in
      guard.service)
        if [[ "$state" == inactive && "${GUARD_UPGRADE_TEST_POST_STOP_STATUS_FAIL:-}" == 1 && \
          ! -e "$state_file.post-stop-status-failed" ]]; then
          : > "$state_file.post-stop-status-failed"
          exit 1
        fi
        printf '%s\n' "$state"
        ;;
      guard-exec-as-caller.service) printf '%s\n' inactive ;;
      *) exit 1 ;;
    esac
    ;;
  stop)
    if [[ "${GUARD_UPGRADE_TEST_STOP_FAIL_TO_FAILED:-}" == 1 ]]; then
      printf '%s\n' failed > "$state_file"
      exit 1
    fi
    [[ "${GUARD_UPGRADE_TEST_STOP_FAIL:-}" != 1 ]] || exit 1
    printf '%s\n' inactive > "$state_file"
    ;;
  start)
    printf '%s\n' start >> "${GUARD_UPGRADE_TEST_SYSTEMCTL_START_LOG:?}"
    printf '%s\n' active > "$state_file"
    ;;
  daemon-reload) : > "${state_file}.daemon-reloaded" ;;
  reset-failed) : ;;
  is-enabled) cat "$enabled_state_file" ;;
  enable)
    if [[ " $* " == *' --runtime '* ]]; then
      printf '%s\n' enabled-runtime > "$enabled_state_file"
    else
      printf '%s\n' enabled > "$enabled_state_file"
    fi
    ;;
  disable) printf '%s\n' disabled > "$enabled_state_file" ;;
  mask)
    if [[ " $* " == *' --runtime '* ]]; then
      printf '%s\n' masked-runtime > "$enabled_state_file"
    else
      printf '%s\n' masked > "$enabled_state_file"
    fi
    ;;
  unmask)
    case "$(<"$enabled_state_file")" in
      masked|masked-runtime) printf '%s\n' disabled > "$enabled_state_file" ;;
    esac
    ;;
  show)
    if [[ "$*" == *'ExecStart'* ]]; then
      exec_start="${GUARD_UPGRADE_TEST_EXEC_START:?}"
      if [[ -e "${state_file}.daemon-reloaded" && \
        -n "${GUARD_UPGRADE_TEST_EXEC_START_AFTER_RELOAD:-}" && \
        ! -e "${GUARD_UPGRADE_TEST_EXEC_START_AFTER_RELOAD_MARKER:?}" ]]; then
        : > "${GUARD_UPGRADE_TEST_EXEC_START_AFTER_RELOAD_MARKER}"
        exec_start="$GUARD_UPGRADE_TEST_EXEC_START_AFTER_RELOAD"
      fi
      printf '%s\n' "$exec_start"
    else
      printf '%s\n' 1
    fi
    ;;
  *) printf 'unexpected systemctl invocation: %s\n' "$*" >&2; exit 1 ;;
esac
MOCK
chmod 0755 "$mock_directory/systemctl"

cat > "$mock_directory/sync" <<'MOCK'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$#" == 3 && "$1" == -f && "$2" == -- ]] || {
  printf 'unexpected sync invocation: %s\n' "$*" >&2
  exit 1
}
printf '%s\n' "$3" >> "${GUARD_UPGRADE_TEST_SYNC_LOG:?}"
case "${GUARD_UPGRADE_TEST_SYNC_FAIL_AT:-}:$3" in
  backup:*/var/backups/guard/guard-*|backup-parent:*/var/backups/guard) exit 1 ;;
esac
MOCK
chmod 0755 "$mock_directory/sync"

printf '%s\n' active > "$mock_state"
printf '%s\n' enabled > "$mock_enabled_state"

"$upgrade_script" --help >/dev/null
if "$upgrade_script" >/dev/null 2>&1; then
  echo 'bare invocation unexpectedly mutated or succeeded' >&2
  exit 1
fi

run_upgrade() {
  env \
    GUARD_SOCKET="$test_directory/conflicting.sock" \
    GUARD_UPGRADE_TEST_EXPECTED_SOCKET="${GUARD_UPGRADE_TEST_EXPECTED_SOCKET:-$root_directory$socket_setting}" \
    GUARD_UPGRADE_TEST_EXPECTED_ADMIN_TOKEN_FILE="$root_directory/etc/guard/admin.token" \
    GUARD_UPGRADE_TEST_MODE=1 \
    GUARD_UPGRADE_TEST_EXEC_START="${GUARD_UPGRADE_TEST_EXEC_START:-$default_exec_start}" \
    GUARD_UPGRADE_TEST_EXEC_START_AFTER_RELOAD="${GUARD_UPGRADE_TEST_EXEC_START_AFTER_RELOAD:-}" \
    GUARD_UPGRADE_TEST_EXEC_START_AFTER_RELOAD_MARKER="${GUARD_UPGRADE_TEST_EXEC_START_AFTER_RELOAD_MARKER:-$test_directory/exec-start-after-reload}" \
    GUARD_UPGRADE_TEST_STATUS_STATE_DB="${GUARD_UPGRADE_TEST_STATUS_STATE_DB:-$state_db_setting}" \
    GUARD_UPGRADE_TEST_STATUS_STATE_DB_ONCE="${GUARD_UPGRADE_TEST_STATUS_STATE_DB_ONCE:-}" \
    GUARD_UPGRADE_TEST_STATUS_STATE_DB_ONCE_MARKER="${GUARD_UPGRADE_TEST_STATUS_STATE_DB_ONCE_MARKER:-$test_directory/status-state-db-once}" \
    GUARD_UPGRADE_TEST_STATUS_SOCKET="${GUARD_UPGRADE_TEST_STATUS_SOCKET:-$socket_setting}" \
    GUARD_UPGRADE_TEST_STATUS_SOCKET_ONCE="${GUARD_UPGRADE_TEST_STATUS_SOCKET_ONCE:-}" \
    GUARD_UPGRADE_TEST_STATUS_SOCKET_ONCE_MARKER="${GUARD_UPGRADE_TEST_STATUS_SOCKET_ONCE_MARKER:-$test_directory/status-socket-once}" \
    GUARD_UPGRADE_TEST_SYSTEMCTL_START_LOG="$mock_start_log" \
    GUARD_UPGRADE_TEST_SYSTEMCTL_ENABLED_STATE="$mock_enabled_state" \
    GUARD_UPGRADE_TEST_SYSTEMCTL_STATE="$mock_state" \
    GUARD_UPGRADE_TEST_SYNC_LOG="$mock_sync_log" \
    PATH="$mock_directory:$PATH" \
    "$upgrade_script" "$@" --root "$root_directory"
}

run_install() {
  run_upgrade install \
    --release-archive "$release_archive" \
    --expected-sha256 "$release_sha256" \
    "$@"
}

rewrite_backup_manifest() {
  local directory="$1"
  (
    cd "$directory"
    find . -type f ! -path ./SHA256SUMS -print0 |
      LC_ALL=C sort -z |
      xargs -0r sha256sum > SHA256SUMS
  )
}

run_install --dry-run

for candidate_failure in incompatible malformed; do
  case "$candidate_failure" in
    incompatible)
      if GUARD_UPGRADE_TEST_CANDIDATE_INCOMPATIBLE=1 run_install --dry-run; then
        echo 'dry-run candidate check unexpectedly accepted incompatible state' >&2
        exit 1
      fi
      ;;
    malformed)
      if GUARD_UPGRADE_TEST_CANDIDATE_MALFORMED=1 run_install --dry-run; then
        echo 'dry-run candidate check unexpectedly accepted malformed output' >&2
        exit 1
      fi
      ;;
  esac
  [[ "$(<"$mock_state")" == active ]]
  [[ ! -s "$mock_start_log" ]]
done

assert_original() {
  local expected_active="${1:-active}"
  local expected_enabled="${2:-enabled}"
  sh -n "$root_directory/usr/local/bin/guard"
  grep -Fq original "$root_directory/usr/local/bin/guard"
  grep -Fxq original-operator "$root_directory/usr/local/sbin/guard-operator"
  grep -Fxq original-unit "$root_directory/etc/systemd/system/guard.service"
  grep -Fxq original-caller-unit "$root_directory/etc/systemd/system/guard-exec-as-caller.service"
  [[ ! -e "$root_directory/usr/local/sbin/upgrade-guard" ]]
  grep -Fxq original-config "$root_directory/etc/guard/config.yaml"
  [[ "$(sqlite3 "$state_db" 'select value from state;')" == original ]]
  [[ "$(sqlite3 "$decoy_state_db" 'select value from state;')" == untouched ]]
  grep -Fxq original-authority "$authority_key"
  grep -Fxq untouched-authority "$decoy_authority_key"
  grep -Fxq original-api "$api_directory/body.json"
  grep -Fxq untouched-api "$decoy_api_directory/body.json"
  [[ "$(<"$mock_state")" == "$expected_active" ]]
  [[ "$(<"$mock_enabled_state")" == "$expected_enabled" ]]
}

assert_release() {
  local expected_active="${1:-active}"
  local expected_enabled="${2:-enabled}"
  sh -n "$root_directory/usr/local/bin/guard"
  grep -Fq release "$root_directory/usr/local/bin/guard"
  grep -Fxq release-operator "$root_directory/usr/local/sbin/guard-operator"
  grep -Fxq release-unit "$root_directory/etc/systemd/system/guard.service"
  grep -Fxq release-caller-unit "$root_directory/etc/systemd/system/guard-exec-as-caller.service"
  cmp -s "$upgrade_script" "$root_directory/usr/local/sbin/upgrade-guard"
  grep -Fxq original-authority "$authority_key"
  grep -Fxq untouched-authority "$decoy_authority_key"
  [[ "$(stat -c '%a' "$root_directory/var/lib/guard-exec")" == 700 ]]
  [[ "$(stat -c '%a' "$root_directory/var/lib/guard-exec/.ssh")" == 700 ]]
  [[ "$(<"$mock_state")" == "$expected_active" ]]
  [[ "$(<"$mock_enabled_state")" == "$expected_enabled" ]]
}

reset_original() {
  make_guard "$root_directory/usr/local/bin/guard" original
  printf '%s\n' original-operator > "$root_directory/usr/local/sbin/guard-operator"
  printf '%s\n' original-unit > "$root_directory/etc/systemd/system/guard.service"
  printf '%s\n' original-caller-unit > "$root_directory/etc/systemd/system/guard-exec-as-caller.service"
  rm -f -- "$root_directory/usr/local/sbin/upgrade-guard"
  printf '%s\n' original-config > "$root_directory/etc/guard/config.yaml"
  rm -r -- "$api_directory" "$decoy_api_directory" 2>/dev/null || true
  mkdir -p "$api_directory" "$decoy_api_directory"
  printf '%s\n' original-api > "$api_directory/body.json"
  printf '%s\n' untouched-api > "$decoy_api_directory/body.json"
  sqlite3 "$state_db" 'delete from state; insert into state values("original");'
  sqlite3 "$decoy_state_db" 'delete from state; insert into state values("untouched");'
  printf '%s\n' original-authority > "$authority_key"
  printf '%s\n' untouched-authority > "$decoy_authority_key"
  rm -f -- "$mock_state.post-stop-status-failed"
  rm -r -- "$root_directory/var/lib/guard-upgrade" 2>/dev/null || true
  : > "$mock_start_log"
  : > "$mock_sync_log"
  printf '%s\n' active > "$mock_state"
  printf '%s\n' enabled > "$mock_enabled_state"
  rm -f -- \
    "$mock_state.daemon-reloaded" \
    "$test_directory/exec-start-after-reload" \
    "$test_directory/status-state-db-once" \
    "$test_directory/status-socket-once"
}

for test_control in GUARD_UPGRADE_TEST_MODE GUARD_UPGRADE_TEST_FAIL_AT; do
  if env "$test_control=1" "$upgrade_script" install \
    --release-archive "$release_archive" \
    --expected-sha256 "$release_sha256" \
    --dry-run; then
    printf 'inherited test control unexpectedly reached the real root: %s\n' "$test_control" >&2
    exit 1
  fi
done
if GUARD_UPGRADE_TEST_MODE=1 "$upgrade_script" install \
  --release-archive "$release_archive" \
  --expected-sha256 "$release_sha256" \
  --dry-run --root /; then
  echo 'test mode unexpectedly accepted the real root' >&2
  exit 1
fi
assert_original

reset_original
mv "$root_directory/var/lib/guard-exec" "$root_directory/var/lib/guard-exec.withheld"
if run_install --dry-run; then
  echo 'dry run unexpectedly accepted a missing fixed execution account home' >&2
  exit 1
fi
if run_install; then
  echo 'installation unexpectedly accepted a missing fixed execution account home' >&2
  exit 1
fi
[[ "$(<"$mock_state")" == active ]]
mv "$root_directory/var/lib/guard-exec.withheld" "$root_directory/var/lib/guard-exec"
assert_original

reset_original
printf '%s\n' fixture > "$root_directory/var/lib/guard-exec/.ssh/config"
if run_install --dry-run; then
  echo 'dry run unexpectedly accepted SSH authority under the shared child home' >&2
  exit 1
fi
if run_install; then
  echo 'installation unexpectedly accepted SSH authority under the shared child home' >&2
  exit 1
fi
[[ "$(<"$mock_state")" == active ]]
mv "$root_directory/var/lib/guard-exec/.ssh/config" "$test_directory/withheld-child-ssh-config"
assert_original

reset_original
if TAR_OPTIONS=--no-recursion run_install; then
  echo 'inherited TAR_OPTIONS unexpectedly affected installation' >&2
  exit 1
fi
assert_original

for hostile_kind in absolute dotdot link device layout; do
  reset_original
  hostile_archive="$(make_hostile_archive "$hostile_kind")"
  hostile_sha256="$(sha256sum "$hostile_archive" | cut -d ' ' -f 1)"
  if run_upgrade install \
    --release-archive "$hostile_archive" \
    --expected-sha256 "$hostile_sha256"; then
    printf 'hostile release archive unexpectedly installed: %s\n' "$hostile_kind" >&2
    exit 1
  fi
  assert_original
done

GUARD_UPGRADE_TEST_EXEC_START="{ path=/usr/local/bin/guard ; argv[]=/usr/local/bin/guard server start --socket $socket_setting --state-db=$state_db_setting ; }" \
  run_install --dry-run

for exec_start in \
  '{ path=/usr/local/bin/guard ; argv[]=/usr/local/bin/guard server start ; }' \
  "{ path=/usr/local/bin/guard ; argv[]=/usr/local/bin/guard server start --state-db $state_db_setting --state-db /srv/other.sqlite ; }" \
  '{ path=/usr/local/bin/guard ; argv[]=/usr/local/bin/guard server start --state-db relative.sqlite ; }' \
  '{ path=/usr/local/bin/guard ; argv[]=/usr/local/bin/guard server start --state-db /srv/guard\ state/guard.sqlite ; }'; do
  if GUARD_UPGRADE_TEST_EXEC_START="$exec_start" run_install; then
    echo 'invalid active service state database setting unexpectedly succeeded' >&2
    exit 1
  fi
  assert_original
done

for candidate_failure in incompatible malformed; do
  reset_original
  case "$candidate_failure" in
    incompatible)
      if GUARD_UPGRADE_TEST_CANDIDATE_INCOMPATIBLE=1 run_install; then
        echo 'candidate state database check unexpectedly accepted incompatible state' >&2
        exit 1
      fi
      ;;
    malformed)
      if GUARD_UPGRADE_TEST_CANDIDATE_MALFORMED=1 run_install; then
        echo 'candidate state database check unexpectedly accepted malformed output' >&2
        exit 1
      fi
      ;;
  esac
  assert_original
  [[ ! -s "$mock_start_log" ]]
done

reset_original
if GUARD_UPGRADE_TEST_KILL_AT=candidate-state-db-checked run_install; then
  echo 'pre-transaction process-death injection unexpectedly succeeded' >&2
  exit 1
fi
staging_root="$root_directory/var/lib/guard-upgrade/release-staging"
[[ ! -e "$root_directory/var/lib/guard/upgrade-staging" ]]
stale_probe_archive="$test_directory/stale-probe-release.tar.gz"
cp "$release_archive" "$stale_probe_archive"
printf '%s' tampered >> "$stale_probe_archive"
if run_upgrade install \
  --release-archive "$stale_probe_archive" \
  --expected-sha256 "$release_sha256"; then
  echo 'stale-stage recovery probe unexpectedly installed a tampered archive' >&2
  exit 1
fi
if [[ -d "$staging_root" ]]; then
  [[ -z "$(find "$staging_root" -mindepth 1 -maxdepth 1 -print -quit)" ]]
fi
assert_original

reset_original
live_wal_fifo="$test_directory/live-wal-input"
mkfifo "$live_wal_fifo"
sqlite3 "$state_db" < "$live_wal_fifo" > "$test_directory/live-wal-output" &
live_wal_pid=$!
exec 7>"$live_wal_fifo"
printf '%s\n' \
  'PRAGMA journal_mode=WAL;' \
  'BEGIN IMMEDIATE;' \
  'INSERT INTO state VALUES("live-wal");' >&7
for _ in $(seq 1 40); do
  [[ -e "$state_db-wal" ]] && break
  sleep 0.05
done
[[ -e "$state_db-wal" ]]
if GUARD_UPGRADE_TEST_EXPECT_LIVE_WAL=1 \
  GUARD_UPGRADE_TEST_FAIL_AT=candidate-state-db-checked run_install; then
  echo 'live-WAL candidate compatibility probe unexpectedly succeeded' >&2
  exit 1
fi
printf '%s\n' 'COMMIT;' >&7
exec 7>&-
wait "$live_wal_pid"
rm -f -- "$live_wal_fifo"
sqlite3 "$state_db" 'delete from state where value="live-wal";'
assert_original
[[ ! -s "$mock_start_log" ]]

sqlite_injection_probe="$test_directory/sqlite-injection-probe"
sqlite_injection_directory="${root_directory}/var/backups/guard-inject"$'\'\n.shell touch sqlite-injection-probe'
if run_install --backup-dir "$sqlite_injection_directory"; then
  echo 'SQLite-injection backup directory unexpectedly succeeded' >&2
  exit 1
fi
[[ ! -e "$sqlite_injection_probe" ]]
assert_original

tampered_archive="$test_directory/tampered-release.tar.gz"
cp "$release_archive" "$tampered_archive"
printf '%s' tampered >> "$tampered_archive"
if run_upgrade install \
  --release-archive "$tampered_archive" \
  --expected-sha256 "$release_sha256" \
  --dry-run; then
  echo 'tampered release archive unexpectedly passed its external digest' >&2
  exit 1
fi

transaction_root="$root_directory/var/lib/guard-upgrade"
mkdir -p "$transaction_root"
chmod 0700 "$transaction_root"
rm -f -- "$transaction_root/upgrade.lock"
ln -s "$test_directory/untrusted-lock-target" "$transaction_root/upgrade.lock"
if run_install; then
  echo 'installation unexpectedly accepted a symbolic-link deployment lock' >&2
  exit 1
fi
rm "$transaction_root/upgrade.lock"
install -m 0600 /dev/null "$transaction_root/upgrade.lock"
exec 8<>"$transaction_root/upgrade.lock"
flock -n 8
if run_install; then
  echo 'concurrent install unexpectedly acquired the deployment lock' >&2
  exit 1
fi
flock -u 8
exec 8>&-
assert_original

for boundary in install-service-stopped install-binary install-operator install-upgrader install-standard-unit install-caller-unit; do
  reset_original
  if GUARD_UPGRADE_TEST_FAIL_AT="$boundary" run_install; then
    printf 'fault injection unexpectedly succeeded: %s\n' "$boundary" >&2
    exit 1
  fi
  assert_original
done

reset_original
if GUARD_UPGRADE_TEST_FAIL_AT=backup-database run_install; then
  echo 'quiesced backup failure unexpectedly succeeded' >&2
  exit 1
fi
assert_original
[[ ! -e "$root_directory/var/lib/guard-upgrade/upgrade-transaction" ]]
[[ "$(wc -l < "$mock_start_log")" == 1 ]]

for sync_failure in backup backup-parent; do
  reset_original
  if GUARD_UPGRADE_TEST_SYNC_FAIL_AT="$sync_failure" run_install; then
    printf 'installation unexpectedly advanced past an undurable %s\n' "$sync_failure" >&2
    exit 1
  fi
  assert_original
  [[ ! -e "$root_directory/var/lib/guard-upgrade/upgrade-transaction" ]]
  [[ -n "$(find "$root_directory/var/backups/guard" -mindepth 1 -maxdepth 1 -type d -name 'guard-install-*' -print -quit)" ]]
done

reset_original
if GUARD_UPGRADE_TEST_KILL_AT=backup-database run_install; then
  echo 'quiesced backup process-death injection unexpectedly succeeded' >&2
  exit 1
fi
journal_directory="$root_directory/var/lib/guard-upgrade/upgrade-transaction"
[[ "$(<"$journal_directory/phase")" == quiescing ]]
rm -f -- "$journal_directory/service-active" "$journal_directory/service-enabled"
if run_upgrade install \
  --release-archive "$tampered_archive" \
  --expected-sha256 "$release_sha256"; then
  echo 'quiesced backup recovery probe unexpectedly installed a tampered archive' >&2
  exit 1
fi
assert_original
[[ ! -e "$journal_directory" ]]

reset_original
if GUARD_UPGRADE_TEST_STOP_FAIL=1 run_install; then
  echo 'unchanged-service stop failure unexpectedly succeeded' >&2
  exit 1
fi
assert_original
if [[ -s "$mock_start_log" ]]; then
  echo 'unchanged-service stop failure unexpectedly restarted Guard' >&2
  exit 1
fi

reset_original
if GUARD_UPGRADE_TEST_STOP_FAIL_TO_FAILED=1 run_install; then
  echo 'failed-state stop failure unexpectedly succeeded' >&2
  exit 1
fi
assert_original
[[ "$(wc -l < "$mock_start_log")" == 1 ]]

reset_original
if GUARD_UPGRADE_TEST_SIGNAL_AT=service-stop-command-returned run_install; then
  echo 'post-stop signal injection unexpectedly succeeded' >&2
  exit 1
fi
assert_original

reset_original
GUARD_UPGRADE_TEST_POST_STOP_STATUS_FAIL=1 run_install
assert_release

reset_original
if GUARD_UPGRADE_TEST_STATUS_FAIL=1 run_install; then
  echo 'status handshake failure unexpectedly succeeded' >&2
  exit 1
fi
assert_original

reset_original
if GUARD_UPGRADE_TEST_EXEC_START_AFTER_RELOAD="{ path=/usr/local/bin/guard ; argv[]=/usr/local/bin/guard server start --socket /run/guard/guard.sock --state-db /var/lib/guard/state.db --users 1000 ; }" \
  run_install; then
  echo 'install accepted changed effective Guard service settings' >&2
  exit 1
fi
assert_original

reset_original
if GUARD_UPGRADE_TEST_STATUS_SOCKET_ONCE=/run/guard/guard.sock run_install; then
  echo 'install accepted a daemon socket mismatch' >&2
  exit 1
fi
assert_original

reset_original
if GUARD_UPGRADE_TEST_SIGNAL_AT=install-operator run_install; then
  echo 'signal injection unexpectedly succeeded' >&2
  exit 1
fi
assert_original

for boundary in install-service-stopped install-binary install-operator install-upgrader install-standard-unit install-caller-unit; do
  reset_original
  if GUARD_UPGRADE_TEST_KILL_AT="$boundary" run_install; then
    printf 'process-death injection unexpectedly succeeded: %s\n' "$boundary" >&2
    exit 1
  fi
  [[ -d "$root_directory/var/lib/guard-upgrade/upgrade-transaction" ]]
  if run_upgrade install \
    --release-archive "$tampered_archive" \
    --expected-sha256 "$release_sha256"; then
    printf 'recovery probe unexpectedly installed a tampered archive: %s\n' "$boundary" >&2
    exit 1
  fi
  assert_original
  [[ ! -e "$root_directory/var/lib/guard-upgrade/upgrade-transaction" ]]
done

reset_original
if GUARD_UPGRADE_TEST_FAIL_AT=install-binary \
  GUARD_UPGRADE_TEST_RECOVERY_FAIL_AT=recovery-before-restore run_install; then
  echo 'recovery fault injection unexpectedly succeeded' >&2
  exit 1
fi
[[ -d "$root_directory/var/lib/guard-upgrade/upgrade-transaction" ]]
if run_upgrade install \
  --release-archive "$tampered_archive" \
  --expected-sha256 "$release_sha256"; then
  echo 'retained-journal recovery probe unexpectedly installed a tampered archive' >&2
  exit 1
fi
assert_original
[[ ! -e "$root_directory/var/lib/guard-upgrade/upgrade-transaction" ]]

reset_original
if GUARD_UPGRADE_TEST_KILL_AT=install-binary run_install; then
  echo 'journal validation setup unexpectedly succeeded' >&2
  exit 1
fi
journal_directory="$root_directory/var/lib/guard-upgrade/upgrade-transaction"
[[ -d "$journal_directory" && ! -L "$journal_directory" ]]
[[ "$(stat -c '%a' "$root_directory/var/lib/guard-upgrade")" == 700 ]]
[[ "$(stat -c '%a' "$journal_directory")" == 700 ]]
chmod 0755 "$journal_directory"
if run_upgrade install \
  --release-archive "$tampered_archive" \
  --expected-sha256 "$release_sha256"; then
  echo 'permissive transaction journal unexpectedly recovered' >&2
  exit 1
fi
reset_original

if GUARD_UPGRADE_TEST_KILL_AT=install-binary run_install; then
  echo 'journal type validation setup unexpectedly succeeded' >&2
  exit 1
fi
rm -r -- "$journal_directory"
ln -s "$test_directory" "$journal_directory"
if run_upgrade install \
  --release-archive "$tampered_archive" \
  --expected-sha256 "$release_sha256"; then
  echo 'symbolic-link transaction journal unexpectedly recovered' >&2
  exit 1
fi
reset_original

reset_original
upgrade_output="$(run_install)"
assert_release
backup_directory="$(
  printf '%s\n' "$upgrade_output" |
    sed -n 's/^Guard release installed; verified backup: //p' |
    tail -n 1
)"
[[ -n "$backup_directory" ]]
[[ "$(dirname "$backup_directory")" == "$root_directory/var/backups/guard" ]]
[[ "$(stat -c '%a' "$root_directory/var/backups")" == 755 ]]
[[ "$(stat -c '%a' "$root_directory/var/backups/guard")" == 700 ]]
[[ "$(stat -c '%a' "$root_directory/var/lib/guard-upgrade")" == 700 ]]
[[ "$(stat -c '%a' "$root_directory/var/lib/guard-upgrade/release-staging")" == 700 ]]
[[ ! -e "$root_directory/var/lib/guard/upgrade-staging" ]]
[[ "$(<"$backup_directory/metadata/state-db")" == "$state_db_setting" ]]
[[ "$(<"$backup_directory/metadata/service-active")" == active ]]
[[ "$(<"$backup_directory/metadata/service-enabled")" == enabled ]]
grep -Fxq "$backup_directory" "$mock_sync_log"
grep -Fxq "$(dirname "$backup_directory")" "$mock_sync_log"

chmod 0777 "$root_directory/var/backups/guard"
if run_upgrade rollback --backup-dir "$backup_directory" --dry-run; then
  echo 'rollback accepted a writable Guard backup root' >&2
  exit 1
fi
chmod 0700 "$root_directory/var/backups/guard"

self_signed_backup="$root_directory/var/backups/guard/guard-untrusted-self-signed"
cp -a "$backup_directory" "$self_signed_backup"
chmod 0777 "$self_signed_backup"
printf '%s\n' tampered >> "$self_signed_backup/files/guard"
rewrite_backup_manifest "$self_signed_backup"
if run_upgrade rollback --backup-dir "$self_signed_backup" --dry-run; then
  echo 'rollback accepted a self-signed writable backup' >&2
  exit 1
fi

unlisted_backup="$root_directory/var/backups/guard/guard-unlisted-file"
cp -a "$backup_directory" "$unlisted_backup"
printf '%s\n' unlisted > "$unlisted_backup/metadata/unlisted"
if run_upgrade rollback --backup-dir "$unlisted_backup" --dry-run; then
  echo 'rollback accepted a backup file omitted from its manifest' >&2
  exit 1
fi

hard_linked_backup="$root_directory/var/backups/guard/guard-hard-linked-file"
cp -a "$backup_directory" "$hard_linked_backup"
ln "$hard_linked_backup/files/guard" "$test_directory/external-backup-link"
if run_upgrade rollback --backup-dir "$hard_linked_backup" --dry-run; then
  echo 'rollback accepted a backup file linked outside its protected directory' >&2
  exit 1
fi

legacy_backup="$root_directory/var/backups/guard/guard-legacy-service-state"
cp -a "$backup_directory" "$legacy_backup"
rm -f -- "$legacy_backup/metadata/service-active"
rewrite_backup_manifest "$legacy_backup"
run_upgrade rollback --backup-dir "$legacy_backup" --dry-run

rm -f -- "$mock_state.daemon-reloaded" "$test_directory/exec-start-after-reload"
if GUARD_UPGRADE_TEST_EXEC_START_AFTER_RELOAD="{ path=/usr/local/bin/guard ; argv[]=/usr/local/bin/guard server start --socket /run/guard/guard.sock --state-db /var/lib/guard/state.db --users 1000 ; }" \
  run_upgrade rollback --backup-dir "$backup_directory"; then
  echo 'rollback accepted a changed effective state database' >&2
  exit 1
fi
assert_release

if GUARD_UPGRADE_TEST_STATUS_STATE_DB_ONCE=/var/lib/guard/state.db \
  run_upgrade rollback --backup-dir "$backup_directory"; then
  echo 'rollback accepted a daemon state database mismatch' >&2
  exit 1
fi
assert_release

for boundary in rollback-service-stopped restore-binary restore-operator restore-upgrader restore-standard-unit restore-caller-unit restore-authority-key restore-database restore-config restore-api-proxy-reverts; do
  if GUARD_UPGRADE_TEST_FAIL_AT="$boundary" run_upgrade rollback --backup-dir "$backup_directory"; then
    printf 'rollback fault injection unexpectedly succeeded: %s\n' "$boundary" >&2
    exit 1
  fi
  assert_release
done

for boundary in rollback-service-stopped restore-binary restore-operator restore-upgrader restore-standard-unit restore-caller-unit restore-authority-key restore-database restore-config-displaced restore-config restore-api-proxy-reverts-displaced restore-api-proxy-reverts; do
  if GUARD_UPGRADE_TEST_KILL_AT="$boundary" run_upgrade rollback --backup-dir "$backup_directory"; then
    printf 'rollback process-death injection unexpectedly succeeded: %s\n' "$boundary" >&2
    exit 1
  fi
  [[ -d "$root_directory/var/lib/guard-upgrade/upgrade-transaction" ]]
  if run_upgrade install \
    --release-archive "$tampered_archive" \
    --expected-sha256 "$release_sha256"; then
    printf 'rollback recovery probe unexpectedly installed a tampered archive: %s\n' "$boundary" >&2
    exit 1
  fi
  assert_release
  [[ ! -e "$root_directory/var/lib/guard-upgrade/upgrade-transaction" ]]
done

printf '%s\n' release-api > "$api_directory/body.json"
run_upgrade rollback --backup-dir "$backup_directory"
assert_original

printf '%s\n' inactive > "$mock_state"
printf '%s\n' disabled > "$mock_enabled_state"
if GUARD_UPGRADE_TEST_FAIL_AT=rollback-service-stopped \
  run_upgrade rollback --backup-dir "$backup_directory"; then
  echo 'inactive rollback recovery fault unexpectedly succeeded' >&2
  exit 1
fi
assert_original inactive disabled
[[ ! -e "$root_directory/var/lib/guard-upgrade/upgrade-transaction" ]]

reset_original
printf '%s\n' disabled > "$mock_enabled_state"
stateful_upgrade_output="$(run_install)"
assert_release active disabled
stateful_backup_directory="$(
  printf '%s\n' "$stateful_upgrade_output" |
    sed -n 's/^Guard release installed; verified backup: //p' |
    tail -n 1
)"
[[ "$(<"$stateful_backup_directory/metadata/service-active")" == active ]]
[[ "$(<"$stateful_backup_directory/metadata/service-enabled")" == disabled ]]
printf '%s\n' enabled > "$mock_enabled_state"
run_upgrade rollback --backup-dir "$stateful_backup_directory"
assert_original active disabled
printf '%s\n' 'upgrade-guard fault-injection test passed'
