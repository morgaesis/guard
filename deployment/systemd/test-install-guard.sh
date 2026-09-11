#!/bin/bash
# Full mode requires an empty disposable Linux container, never the host.
set -euo pipefail
umask 077
assets=$(cd -- "$(dirname -- "$0")" && pwd -P)
installer=$assets/install-guard
bash -n "$installer"
"$installer" --help | grep -q -- '--check'
"$installer" | grep -q '^Usage:'
if "$installer" --unknown >/dev/null 2>&1; then exit 1; else test "$?" -eq 2; fi
[[ "${1:-}" != --verify-only ]] || { printf 'Installer syntax/help checks passed\n'; exit 0; }
[[ $# == 0 ]] || { printf 'Usage: test-install-guard.sh [--verify-only]\n' >&2; exit 2; }
[[ $EUID == 0 && ( -f /run/.containerenv || -f /.dockerenv ) ]] || { echo 'Full tests require root inside an empty disposable container' >&2; exit 1; }
for path in /etc/guard /var/lib/guard /usr/local/bin/guard /usr/local/sbin/guard-operator /usr/bin/systemctl; do
  [[ ! -e "$path" && ! -L "$path" ]] || { echo "Fixture is not empty: $path" >&2; exit 1; }
done
fixture=$(mktemp -d /tmp/guard-installer-fixture.XXXXXXXX)
printf 'Fixture retained at %s\n' "$fixture"
cat > /usr/bin/systemctl <<'MOCK'
#!/bin/sh
if test "$1" = show; then
  test "$2" = --all && test "$4" = guard.service || exit 91
  cat /tmp/guard-fixture-unit.properties
  exit 0
fi
test "$1" = is-active || { echo 'unexpected service mutation' >&2; exit 90; }
if test -f /tmp/guard-fixture-service-active; then echo active; exit 0; fi
echo inactive
exit 3
MOCK
chmod 755 /usr/bin/systemctl
mkdir "$fixture/package"
cp "$assets"/{install-guard,guard.service,guard-exec-as-caller.service,guard.env.example,guard-operator} "$fixture/package/"
installer=$fixture/package/install-guard
make_binary() {
  printf '%s\n' "$1" > "$fixture/package/PACKAGE-VERSION"
  cat > "$fixture/candidate binary" <<'CANDIDATE'
#!/bin/sh
test "$HOME" = "$PWD" || exit 81
test "$GUARD_NO_AUTO_CONFIG" = 1 || exit 82
test -z "${GUARD_ADMIN_TOKEN+x}" || exit 83
test -z "${INSTALLER_TEST_SENTINEL+x}" || exit 84
printf 'executed\n' >> /tmp/guard-fixture-candidate-executed
CANDIDATE
  printf 'printf "guard v%s\\n"\n' "$1" >> "$fixture/candidate binary"
  chmod 755 "$fixture/candidate binary"
}
make_binary 1.2.3
arguments=(--binary "$fixture/candidate binary" --version 1.2.3 --sha256 "$(sha256sum "$fixture/candidate binary" | cut -d ' ' -f 1)")
printf '0.8.7\n' > "$fixture/package/PACKAGE-VERSION"
if "$installer" --apply --binary "$fixture/candidate binary" --version 0.8.7 --sha256 "${arguments[5]}" > "$fixture/old-version.log" 2>&1; then exit 1; fi
test ! -e /etc/guard
test ! -e /tmp/guard-fixture-candidate-executed
printf '1.2.3\n' > "$fixture/package/PACKAGE-VERSION"
if [[ -f /fixtures/guard-old ]]; then
  if "$installer" --apply --binary /fixtures/guard-old --version 1.2.3 --sha256 "$(sha256sum /fixtures/guard-old | cut -d ' ' -f 1)" > "$fixture/old-initial.log" 2>&1; then exit 1; fi
  grep -q 'staged binary lacks the required 0.8.8' "$fixture/old-initial.log"
  test ! -e /etc/guard
  test ! -e /var/lib/guard
  if getent passwd guard >/dev/null || getent group guard-clients >/dev/null; then exit 1; fi
fi
export INSTALLER_TEST_SENTINEL=present
"$installer" --check "${arguments[@]}" > "$fixture/check-initial.log"
test ! -e /etc/guard
test ! -e /tmp/guard-fixture-candidate-executed
"$installer" --apply "${arguments[@]}" > "$fixture/install.log"
test "$(stat -c '%u:%g:%a' /usr/local/sbin/guard-operator)" = 0:0:700
test "$(stat -c '%u:%g:%a' /etc/guard/admin.token)" = 0:0:400
test "$(stat -c '%u:%g:%a' /etc/guard)" = 0:0:700
test "$(stat -c '%u:%g:%a' /var/lib/guard)" = "$(id -u guard):$(id -g guard):700"
test "$(stat -c %s /etc/guard/admin.token)" = 64
cp /etc/guard/admin.token "$fixture/original-token"
printf '\n# fixture configuration\n' >> /etc/default/guard
printf 'retained authority fixture\n' > /var/lib/guard/state.db
cp /etc/default/guard "$fixture/original-environment"
cp /var/lib/guard/state.db "$fixture/original-state"
identity=$(getent passwd guard)
group=$(getent group guard-clients)
inode=$(stat -c %i /usr/local/bin/guard)
"$installer" --check "${arguments[@]}" > "$fixture/check-repeat.log"
grep -q 'Planned changes: 0' "$fixture/check-repeat.log"
"$installer" --apply "${arguments[@]}" > "$fixture/repeat.log"
test "$(stat -c %i /usr/local/bin/guard)" = "$inode"
cmp -s /etc/guard/admin.token "$fixture/original-token"
cmp -s /etc/default/guard "$fixture/original-environment"
cmp -s /var/lib/guard/state.db "$fixture/original-state"
test "$(getent passwd guard)" = "$identity"
test "$(getent group guard-clients)" = "$group"

# A reader holding the old inode keeps a complete old binary across replacement.
exec 8</usr/local/bin/guard
cp /usr/local/bin/guard "$fixture/old-binary"
make_binary 1.2.4
arguments=(--binary "$fixture/candidate binary" --version 1.2.4 --sha256 "$(sha256sum "$fixture/candidate binary" | cut -d ' ' -f 1)")
printf '\n# packaged unit revision\n' >> "$fixture/package/guard.service"
"$installer" --apply "${arguments[@]}" > "$fixture/update.log"
cmp -s /proc/self/fd/8 "$fixture/old-binary"
cmp -s /usr/local/bin/guard "$fixture/candidate binary"
cmp -s /etc/guard/admin.token "$fixture/original-token"
cmp -s /etc/default/guard "$fixture/original-environment"
cmp -s /var/lib/guard/state.db "$fixture/original-state"
"$installer" --check "${arguments[@]}" > "$fixture/check-updated.log"
grep -q 'Planned changes: 0' "$fixture/check-updated.log"
cp /usr/local/bin/guard "$fixture/installed-binary"
cp /usr/local/sbin/guard-operator "$fixture/installed-operator"

reject() {
  if "$installer" --apply "${arguments[@]}" > "$fixture/refusal-$1.log" 2>&1; then
    echo "unexpected acceptance: $1" >&2; exit 1
  fi
  cmp -s /etc/guard/admin.token "$fixture/original-token"
  cmp -s /etc/default/guard "$fixture/original-environment"
  cmp -s /var/lib/guard/state.db "$fixture/original-state"
  cmp -s /usr/local/bin/guard "$fixture/installed-binary"
  cmp -s /usr/local/sbin/guard-operator "$fixture/installed-operator"
  test "$(getent passwd guard)" = "$identity"
  test "$(getent group guard-clients)" = "$group"
}
touch /tmp/guard-fixture-service-active
reject active-service
mv /tmp/guard-fixture-service-active "$fixture/service-active.control"
mkdir /etc/systemd/system/guard.service.d
printf '[Service]\nSupplementaryGroups=custom-clients\nPrivateTmp=true\n' > /etc/systemd/system/guard.service.d/custom.conf
cp /etc/systemd/system/guard.service.d/custom.conf "$fixture/drop-in-original"
reject custom-drop-in
cmp -s /etc/systemd/system/guard.service.d/custom.conf "$fixture/drop-in-original"
mv /etc/systemd/system/guard.service.d "$fixture/preserved-drop-ins"
printf '\n# local unit edit\n' >> /etc/systemd/system/guard.service
reject modified-unit
mv /etc/systemd/system/guard.service "$fixture/preserved-modified-unit"
cp "$fixture/package/guard.service" /etc/systemd/system/guard.service
chmod 644 /etc/systemd/system/guard.service
chmod 600 /etc/guard/admin.token
reject unsafe-token
chmod 400 /etc/guard/admin.token
mv /usr/local/bin/guard "$fixture/preserved-installed-binary"
ln -s "$fixture/preserved-installed-binary" /usr/local/bin/guard
reject symlink-binary
mv /usr/local/bin/guard "$fixture/preserved-binary-symlink"
mv "$fixture/preserved-installed-binary" /usr/local/bin/guard
arguments=(--binary "$fixture/candidate binary" --version 9.9.9 --sha256 "$(sha256sum "$fixture/candidate binary" | cut -d ' ' -f 1)")
reject wrong-version
printf '9.9.9\n' > "$fixture/package/PACKAGE-VERSION"
reject actual-version-mismatch
grep -q 'staged binary version does not match' "$fixture/refusal-actual-version-mismatch.log"
printf '1.2.4\n' > "$fixture/package/PACKAGE-VERSION"
make_binary 1.2.4-rc1
printf '1.2.4\n' > "$fixture/package/PACKAGE-VERSION"
arguments=(--binary "$fixture/candidate binary" --version 1.2.4 --sha256 "$(sha256sum "$fixture/candidate binary" | cut -d ' ' -f 1)")
reject prerelease
grep -q 'stable package version' "$fixture/refusal-prerelease.log"
make_binary 1.2.4
if [[ -f /fixtures/guard-old ]]; then
  arguments=(--binary /fixtures/guard-old --version 1.2.4 --sha256 "$(sha256sum /fixtures/guard-old | cut -d ' ' -f 1)")
  reject real-old-binary
  grep -q 'staged binary lacks the required 0.8.8' "$fixture/refusal-real-old-binary.log"
  printf 'Real pre-isolation binary rejected with installed state preserved\n'
fi
arguments=(--binary "$fixture/candidate binary" --version 1.2.4 --sha256 "$(printf '%064d' 0)")
reject wrong-digest
if grep -Fq -f "$fixture/original-token" "$fixture/"*.log; then echo 'token leaked to diagnostics' >&2; exit 1; fi
printf 'Installer lifecycle, preservation, refusal and atomic-replacement fixtures passed\n'
if [[ -f /fixtures/guard-new && -f /fixtures/guard-operator ]]; then
  cp /fixtures/guard-operator "$fixture/package/guard-operator"
  printf '0.8.8\n' > "$fixture/package/PACKAGE-VERSION"
  arguments=(--binary /fixtures/guard-new --version 0.8.8 --sha256 "$(sha256sum /fixtures/guard-new | cut -d ' ' -f 1)")
  "$installer" --apply "${arguments[@]}" > "$fixture/actual-package.log"
  cmp -s /usr/local/bin/guard /fixtures/guard-new
  cmp -s /usr/local/sbin/guard-operator /fixtures/guard-operator
  test "$(stat -c '%u:%g:%a' /usr/local/sbin/guard-operator)" = 0:0:700
  test "$(stat -c '%u:%g:%a' /etc/guard/admin.token)" = 0:0:400
  "$installer" --check "${arguments[@]}" > "$fixture/actual-package-check.log"
  grep -q 'Planned changes: 0' "$fixture/actual-package-check.log"
  if [[ -f /fixtures/guard-old ]]; then
    if "$installer" --apply --binary /fixtures/guard-old --version 0.8.8 --sha256 "$(sha256sum /fixtures/guard-old | cut -d ' ' -f 1)" > "$fixture/actual-mixed-package.log" 2>&1; then exit 1; fi
    grep -q 'staged binary lacks the required 0.8.8' "$fixture/actual-mixed-package.log"
  fi
  cmp -s /usr/local/bin/guard /fixtures/guard-new
  cmp -s /usr/local/sbin/guard-operator /fixtures/guard-operator
  cmp -s /etc/guard/admin.token "$fixture/original-token"
  cmp -s /etc/default/guard "$fixture/original-environment"
  cmp -s /var/lib/guard/state.db "$fixture/original-state"
  printf 'Actual 0.8.8 package installation and mixed-version refusal passed\n'
fi

# A compatible existing deployment keeps its unit/drop-in and identity contract.
mkdir /etc/systemd/system/guard.service.d
cat > /etc/systemd/system/guard.service.d/10-socket-group.conf <<'DROPIN'
[Service]
Group=guard
SupplementaryGroups=guard
ExecStart=
ExecStart=/usr/local/bin/guard server start --socket /run/guard/guard.sock --socket-group guard --state-db /var/lib/guard/state.db --users ${GUARD_ALLOWED_UIDS} --admin-token-stdin
DROPIN
printf '[Service]\nPrivateTmp=false\n' > /etc/systemd/system/guard.service.d/50-host-tmp.conf
cat > /tmp/guard-fixture-unit.properties <<'PROPERTIES'
LoadState=loaded
NeedDaemonReload=no
FragmentPath=/etc/systemd/system/guard.service
DropInPaths=/etc/systemd/system/guard.service.d/10-socket-group.conf /etc/systemd/system/guard.service.d/50-host-tmp.conf
ExecStart={ path=/usr/local/bin/guard ; argv[]=/usr/local/bin/guard server start --socket /run/guard/guard.sock --socket-group guard --state-db /var/lib/guard/state.db --users ${GUARD_ALLOWED_UIDS} --admin-token-stdin ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
Type=simple
User=guard
Group=guard
SupplementaryGroups=guard
DynamicUser=no
WorkingDirectory=/var/lib/guard
StandardInput=file
EnvironmentFiles=/etc/default/guard (ignore_errors=yes)
RootDirectory=
RootImage=
RootDirectoryStartOnly=no
PrivateUsers=no
PrivateNetwork=no
PrivateTmp=no
BindPaths=
BindReadOnlyPaths=
TemporaryFileSystem=
InaccessiblePaths=
MountImages=
ExtensionImages=
JoinsNamespaceOf=
StateDirectory=guard guard/.ssh
RuntimeDirectory=guard
PROPERTIES
cp /tmp/guard-fixture-unit.properties "$fixture/original-unit.properties"
if [[ -f /fixtures/guard-new && -f /fixtures/guard-old ]]; then
  # Replace only a derived fixture binary to exercise an actual version update.
  mv /usr/local/bin/guard "$fixture/before-existing-update"
  cp /fixtures/guard-old /usr/local/bin/guard
  chmod 755 /usr/local/bin/guard
  arguments=(--binary /fixtures/guard-new --version 0.8.8 --sha256 "$(sha256sum /fixtures/guard-new | cut -d ' ' -f 1)")
else
  make_binary 1.2.5
  arguments=(--binary "$fixture/candidate binary" --version 1.2.5 --sha256 "$(sha256sum "$fixture/candidate binary" | cut -d ' ' -f 1)")
fi
preserved_snapshot() {
  # Hashes and metadata stay inside the private fixture; contents are not logged.
  find /etc/guard /etc/default/guard /var/lib/guard /etc/systemd/system /etc/passwd /etc/group -print0 |
    sort -z | xargs -0 stat -c '%n:%d:%i:%u:%g:%a:%Y'
  find /etc/guard /etc/default/guard /var/lib/guard /etc/systemd/system /etc/passwd /etc/group -type f -print0 |
    sort -z | xargs -0 sha256sum
}
preserved_snapshot > "$fixture/preserved-before-update"
cp /usr/local/bin/guard "$fixture/binary-before-update"
cp /usr/local/sbin/guard-operator "$fixture/operator-before-update"
cp /tmp/guard-fixture-candidate-executed "$fixture/executions-before-check"
touch /tmp/guard-fixture-service-active
"$installer" --check --update-binaries --service guard.service "${arguments[@]}" > "$fixture/check-existing-active.log"
grep -q '^PREREQUISITE stop guard.service before --apply' "$fixture/check-existing-active.log"
cmp -s /tmp/guard-fixture-candidate-executed "$fixture/executions-before-check"
preserved_snapshot > "$fixture/preserved-after-check"
cmp -s "$fixture/preserved-before-update" "$fixture/preserved-after-check"
if "$installer" --apply --update-binaries --service guard.service "${arguments[@]}" > "$fixture/refuse-existing-active.log" 2>&1; then exit 1; fi
grep -q 'stop and inspect' "$fixture/refuse-existing-active.log"
if "$installer" --check --update-binaries "${arguments[@]}" > "$fixture/refuse-implicit-service.log" 2>&1; then exit 1; else test "$?" = 2; fi
mv /tmp/guard-fixture-service-active "$fixture/existing-active.control"
"$installer" --apply --update-binaries --service guard.service "${arguments[@]}" > "$fixture/update-existing.log"
cmp -s /usr/local/bin/guard "${arguments[1]}"
cmp -s /usr/local/sbin/guard-operator "$fixture/package/guard-operator"
test "$(stat -c '%u:%g:%a' /usr/local/sbin/guard-operator)" = 0:0:700
preserved_snapshot > "$fixture/preserved-after-update"
cmp -s "$fixture/preserved-before-update" "$fixture/preserved-after-update"
inode=$(stat -c '%i' /usr/local/bin/guard)
"$installer" --apply --update-binaries --service guard.service "${arguments[@]}" > "$fixture/update-existing-repeat.log"
test "$(stat -c '%i' /usr/local/bin/guard)" = "$inode"
"$installer" --check --update-binaries --service guard.service "${arguments[@]}" > "$fixture/check-existing-repeat.log"
grep -q 'Planned changes: 0' "$fixture/check-existing-repeat.log"
preserved_snapshot > "$fixture/preserved-after-repeat"
cmp -s "$fixture/preserved-before-update" "$fixture/preserved-after-repeat"

reject_existing() {
  preserved_snapshot > "$fixture/before-refuse-existing-$1"
  if "$installer" --apply --update-binaries --service guard.service "${arguments[@]}" > "$fixture/refuse-existing-$1.log" 2>&1; then
    echo "unexpected existing-unit acceptance: $1" >&2; exit 1
  fi
  grep -q "$2" "$fixture/refuse-existing-$1.log"
  preserved_snapshot > "$fixture/after-refuse-existing-$1"
  cmp -s "$fixture/before-refuse-existing-$1" "$fixture/after-refuse-existing-$1"
  cmp -s /usr/local/bin/guard "${arguments[1]}"
  cmp -s /usr/local/sbin/guard-operator "$fixture/package/guard-operator"
}
for failure in endpoint state-path credential-mode stdin-mode binary unit-path identity namespace pending-reload missing-property; do
  cp "$fixture/original-unit.properties" /tmp/guard-fixture-unit.properties
  case "$failure" in
    endpoint) sed -i 's|--socket /run/guard/guard.sock|--socket /run/other.sock|' /tmp/guard-fixture-unit.properties; expected='socket must match' ;;
    state-path) sed -i 's|--state-db /var/lib/guard/state.db|--state-db /var/lib/other/state.db|' /tmp/guard-fixture-unit.properties; expected='database path' ;;
    credential-mode) sed -i 's/--admin-token-stdin/--admin-token-file other/' /tmp/guard-fixture-unit.properties; expected='credential mode' ;;
    stdin-mode) sed -i 's/^StandardInput=file$/StandardInput=socket/' /tmp/guard-fixture-unit.properties; expected='protected stdin file' ;;
    binary) sed -i 's|path=/usr/local/bin/guard|path=/usr/local/bin/other|' /tmp/guard-fixture-unit.properties; expected='directly execute' ;;
    unit-path) sed -i 's|^FragmentPath=.*|FragmentPath=/run/systemd/system/guard.service|' /tmp/guard-fixture-unit.properties; expected='installed unit path' ;;
    identity) sed -i 's/^User=guard$/User=root/' /tmp/guard-fixture-unit.properties; expected='guard identity' ;;
    namespace) sed -i 's|^RootDirectory=$|RootDirectory=/other|' /tmp/guard-fixture-unit.properties; expected='namespace or lifecycle' ;;
    pending-reload) sed -i 's/^NeedDaemonReload=no$/NeedDaemonReload=yes/' /tmp/guard-fixture-unit.properties; expected='pending unit-file changes' ;;
    missing-property) sed -i '/^RootImage=/d' /tmp/guard-fixture-unit.properties; expected='property unavailable' ;;
  esac
  reject_existing "$failure" "$expected"
done
cp "$fixture/original-unit.properties" /tmp/guard-fixture-unit.properties
cp /etc/systemd/system/guard.service.d/50-host-tmp.conf "$fixture/original-tmp-drop-in"
printf 'StandardInput=file:/etc/guard/other.token\n' >> /etc/systemd/system/guard.service.d/50-host-tmp.conf
reject_existing stdin-path 'stdin must use'
mv /etc/systemd/system/guard.service.d/50-host-tmp.conf "$fixture/rejected-stdin-drop-in"
cp "$fixture/original-tmp-drop-in" /etc/systemd/system/guard.service.d/50-host-tmp.conf
chmod 666 /etc/systemd/system/guard.service.d/50-host-tmp.conf
reject_existing untrusted-unit 'writable path'
chmod 600 /etc/systemd/system/guard.service.d/50-host-tmp.conf
printf 'ExecStart=+/usr/local/bin/guard server start --admin-token-stdin\n' >> /etc/systemd/system/guard.service.d/50-host-tmp.conf
reject_existing privilege-prefix 'executable prefix'
mv /etc/systemd/system/guard.service.d/50-host-tmp.conf "$fixture/rejected-privilege-drop-in"
cp "$fixture/original-tmp-drop-in" /etc/systemd/system/guard.service.d/50-host-tmp.conf
chmod 600 /etc/guard/admin.token
reject_existing token-mode 'mode 0400'
chmod 400 /etc/guard/admin.token
printf 'ExecStartPre=/bin/true\n' >> /etc/systemd/system/guard.service.d/50-host-tmp.conf
reject_existing lifecycle 'lifecycle commands'
mv /etc/systemd/system/guard.service.d/50-host-tmp.conf "$fixture/rejected-lifecycle-drop-in"
cp "$fixture/original-tmp-drop-in" /etc/systemd/system/guard.service.d/50-host-tmp.conf
if grep -Fq -f "$fixture/original-token" "$fixture/"*.log; then echo 'token leaked to diagnostics' >&2; exit 1; fi
printf 'Existing-unit update, active dry-run, preservation, convergence and compatibility refusals passed\n'

# Execute the documented Bash bodies, changing only absolute fixture paths.
documentation=$assets/../../DEPLOYMENT.md
awk '/^backup_dir=.*GUARD_SNAPSHOT/ { copying=1; next } /^GUARD_SNAPSHOT$/ { exit } copying { print }' "$documentation" > "$fixture/snapshot-body.sh"
awk '/^bash -s -- .*GUARD_ROLLBACK/ { copying=1; next } /^GUARD_ROLLBACK$/ { exit } copying { print }' "$documentation" > "$fixture/rollback-body.sh"
test -s "$fixture/snapshot-body.sh"
test -s "$fixture/rollback-body.sh"
mkdir "$fixture/doc-bin"
cat > "$fixture/doc-bin/fixture-command" <<'DOC_MOCK'
#!/bin/bash
set -euo pipefail
name=${0##*/}
printf '%s %s\n' "$name" "${1:-}" >> "$DOC_ROOT/calls"
injected() { printf 'injected %s\n' "$DOC_FAILURE" >> "$DOC_ROOT/calls"; exit 42; }
case "$name" in
  systemctl)
    case "$1" in
      stop)
        [[ "$DOC_FAILURE" != stop ]] || injected
        touch "$DOC_ROOT/stopped" ;;
      is-active)
        if [[ "$2" == guard-exec-as-caller.service ]]; then echo inactive
        elif [[ -f "$DOC_ROOT/stopped" && "$DOC_FAILURE" == inactive ]]; then
          printf 'injected inactive\n' >> "$DOC_ROOT/calls"; echo active
        elif [[ -f "$DOC_ROOT/stopped" ]]; then echo inactive
        else echo active; fi ;;
      start|daemon-reload) ;;
      *) exit 43 ;;
    esac ;;
  sha256sum)
    [[ "$1" != --check || "$DOC_FAILURE" != checksum ]] || injected
    exec /usr/bin/sha256sum "$@" ;;
  mv)
    count=$(cat "$DOC_ROOT/moves" 2>/dev/null || echo 0)
    count=$((count + 1))
    printf '%s\n' "$count" > "$DOC_ROOT/moves"
    [[ "$DOC_FAILURE" != "move-$count" ]] || injected
    if [[ "$count" == 1 && "$DOC_FAILURE" == move-partial ]]; then
      /usr/bin/mv "$@"
      injected
    fi
    if [[ "$count" == 1 && "$DOC_FAILURE" == move-collision ]]; then
      mkdir "${@: -1}"
      printf 'retained collision\n' > "${@: -1}/collision"
      printf 'injected move-collision\n' >> "$DOC_ROOT/calls"
    fi
    exec /usr/bin/mv "$@" ;;
  cp)
    count=$(cat "$DOC_ROOT/copies" 2>/dev/null || echo 0)
    count=$((count + 1))
    printf '%s\n' "$count" > "$DOC_ROOT/copies"
    [[ "$DOC_FAILURE" != "copy-$count" ]] || injected
    exec /usr/bin/cp "$@" ;;
  sqlite3) [[ "$DOC_FAILURE" != sqlite ]] || injected ;;
  *) exit 43 ;;
esac
DOC_MOCK
chmod 755 "$fixture/doc-bin/fixture-command"
for tool in systemctl sha256sum mv cp sqlite3; do
  ln -s fixture-command "$fixture/doc-bin/$tool"
done
for kind in snapshot rollback; do
  failures=(stop inactive checksum)
  if [[ "$kind" == rollback ]]; then
    failures+=(move-1 move-2 move-3 move-4 move-5 move-6 move-7 move-8 move-9 move-partial move-collision success)
  else
    failures+=(sqlite copy-1 copy-2 copy-3 copy-4 copy-5 copy-6 copy-7 copy-8 copy-9)
  fi
  for failure in "${failures[@]}"; do
    doc_root=$fixture/doc-$kind-$failure
    mkdir -p "$doc_root"/{var/lib/guard,var/backups,etc/guard,etc/default,etc/systemd/system,usr/local/bin,usr/local/sbin,snapshot/state,snapshot/config,snapshot/units}
    printf 'new database\n' > "$doc_root/var/lib/guard/state.db"
    printf 'new WAL\n' > "$doc_root/var/lib/guard/state.db-wal"
    printf 'new SHM\n' > "$doc_root/var/lib/guard/state.db-shm"
    printf 'old database\n' > "$doc_root/snapshot/state/state.db"
    printf 'guard.service\n' > "$doc_root/snapshot/service-unit"
    for path in etc/default/guard usr/local/bin/guard usr/local/sbin/guard-operator; do
      printf 'new fixture file\n' > "$doc_root/$path"
    done
    for path in environment guard guard-operator; do printf 'old fixture file\n' > "$doc_root/snapshot/$path"; done
    for unit in guard.service guard-exec-as-caller.service; do
      printf 'new unit\n' > "$doc_root/etc/systemd/system/$unit"
      mkdir "$doc_root/etc/systemd/system/$unit.d"
      printf 'retained drop-in\n' > "$doc_root/etc/systemd/system/$unit.d/override.conf"
      printf 'old unit\n' > "$doc_root/snapshot/units/$unit"
    done
    (cd "$doc_root/snapshot" && find . -type f -print0 | sort -z | xargs -0 sha256sum) > "$doc_root/checksums"
    mv "$doc_root/checksums" "$doc_root/snapshot/SHA256SUMS"
    sed -e "s|/var/|$doc_root/var/|g" -e "s|/etc/|$doc_root/etc/|g" -e "s|/usr/local/|$doc_root/usr/local/|g" "$fixture/$kind-body.sh" > "$doc_root/commands.sh"
    # The conditional caller must not suppress fail-fast behavior in Bash.
    if DOC_ROOT="$doc_root" DOC_FAILURE="$failure" PATH="$fixture/doc-bin:$PATH" \
      bash "$doc_root/commands.sh" "$doc_root/snapshot" guard.service > "$doc_root/output" 2>&1; then
      [[ "$failure" == success ]] || { echo "doc failure injection accepted: $kind/$failure" >&2; exit 1; }
    else
      [[ "$failure" != success ]] || { echo 'documented restore failed' >&2; exit 1; }
    fi
    if [[ "$failure" != success ]]; then
      grep -q "^injected $failure$" "$doc_root/calls" || { echo "injection not reached: $kind/$failure" >&2; exit 1; }
      if grep -q '^systemctl start' "$doc_root/calls"; then echo 'restart after failed prerequisite' >&2; exit 1; fi
      if [[ "$kind" == rollback ]] && grep -q '^cp ' "$doc_root/calls"; then echo 'restoration after failed prerequisite' >&2; exit 1; fi
      retained_database=$(find "$doc_root/var/lib" -name state.db)
      retained_wal=$(find "$doc_root/var/lib" -name state.db-wal)
      retained_shm=$(find "$doc_root/var/lib" -name state.db-shm)
      test "$(cat "$retained_database")" = 'new database'
      test "$(cat "$retained_wal")" = 'new WAL'
      test "$(cat "$retained_shm")" = 'new SHM'
      if [[ "$failure" == move-collision ]]; then
        collision=$(find "$doc_root/var/lib" -name collision)
        test "$(cat "$collision")" = 'retained collision'
      fi
    else
      cmp -s "$doc_root/var/lib/guard/state.db" "$doc_root/snapshot/state/state.db"
      test ! -e "$doc_root/var/lib/guard/state.db-wal"
      test ! -e "$doc_root/var/lib/guard/state.db-shm"
      displaced=$(find "$doc_root/var/lib" -path '*/state/state.db-wal')
      test -n "$displaced"
      test "$(cat "$displaced")" = 'new WAL'
      grep -q '^systemctl start' "$doc_root/calls"
    fi
  done
done
printf 'Documented snapshot/rollback failure injection and displaced-sidecar preservation passed\n'
