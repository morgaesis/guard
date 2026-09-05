#!/bin/bash
# Container-side synthetic-user fixture and deterministic contract runner.
set -euo pipefail

SOCKET=/scenario/run/guard.sock
PROTECTED_CATALOG_DIR=/authority
PROTECTED_CATALOG="$PROTECTED_CATALOG_DIR/verbs.yaml"
PROTECTED_CATALOG_LOCK="$PROTECTED_CATALOG_DIR/.verbs.yaml.learning-lock"
PROTECTED_OPERATOR_NOTE="$PROTECTED_CATALOG_DIR/operator-note"
SCENARIO="${2:-}"
RAW="/scenario/raw/$SCENARIO.log"
PRINCIPAL_ROOT="/scenario/principals/$(id -u)"
PHASE_OUTPUT="$PRINCIPAL_ROOT/phase-output"
RESULT="$PRINCIPAL_ROOT/results/$SCENARIO.md"
FAILURE="$PRINCIPAL_ROOT/failure.txt"
COLLECTOR_ROOT=/scenario/collector
COLLECTOR_RESULTS="$COLLECTOR_ROOT/results"
COLLECTOR_PHASES="$COLLECTOR_ROOT/phases"
FIXTURE_API_AUTHORITY_DIR=/scenario/api-contract
FIXTURE_API_TOKEN_FILE="$FIXTURE_API_AUTHORITY_DIR/token"
FIXTURE_API_TOKEN_DIGEST_FILE="$FIXTURE_API_AUTHORITY_DIR/token.sha256"
UPSTREAM_KUBECONFIG=/scenario/fixtures/upstream.kubeconfig
BROKERED_KUBECONFIG=/scenario/run/brokered.kubeconfig
KUBE_PROXY=127.0.0.1:18443

caller_identity_scenario() {
  [ "$SCENARIO" = SU-12-api ] || [ "$SCENARIO" = SU-12-ansible ]
}

generate_fixture_value() {
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
}

write_generated_fixture_value() {
  local destination="$1"
  generate_fixture_value > "$destination"
  printf '\n' >> "$destination"
}

provision_fixture_api_token() {
  [ "$(id -u)" -eq 0 ]
  runuser -u agent -- env -i \
    HOME=/tmp/synthetic-home-1001 \
    XDG_CONFIG_HOME=/tmp/synthetic-config-1001 \
    XDG_DATA_HOME=/tmp/synthetic-data-1001 \
    GUARD_SOCKET="$SOCKET" \
    PATH=/usr/local/bin:/usr/bin:/bin \
    guard secrets add fixture/api-token < "$FIXTURE_API_TOKEN_FILE"
}

setup_fixture() {
  mkdir -p /scenario/home /scenario/config/guard /scenario/data \
    /scenario/raw \
    /scenario/fixtures/staging /scenario/bin /scenario/ansible /scenario/run
  if [ ! -d /scenario/journey ]; then
    mkdir /scenario/journey
    chmod 1777 /scenario/journey
  fi
  if [ ! -d /scenario/principals ]; then
    mkdir /scenario/principals
    chmod 1777 /scenario/principals
  fi
  chmod 0711 /scenario
  chmod 1777 /scenario/raw
  chmod 0777 /scenario/fixtures /scenario/fixtures/staging /scenario/ansible
  chgrp guard-clients /scenario/run
  chmod 0755 /scenario/run
  cat > "$UPSTREAM_KUBECONFIG" <<'EOF'
apiVersion: v1
kind: Config
clusters:
  - name: fixture
    cluster:
      server: https://127.0.0.1:19443
contexts:
  - name: fixture
    context:
      cluster: fixture
      user: fixture
current-context: fixture
users:
  - name: fixture
    user: {}
EOF
  printf '[fixture]\nlocalhost\n' > /scenario/ansible/inventory
  printf '[defaults]\ninventory = inventory\n' > /scenario/ansible/ansible.cfg
  printf '%s\n' '---' '- hosts: fixture' '  gather_facts: false' '  tasks: []' > /scenario/ansible/site.yml
  cat > /scenario/config/guard/tools.yaml <<'EOF'
tools:
  systemctl:
    secrets:
      FIXTURE_API_TOKEN: fixture/api-token
EOF
  cat > /scenario/bin/kubectl <<'EOF'
#!/bin/sh
case "${KUBECONFIG:-}" in
  /scenario/run/brokered.kubeconfig|/scenario/private-install/run/brokered.kubeconfig) ;;
  *) exit 43 ;;
esac
[ -r "$KUBECONFIG" ] || exit 44
grep -q 'guard-proxy' "$KUBECONFIG" || exit 45
case "$*" in
  "scale deployment/revert-target --replicas=2 -n fixture")
    : > /scenario/fixtures/revert-target
    ;;
  "scale deployment/workload-maintenance --replicas=2 -n fixture")
    : > /scenario/fixtures/maintenance-applied
    ;;
  "scale deployment/workload-maintenance --replicas=1 -n fixture")
    unlink /scenario/fixtures/maintenance-applied
    ;;
  "scale deployment/access-maintenance --replicas=2 -n access-fixture")
    : > /scenario/fixtures/access-maintenance-applied
    ;;
  "scale deployment/access-maintenance --replicas=1 -n access-fixture")
    unlink /scenario/fixtures/access-maintenance-applied
    ;;
  "delete namespace access-staging")
    rmdir /scenario/fixtures/staging
    ;;
  "get pods --namespace fixture"|"get pods --namespace access-fixture")
    printf 'fixture-pod Running\n'
    ;;
  *)
    printf 'unexpected kubectl fixture command: %s\n' "$*" >&2
    exit 51
    ;;
esac
EOF
  cat > /scenario/bin/helm <<'EOF'
#!/bin/sh
printf 'fixture-release deployed\n'
EOF
  cat > /scenario/bin/ansible-playbook <<'EOF'
#!/bin/sh
[ "$(pwd)" = /scenario/ansible ] || exit 45
[ -z "${ANSIBLE_CONFIG:-}" ] || exit 46
printf 'fixture ok changed=0\n'
EOF
cat > /scenario/bin/whoami <<'EOF'
#!/bin/sh
if [ "$#" -eq 1 ] && [ "$1" = child-contract ]; then
  cap_eff="$(awk '/^CapEff:/ { print $2 }' "/proc/$$/status")"
  case "$cap_eff" in
    ''|*[1-9a-fA-F]*) exit 52 ;;
  esac
  printf 'uid=%s\ncap_eff=%s\n' "$(id -u)" "$cap_eff"
  exit 0
fi
exec /usr/bin/whoami "$@"
EOF
  cat > /scenario/bin/systemctl <<'EOF'
#!/bin/sh
[ "$#" -eq 2 ] || exit 48
[ "$1" = status ] || exit 48
[ "$2" = fixture-api.service ] || [ "$2" = access-api.service ] || exit 48
[ -n "${FIXTURE_API_TOKEN:-}" ] || exit 49
[ -r /scenario/api-contract/token.sha256 ] || exit 49
observed_digest="$(printf '%s' "$FIXTURE_API_TOKEN" | sha256sum | awk '{print $1}')"
expected_digest="$(cat /scenario/api-contract/token.sha256)"
[ "$observed_digest" = "$expected_digest" ] || exit 49
printf 'fixture-api:healthy uid=%s token=%s\n' "$(id -u)" "$FIXTURE_API_TOKEN"
EOF
  cat > /scenario/bin/novelctl <<'EOF'
#!/bin/sh
[ "$1" = status ] || exit 50
printf 'novel-diagnostic:healthy\n'
EOF
  chmod 0755 /scenario/bin/*
}

assert_protected_catalog_as_daemon() {
  local authority_owner catalog_mount_identity expected_lock root_mount_identity
  local lock_mount_identity marker replacement lock_replacement mounted_targets
  local root_mode root_owner
  echo 'synthetic catalog preflight: initial authority' >&2
  root_owner="$(stat -c '%u:%g' /)" || return 1
  root_mode="$(stat -c '%a' /)" || return 1
  [ "$root_owner" = 0:0 ] || {
    echo 'synthetic catalog preflight: root owner is not trusted' >&2
    return 1
  }
  case "$root_mode" in
    [1357][015][015]) ;;
    *)
      echo 'synthetic catalog preflight: root permissions are not trusted' >&2
      return 1
      ;;
  esac
  [ -f "$PROTECTED_CATALOG" ] || {
    echo 'synthetic catalog preflight: protected catalog is missing' >&2
    return 1
  }
  [ -r "$PROTECTED_CATALOG" ] || {
    echo 'synthetic catalog preflight: protected catalog is unreadable' >&2
    return 1
  }
  [ "$(sha256sum "$PROTECTED_CATALOG" | awk '{print $1}')" = \
    "$(sha256sum /etc/guard/verbs.yaml | awk '{print $1}')" ] || {
    echo 'synthetic catalog preflight: protected catalog digest differs' >&2
    return 1
  }
  echo 'synthetic catalog preflight: mount identities' >&2
  catalog_mount_identity="$(capture_exact_mount_identity "$PROTECTED_CATALOG_DIR" ro)" \
    || return 1
  lock_mount_identity="$(capture_exact_mount_identity "$PROTECTED_CATALOG_LOCK" rw)" \
    || return 1
  root_mount_identity="$(capture_exact_mount_identity / ro)" || return 1
  echo 'synthetic catalog preflight: mount targets' >&2
  mounted_targets="$(findmnt -rn -o TARGET | awk -v directory="$PROTECTED_CATALOG_DIR" '
    $0 == directory || index($0, directory "/") == 1 { print }
  ' | LC_ALL=C sort)"
  [ "$mounted_targets" = "$(printf '%s\n%s\n' \
    "$PROTECTED_CATALOG_DIR" "$PROTECTED_CATALOG_LOCK" | LC_ALL=C sort)" ]

  echo 'synthetic catalog preflight: ownership' >&2
  if caller_identity_scenario; then
    [ "$(id -u)" -eq 0 ]
    authority_owner=0:0
    expected_lock=0:0:600
  else
    [ "$(id -u)" -eq 1000 ]
    authority_owner=1000:1000
    expected_lock=1000:1000:600
  fi
  [ "$(stat -c '%u:%g:%a' "$PROTECTED_CATALOG_DIR")" = \
    "$authority_owner:555" ]
  [ "$(stat -c '%u:%g:%a' "$PROTECTED_CATALOG")" = \
    "$authority_owner:444" ]
  [ "$(stat -c '%u:%g:%a' "$PROTECTED_CATALOG_LOCK")" = "$expected_lock" ]

  echo 'synthetic catalog preflight: local mutation rejection' >&2
  replacement=/tmp/protected-catalog-replacement
  lock_replacement=/tmp/protected-catalog-lock-replacement
  marker=/tmp/protected-catalog-lock-marker
  printf 'replacement must not install\n' > "$replacement"
  printf 'lock replacement must not install\n' > "$lock_replacement"
  rm -f "$marker"
  if printf blocked > "$PROTECTED_CATALOG" \
    || chmod 0600 "$PROTECTED_CATALOG" \
    || rm -f "$PROTECTED_CATALOG" \
    || mv "$replacement" "$PROTECTED_CATALOG" \
    || chmod 0700 "$PROTECTED_CATALOG_DIR" \
    || mkdir "$PROTECTED_CATALOG_DIR/unauthorized" \
    || rmdir "$PROTECTED_CATALOG_DIR" \
    || mv "$PROTECTED_CATALOG_DIR" "$PROTECTED_CATALOG_DIR-replaced" \
    || mkdir "$PROTECTED_CATALOG_DIR" \
    || chmod 0700 / \
    || mkdir /authority-sibling \
    || rm -f "$PROTECTED_CATALOG_LOCK" \
    || mv "$PROTECTED_CATALOG_LOCK" "$PROTECTED_CATALOG_LOCK-replaced" \
    || mv "$lock_replacement" "$PROTECTED_CATALOG_LOCK"; then
    rm -f "$replacement" "$lock_replacement" "$marker"
    echo 'protected catalog preflight accepted an unauthorized mutation' >&2
    return 1
  fi
  [ -f "$PROTECTED_CATALOG" ]
  echo 'synthetic catalog preflight: writable coordination lock' >&2
  exec 9<>"$PROTECTED_CATALOG_LOCK"
  flock -n 9
  printf 'fixture-lock-contract\n' >&9
  grep -qx fixture-lock-contract "$PROTECTED_CATALOG_LOCK"
  : > "$PROTECTED_CATALOG_LOCK"
  printf lock-opened > "$marker"
  [ "$(cat "$marker")" = lock-opened ]
  exec 9>&-
  rm -f "$replacement" "$lock_replacement" "$marker"
  [ -f "$PROTECTED_CATALOG_LOCK" ]
  [ ! -s "$PROTECTED_CATALOG_LOCK" ]
  echo 'synthetic catalog preflight: stable mount identities' >&2
  [ "$(capture_exact_mount_identity "$PROTECTED_CATALOG_DIR" ro)" = \
    "$catalog_mount_identity" ]
  [ "$(capture_exact_mount_identity "$PROTECTED_CATALOG_LOCK" rw)" = \
    "$lock_mount_identity" ]
  [ "$(capture_exact_mount_identity / ro)" = "$root_mount_identity" ]

  # The rootfs-backed mountpoint remains immutable under every representative
  # identity reachable through CAP_SETUID. Ownership satisfies Guard's trust
  # checks; the read-only mount enforces catalog immutability.
  echo 'synthetic catalog preflight: root identity transition' >&2
  assert_catalog_mutation_rejected_after_identity_transition \
    0 0 root-identity "$catalog_mount_identity" "$lock_mount_identity" \
    "$root_mount_identity"
  echo 'synthetic catalog preflight: daemon identity transition' >&2
  assert_catalog_mutation_rejected_after_identity_transition \
    1000 1000 fixed-daemon-identity "$catalog_mount_identity" \
    "$lock_mount_identity" "$root_mount_identity"
  echo 'synthetic catalog preflight: alternate identity transition' >&2
  assert_catalog_mutation_rejected_after_identity_transition \
    65534 65534 alternate-identity "$catalog_mount_identity" \
    "$lock_mount_identity" "$root_mount_identity"
  echo 'synthetic catalog preflight: final digest' >&2
  [ "$(sha256sum "$PROTECTED_CATALOG" | awk '{print $1}')" = \
    "$(sha256sum /etc/guard/verbs.yaml | awk '{print $1}')" ]
}

capture_exact_mount_identity() {
  local target="$1" expected_access="$2" observed_target options
  observed_target="$(findmnt -n -o TARGET --target "$target")"
  [ "$observed_target" = "$target" ] || {
    echo 'protected catalog mount target is not exact' >&2
    return 1
  }
  options="$(findmnt -n -o OPTIONS --target "$target")"
  case ",$options," in
    *",$expected_access,"*) ;;
    *)
      echo 'protected catalog mount access is incorrect' >&2
      return 1
      ;;
  esac
  findmnt -n -o SOURCE,TARGET,OPTIONS --target "$target"
}

assert_catalog_mutation_rejected_after_identity_transition() {
  local target_uid="$1" target_gid="$2" label="$3"
  local expected_catalog_mount="$4" expected_lock_mount="$5" expected_root_mount="$6"
  local marker replacement lock_replacement status
  # This scratch directory is deliberately non-sticky. A transitioned child
  # can own the files it creates while the daemon identity can still perform
  # deterministic cleanup through the parent directory's write authority.
  marker="/scenario/fixtures/catalog-owner-transition-$label"
  replacement="/scenario/fixtures/catalog-owner-replacement-$label"
  lock_replacement="/scenario/fixtures/catalog-lock-owner-replacement-$label"
  rm -f "$marker" "$replacement" "$lock_replacement"
  set +e
  # The child expands these expressions after changing identity.
  # shellcheck disable=SC2016
  setpriv \
    --reuid "$target_uid" \
    --regid "$target_gid" \
    --clear-groups \
    /bin/sh -c '
      marker=$1
      replacement=$2
      lock_replacement=$3
      catalog=$4
      directory=$5
      lock=$6
      expected_catalog_mount=$7
      expected_lock_mount=$8
      target_uid=$9
      expected_root_mount=${10}
      fsuid=$(awk "/^Uid:/ { print \$5 }" /proc/self/status)
      printf "%s:%s:%s\n" "$(id -u)" "$(id -g)" "$fsuid" > "$marker" || exit 90
      [ "$(id -u)" = "$target_uid" ] && [ "$fsuid" = "$target_uid" ] || exit 90
      printf "replacement must not install\n" > "$replacement" || exit 90
      printf "lock replacement must not install\n" > "$lock_replacement" || exit 90
      if printf "blocked\n" > "$catalog" \
        || chmod 0600 "$catalog" \
        || rm -f "$catalog" \
        || mv "$replacement" "$catalog" \
        || chmod 0700 "$directory" \
        || mkdir "$directory/unauthorized" \
        || rmdir "$directory" \
        || mv "$directory" "$directory-replaced" \
        || mkdir "$directory" \
        || chmod 0700 / \
        || mkdir /authority-sibling \
        || rm -f "$lock" \
        || mv "$lock" "$lock-replaced" \
        || mv "$lock_replacement" "$lock"; then
        exit 91
      fi
      [ -d "$directory" ] && [ -f "$catalog" ] && [ -f "$lock" ] || exit 92
      [ "$(findmnt -n -o SOURCE,TARGET,OPTIONS --target "$directory")" = \
        "$expected_catalog_mount" ] || exit 93
      [ "$(findmnt -n -o SOURCE,TARGET,OPTIONS --target "$lock")" = \
        "$expected_lock_mount" ] || exit 94
      [ "$(findmnt -n -o SOURCE,TARGET,OPTIONS --target /)" = \
        "$expected_root_mount" ] || exit 95
      exit 73
    ' synthetic-catalog-owner "$marker" "$replacement" "$lock_replacement" \
    "$PROTECTED_CATALOG" "$PROTECTED_CATALOG_DIR" "$PROTECTED_CATALOG_LOCK" \
    "$expected_catalog_mount" "$expected_lock_mount" "$target_uid" \
    "$expected_root_mount" \
    2>/dev/null
  status=$?
  set -e
  [ "$status" -eq 73 ]
  [ "$(cat "$marker")" = "$target_uid:$target_gid:$target_uid" ]
  [ -f "$PROTECTED_CATALOG" ]
  [ -f "$PROTECTED_CATALOG_LOCK" ]
  rm -f "$marker" "$replacement" "$lock_replacement"
}

assert_daemon_path_contract() {
  assert_path_contract_stat() {
    local path="$1" expected="$2" label="$3" observed
    observed="$(stat -c '%u:%g:%a' "$path" 2>/dev/null || printf missing)"
    if [ "$observed" != "$expected" ]; then
      printf 'daemon path contract failed: %s expected=%s observed=%s\n' \
        "$label" "$expected" "$observed" >&2
      return 1
    fi
  }
  if caller_identity_scenario; then
    [ "$(id -u)" -eq 0 ]
    assert_path_contract_stat /scenario 0:0:711 scenario-root
    assert_path_contract_stat /scenario/home 0:0:755 daemon-home
    assert_path_contract_stat /scenario/config 0:0:755 daemon-config
    assert_path_contract_stat /scenario/data 0:0:700 daemon-state
    assert_path_contract_stat /scenario/run 0:2000:755 daemon-runtime
    assert_path_contract_stat /scenario/run/admin.token 1000:0:440 admin-token
  else
    [ "$(id -u)" -eq 1000 ]
    assert_path_contract_stat /scenario 1000:1000:711 scenario-root
    assert_path_contract_stat /scenario/home 1000:1000:755 daemon-home
    assert_path_contract_stat /scenario/config 1000:1000:755 daemon-config
    assert_path_contract_stat /scenario/data 1000:1000:700 daemon-state
    assert_path_contract_stat /scenario/run 1000:2000:755 daemon-runtime
    assert_path_contract_stat /scenario/run/admin.token 1000:0:400 admin-token
    [ ! -r "$FIXTURE_API_TOKEN_FILE" ] || {
      echo 'daemon path contract failed: API token became readable' >&2
      return 1
    }
  fi
  assert_path_contract_stat "$FIXTURE_API_AUTHORITY_DIR" 0:0:755 api-authority
  assert_path_contract_stat "$FIXTURE_API_TOKEN_FILE" 0:0:600 api-token
  assert_path_contract_stat "$FIXTURE_API_TOKEN_DIGEST_FILE" 0:0:444 api-token-digest
  [ -r "$FIXTURE_API_TOKEN_DIGEST_FILE" ] || {
    echo 'daemon path contract failed: API token digest is unreadable' >&2
    return 1
  }
  [ -r /scenario/run/admin.token ] || {
    echo 'daemon path contract failed: admin token is unreadable' >&2
    return 1
  }
  [ -w /scenario/data ] || {
    echo 'daemon path contract failed: state directory is unwritable' >&2
    return 1
  }
  [ -w /scenario/raw ] || {
    echo 'daemon path contract failed: raw evidence directory is unwritable' >&2
    return 1
  }
}

daemon() {
  setup_fixture
  rm -f "$SOCKET"
  echo 'synthetic daemon preflight: runtime path contract' >&2
  assert_daemon_path_contract
  echo 'synthetic daemon preflight: immutable catalog contract' >&2
  assert_protected_catalog_as_daemon
  echo 'synthetic daemon preflight: launching daemon' >&2
  export HOME=/scenario/home
  export XDG_CONFIG_HOME=/scenario/config
  export XDG_DATA_HOME=/scenario/data
  export PATH=/scenario/bin:/usr/local/bin:/usr/bin:/bin
  local evaluator_args=(--no-llm)
  local identity_args=(--exec-user guardexec)
  local profile_args=(
    --child-env KUBECONFIG
    --kube-proxy "$KUBE_PROXY"
    --kubeconfig "$UPSTREAM_KUBECONFIG"
    --brokered-kubeconfig-out "$BROKERED_KUBECONFIG"
  )
  export KUBECONFIG="$BROKERED_KUBECONFIG"
  if caller_identity_scenario; then
    identity_args=(--exec-as-caller)
    profile_args=()
    unset KUBECONFIG
  fi
  if [ "$SCENARIO" = SU-13 ]; then
    guard-fake-llm >>/scenario/raw/fake-llm.log 2>&1 &
    GUARD_LLM_API_KEY="$(generate_fixture_value)"
    export GUARD_LLM_API_KEY
    evaluator_args=(
      --llm
      --llm-api-url http://127.0.0.1:38473
      --llm-model fake-synthesis-model
      --llm-retries 0
    )
  fi
  exec setpriv \
    --bounding-set=-all,+setgid,+setuid \
    --inh-caps=+setgid,+setuid \
    --ambient-caps=+setgid,+setuid \
    --no-new-privs \
    guard server start \
    "${evaluator_args[@]}" \
    --gate consequence \
    --socket "$SOCKET" \
    --socket-group guard-clients \
    --verbs "$PROTECTED_CATALOG" \
    --immutable-verbs-lock "$PROTECTED_CATALOG_LOCK" \
    --state-db /scenario/data/state.db \
    --audit-log /scenario/data/audit.jsonl \
    --history-retention 3600 \
    "${identity_args[@]}" \
    "${profile_args[@]}" \
    --users 1001,1002 \
    --admin-token-stdin \
    </scenario/run/admin.token >>/scenario/raw/daemon.log 2>&1
}

record_result() {
  local outcome="$1" classification="$2" evidence="$3"
  prepare_principal_output
  {
    echo "# $SCENARIO"
    echo
    echo "- Result: $outcome"
    echo "- Classification: $classification"
    echo "- Evidence: $evidence"
    echo "- Isolation: rootless container, private daemon/socket/database/fixtures/principal/network namespace, network disabled"
    echo "- Raw transcript: retained only in the ephemeral scenario volume and removed during teardown"
  } > "$RESULT"
}

safe_error_line() {
  tail -n 1 | sed -E \
    -e 's/[0-9a-f]{32,}/[redacted-handle]/g' \
    -e 's/synthetic-[a-z-]+/[redacted-fixture]/g'
}

run_test_filter() {
  local filter="$1" matched=0 binary listing output
  for binary in /src/target/release/deps/*; do
    if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
      continue
    fi
    case "$binary" in
      *.so) continue ;;
    esac
    listing="$("$binary" --list 2>/dev/null || true)"
    printf '%s\n' "$listing" | grep -Eq '[0-9]+ tests, [0-9]+ benchmarks$' || continue
    output="$(cd "$HOME" && "$binary" "$filter" --nocapture 2>&1)" || {
      printf '%s\n' "$output" >> "$RAW"
      printf 'test filter failed: %s\n' "$filter" > "$FAILURE"
      return 1
    }
    printf '%s\n' "$output" >> "$RAW"
    if printf '%s\n' "$output" | grep -Eq 'running [1-9][0-9]* tests?|[1-9][0-9]* passed'; then
      matched=1
    fi
  done
  if [ "$matched" -ne 1 ]; then
    printf 'test filter matched no tests: %s\n' "$filter" > "$FAILURE"
  fi
  [ "$matched" -eq 1 ]
}

run_contracts() {
  case "$SCENARIO" in
    SU-01)
      run_test_filter denial_escalation_dedup_is_bound_to_session_revision
      run_test_filter cwd_request_matches_cwd_bound_exact_session_allow_only
      ;;
    SU-02) run_test_filter every_mode_requires_loop_and_unrolled_consequence_equivalence ;;
    SU-03)
      run_test_filter scoped_cache_isolates_principals_and_sessions
      run_test_filter evaluation_cache_scope_isolates_principals_and_sessions
      ;;
    SU-04) run_test_filter removed_authority_commands_cannot_mint_or_modify_sessions ;;
    SU-05) run_test_filter proxy_rejects_helm_release_secret_instead_of_returning_false_empty_state ;;
    SU-06)
      run_test_filter permission_denied_path_understands_common_error_shapes
      run_test_filter caller_env_cannot_override_daemon_child_env
      run_test_filter ansible_cwd_profile_is_rejected_before_process_start
      ;;
    SU-07)
      run_test_filter expiry_is_fail_closed_on_timer
      run_test_filter startup_recovery_marks_interrupted_exec_failed
      run_test_filter approve_executes_from_snapshot_only
      run_test_filter audit_allowed_then_exec_failed_emits_both_events
      ;;
    SU-08)
      local live_output
      run_test_filter revert_outcomes_recorded
      if ! live_output="$(cd /src && guard verb run failing-revert --confirm-within 1 --socket "$SOCKET" 2>&1)"; then
        printf '%s\n' "$live_output" >> "$RAW"
        printf 'live failing-revert verb did not enter the provisional state: %s\n' \
          "$(printf '%s\n' "$live_output" | safe_error_line)" > "$FAILURE"
        return 1
      fi
      printf '%s\n' "$live_output" >> "$RAW"
      sleep 5
      guard provisionals --json --socket "$SOCKET" >>"$RAW" 2>&1 || {
        printf 'caller could not inspect its own live provisional\n' > "$FAILURE"
        return 1
      }
      grep -q 'revert_failed' "$RAW" || {
        printf 'live failing revert did not surface revert_failed\n' > "$FAILURE"
        return 1
      }
      ;;
    SU-09) run_test_filter configured_retention_prunes_expired_interactions_on_persist ;;
    SU-10)
      local live_output
      run_test_filter legacy_and_incomplete_envelopes_get_direct_upgrade_errors
      run_test_filter local_contract_requires_supported_version_feature_and_cwd
      if ! live_output="$(guard verb run service-status --socket "$SOCKET" 2>&1)"; then
        printf '%s\n' "$live_output" >> "$RAW"
        printf 'current versioned client failed against the isolated daemon: %s\n' \
          "$(printf '%s\n' "$live_output" | safe_error_line)" > "$FAILURE"
        return 1
      fi
      printf '%s\n' "$live_output" >> "$RAW"
      ;;
    SU-11) run_test_filter secret_exposure_is_audited_only_after_successful_spawn ;;
    SU-13) return 2 ;;
    *) return 2 ;;
  esac
}

capture_phase() {
  local name="$1"
  shift
  local output status
  set +e
  output="$("$@" 2>&1)"
  status=$?
  set -e
  printf '%s\n' "$output" > "/scenario/journey/$name.out"
  printf '%s\n' "$status" > "/scenario/journey/$name.status"
  printf '%s\n' "$output" > "$PHASE_OUTPUT/$name.out"
  printf '%s\n' "$status" > "$PHASE_OUTPUT/$name.status"
  printf 'phase=%s uid=%s exit=%s\n%s\n' "$name" "$(id -u)" "$status" "$output" >> "$RAW"
  return "$status"
}

capture_stdout_phase() {
  local name="$1"
  shift
  local output status stderr_file
  stderr_file="/scenario/journey/$name.stderr"
  set +e
  output="$({ "$@"; } 2>"$stderr_file")"
  status=$?
  set -e
  printf '%s\n' "$output" > "/scenario/journey/$name.out"
  printf '%s\n' "$status" > "/scenario/journey/$name.status"
  printf '%s\n' "$output" > "$PHASE_OUTPUT/$name.out"
  printf '%s\n' "$status" > "$PHASE_OUTPUT/$name.status"
  cp "$stderr_file" "$PHASE_OUTPUT/$name.stderr"
  printf 'phase=%s uid=%s exit=%s stdout\n%s\nstderr\n%s\n' \
    "$name" "$(id -u)" "$status" "$output" "$(cat "$stderr_file")" >> "$RAW"
  return "$status"
}

capture_mcp_denial() {
  local output status
  set +e
  output="$({
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"synthetic-user","version":"1"}}}'
    printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"guard_run","arguments":{"binary":"kubectl","args":["scale","deployment/access-maintenance","--replicas=2","-n","access-fixture"]}}}'
  } | guard mcp serve --socket "$SOCKET" 2>&1)"
  status=$?
  set -e
  printf '%s\n' "$output" > /scenario/journey/maintenance-mcp.out
  printf '%s\n' "$output" > "$PHASE_OUTPUT/maintenance-mcp.out"
  printf 'phase=maintenance-mcp uid=%s exit=%s\n%s\n' "$(id -u)" "$status" "$output" >> "$RAW"
  [ "$status" -eq 0 ]
}

request_reference() {
  sed -nE 's/.*"reference": "(gr-[^"]+)".*/\1/p' "$1" | head -n 1
}

response_handle() {
  sed -nE 's/.*"handle": "([^"]+)".*/\1/p' "$1" | head -n 1
}

response_target() {
  sed -nE 's/.*"target": "(session:[^"]+)".*/\1/p' "$1" | head -n 1
}

require_request_guidance() {
  # Requester-facing guidance is audience-gated: the literal approve command
  # is operator-only, so its presence here would be an authority leak.
  local file="$1" handle="$2"
  grep -Fq "operator approval required for request $handle" "$file"
  grep -Fq "guard access show $handle" "$file"
  ! grep -Fq "guard access approve $handle" "$file"
}

require_hold_guidance() {
  local file="$1" handle="$2"
  grep -Fq "operator approval required for request $handle" "$file"
  ! grep -Fq "guard access approve $handle" "$file"
}

save_request() {
  local name="$1" intent="$2" output="/scenario/journey/$1-request.out" handle
  capture_phase "$name-request" guard access request "$intent" --json || {
    printf 'access request failed: %s-command\n' "$name" > "$FAILURE"
    return 1
  }
  handle="$(request_reference "$output")"
  if [ -z "$handle" ]; then
    printf 'access request failed: %s-reference\n' "$name" > "$FAILURE"
    return 1
  fi
  printf '%s\n' "$handle" > "/scenario/journey/$name.handle"
  require_request_guidance "$output" "$handle" || {
    printf 'access request failed: %s-guidance\n' "$name" > "$FAILURE"
    return 1
  }
}

read_handle() {
  sed -n '1p' "/scenario/journey/$1.handle"
}

expect_failure() {
  local name="$1"
  shift
  if capture_phase "$name" "$@"; then
    return 1
  fi
}

request_concurrently() {
  local name="$1" intent="$2" alternate="$3" index pid status reference references
  local -a pids=()
  for index in 1 2 3 4; do
    if [ "$((index % 2))" -eq 0 ]; then
      reference="$alternate"
    else
      reference="$intent"
    fi
    guard access request "$reference" --json \
      > "/scenario/journey/$name-$index.out" \
      2> "/scenario/journey/$name-$index.stderr" &
    pids+=("$!")
  done
  for pid in "${pids[@]}"; do
    set +e
    wait "$pid"
    status=$?
    set -e
    [ "$status" -eq 0 ]
  done
  references="$(
    for index in 1 2 3 4; do
      request_reference "/scenario/journey/$name-$index.out"
    done
  )"
  [ "$(printf '%s\n' "$references" | sed '/^$/d' | wc -l)" -eq 4 ]
  [ "$(printf '%s\n' "$references" | sed '/^$/d' | sort -u | wc -l)" -eq 1 ]
  printf '%s\n' "$(printf '%s\n' "$references" | sed -n '1p')" \
    > "/scenario/journey/$name.handle"
  printf 'phase=%s uid=%s concurrent_requests=4 unique_references=1\n' \
    "$name" "$(id -u)" >> "$RAW"
}

assert_access_decisions() {
  local file="$1"
  shift
  python3 - "$file" "$@" <<'PY'
import json
import sys

path, *expected = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    document = json.load(stream)
items = document["response"]["items"]
actual = [f"{item['request']}:{str(item['success']).lower()}" for item in items]
if actual != expected:
    raise SystemExit(f"unexpected access decisions: {actual!r}")
PY
}

assert_denied_without_execution() {
  python3 - "$@" <<'PY'
import json
import sys

for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as stream:
        document = json.load(stream)
    response = document["response"]
    assert document["type"] == "run_result", path
    assert response["allowed"] is False, path
    assert response.get("exit_code") is None, path
    assert response.get("stdout") is None, path
    assert response.get("stderr") is None, path
PY
}

PRIVATE_ROOT=/scenario/private-install
PRIVATE_SOCKET="$PRIVATE_ROOT/run/guard.sock"
PRIVATE_BROKERED_KUBECONFIG="$PRIVATE_ROOT/run/brokered.kubeconfig"
PRIVATE_KUBE_PROXY=127.0.0.1:18444

private_daemon_start() {
  local binary="$1" log_name="$2" pid ready=false
  install -d -o 1000 -g 1000 -m 0700 \
    "$PRIVATE_ROOT/home" "$PRIVATE_ROOT/config" "$PRIVATE_ROOT/data" "$PRIVATE_ROOT/log"
  install -d -o 1000 -g 2000 -m 0755 "$PRIVATE_ROOT/run"
  rm -f "$PRIVATE_SOCKET"
  HOME="$PRIVATE_ROOT/home" \
    XDG_CONFIG_HOME="$PRIVATE_ROOT/config" \
    XDG_DATA_HOME="$PRIVATE_ROOT/data" \
    PATH="/scenario/bin:/usr/local/bin:/usr/bin:/bin" \
    KUBECONFIG="$PRIVATE_BROKERED_KUBECONFIG" \
    nohup setpriv \
      --reuid 1000 \
      --regid 1000 \
      --groups 1003,2000 \
      --bounding-set=-all,+setgid,+setuid \
      --inh-caps=+setgid,+setuid \
      --ambient-caps=+setgid,+setuid \
      --no-new-privs \
      "$binary" server start \
      --no-llm \
      --gate consequence \
      --socket "$PRIVATE_SOCKET" \
      --socket-group guard-clients \
      --verbs "$PROTECTED_CATALOG" \
      --immutable-verbs-lock "$PROTECTED_CATALOG_LOCK" \
      --state-db "$PRIVATE_ROOT/data/state.db" \
      --audit-log "$PRIVATE_ROOT/data/audit.jsonl" \
      --history-retention 3600 \
      --exec-user guardexec \
      --child-env KUBECONFIG \
      --kube-proxy "$PRIVATE_KUBE_PROXY" \
      --kubeconfig "$UPSTREAM_KUBECONFIG" \
      --brokered-kubeconfig-out "$PRIVATE_BROKERED_KUBECONFIG" \
      --users 1001,1002 \
      --admin-token-stdin \
      > "$PRIVATE_ROOT/log/$log_name.log" 2>&1 < /scenario/run/admin.token &
  pid=$!
  printf '%s\n' "$pid" > "$PRIVATE_ROOT/run/daemon.pid"
  for _ in $(seq 1 100); do
    if [ -S "$PRIVATE_SOCKET" ] && kill -0 "$pid" 2>/dev/null; then
      ready=true
      break
    fi
    sleep 0.1
  done
  if [ "$ready" != true ]; then
    if kill -0 "$pid" 2>/dev/null; then
      printf 'private daemon failed: %s-socket-readiness\n' "$log_name" > "$FAILURE"
    else
      printf 'private daemon failed: %s-process-exit\n' "$log_name" > "$FAILURE"
    fi
    return 1
  fi
  if [ "$(stat -c '%a:%G' "$PRIVATE_SOCKET")" != 660:guard-clients ]; then
    printf 'private daemon failed: %s-socket-contract\n' "$log_name" > "$FAILURE"
    return 1
  fi
  if [ "$(awk '/^CapEff:/ { value = tolower($2); sub(/^0+/, "", value); print value == "" ? "0" : value }' "/proc/$pid/status")" != c0 ]; then
    printf 'private daemon failed: %s-capability-contract\n' "$log_name" > "$FAILURE"
    return 1
  fi
}

private_daemon_stop() {
  local pid state stopped=false
  pid="$(sed -n '1p' "$PRIVATE_ROOT/run/daemon.pid")"
  kill "$pid"
  for _ in $(seq 1 100); do
    if ! kill -0 "$pid" 2>/dev/null; then
      stopped=true
      break
    fi
    state="$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)"
    if [ "$state" = Z ]; then
      stopped=true
      break
    fi
    sleep 0.1
  done
  [ "$stopped" = true ]
  rm -f "$PRIVATE_ROOT/run/daemon.pid" "$PRIVATE_SOCKET"
}

private_guard() {
  GUARD_SOCKET="$PRIVATE_SOCKET" guard "$@"
}

phase_su13() {
  local phase="$1" handle session
  case "$phase" in
    request)
      [ "$(id -u)" -eq 1001 ]
      sha256sum "$PROTECTED_CATALOG" | awk '{print $1}' > /scenario/journey/catalog.before
      save_request synthesized 'Run the isolated novel diagnostic'
      grep -q 'novelctl' /scenario/journey/synthesized-request.out
      ;;
    approve)
      [ "$(id -u)" -eq 1000 ]
      handle="$(read_handle synthesized)"
      capture_phase synthesized-approve guard access approve "$handle" --json
      grep -q '"success": true' /scenario/journey/synthesized-approve.out
      session="$(response_target /scenario/journey/synthesized-approve.out)"
      [ -n "$session" ]
      printf '%s\n' "$session" > /scenario/journey/synthesized.session
      ;;
    use)
      [ "$(id -u)" -eq 1001 ]
      expect_failure synthesized-first guard run --json novelctl status
      [ "$(cat /scenario/journey/synthesized-first.status)" -eq 127 ]
      handle="$(response_handle /scenario/journey/synthesized-first.out)"
      [ -n "$handle" ]
      printf '%s\n' "$handle" > /scenario/journey/synthesized-execution.handle
      require_hold_guidance /scenario/journey/synthesized-first.out "$handle"
      ! grep -q 'novel-diagnostic:healthy' /scenario/journey/synthesized-first.out
      ;;
    approve-execution)
      [ "$(id -u)" -eq 1000 ]
      handle="$(read_handle synthesized-execution)"
      capture_phase synthesized-execution-approve \
        guard access approve "$handle" --once --json
      grep -q '"success": true' /scenario/journey/synthesized-execution-approve.out
      grep -q '"state": "armed"' /scenario/journey/synthesized-execution-approve.out
      ! grep -q 'novel-diagnostic:healthy' /scenario/journey/synthesized-execution-approve.out
      ;;
    resume-execution)
      [ "$(id -u)" -eq 1001 ]
      handle="$(read_handle synthesized-execution)"
      capture_phase synthesized-execution-resume guard resume "$handle" --json
      grep -q '"type": "resume_result"' /scenario/journey/synthesized-execution-resume.out
      grep -q '"exit_code": 0' /scenario/journey/synthesized-execution-resume.out
      grep -q 'novel-diagnostic:healthy' /scenario/journey/synthesized-execution-resume.out
      ;;
    isolate)
      [ "$(id -u)" -eq 1002 ]
      session="$(sed -n '1p' /scenario/journey/synthesized.session)"
      expect_failure synthesized-replay guard access show "$session" --json
      expect_failure synthesized-cross-principal guard run --json novelctl status
      ;;
    after-restart)
      [ "$(id -u)" -eq 1001 ]
      expect_failure synthesized-restored guard run --json novelctl status
      [ "$(cat /scenario/journey/synthesized-restored.status)" -eq 127 ]
      handle="$(response_handle /scenario/journey/synthesized-restored.out)"
      [ -n "$handle" ]
      printf '%s\n' "$handle" > /scenario/journey/synthesized-restored.handle
      require_hold_guidance /scenario/journey/synthesized-restored.out "$handle"
      ;;
    revoke)
      [ "$(id -u)" -eq 1000 ]
      session="$(sed -n '1p' /scenario/journey/synthesized.session)"
      capture_phase synthesized-revoke guard access revoke "$session" --json
      grep -q '"state": "revoked"' /scenario/journey/synthesized-revoke.out
      handle="$(read_handle synthesized-restored)"
      expect_failure synthesized-revoked-hold-approve \
        guard access approve "$handle" --once --json
      grep -q '"success": false' /scenario/journey/synthesized-revoked-hold-approve.out
      grep -q '"state": "denied"' /scenario/journey/synthesized-revoked-hold-approve.out
      capture_phase synthesized-revoked-hold-show guard access show "$handle" --json
      grep -q '"state": "denied"' /scenario/journey/synthesized-revoked-hold-show.out
      grep -q 'originating access session was revoked' \
        /scenario/journey/synthesized-revoked-hold-show.out
      ;;
    after-revoke)
      [ "$(id -u)" -eq 1001 ]
      expect_failure synthesized-revoked guard run --json novelctl status
      ! grep -q 'novel-diagnostic:healthy' /scenario/journey/synthesized-revoked.out
      ;;
    verify)
      [ "$(id -u)" -eq 1000 ]
      sha256sum "$PROTECTED_CATALOG" | awk '{print $1}' > /scenario/journey/catalog.after
      cmp /scenario/journey/catalog.before /scenario/journey/catalog.after
      run_test_filter synthesized_verbs_default_to_session_scope
      run_test_filter legacy_session_revision_fixture_is_stable
      record_result passed 'intended policy' \
        'live prose synthesis stayed inert until access, operator arming, and requester resume; it remained principal-scoped across restart, left the operator catalog unchanged, and failed closed after revoke'
      ;;
    *) return 2 ;;
  esac
}

phase_su14() {
  local phase="$1" handle retry other session bearer replay_handle
  case "$phase" in
    request)
      [ "$(id -u)" -eq 1001 ]
      save_request owner 'Inspect the fake service'
      handle="$(read_handle owner)"
      capture_phase owner-retry guard access request '  Inspect   the fake service  ' --json
      retry="$(request_reference /scenario/journey/owner-retry.out)"
      [ "$retry" = "$handle" ]
      ;;
    approve)
      [ "$(id -u)" -eq 1000 ]
      handle="$(read_handle owner)"
      capture_phase owner-approve guard access approve "$handle" --once --json
      grep -q '"success": true' /scenario/journey/owner-approve.out
      grep -q '"remaining_uses": 1' /scenario/journey/owner-approve.out
      session="$(response_target /scenario/journey/owner-approve.out)"
      [ -n "$session" ]
      printf '%s\n' "$session" > /scenario/journey/owner.session
      bearer="$(python3 - <<'PY'
import sqlite3

with sqlite3.connect("/scenario/data/state.db") as connection:
    rows = connection.execute(
        "SELECT token FROM session_grants WHERE scope_json LIKE '%\"access_managed\":true%'"
    ).fetchall()
if len(rows) != 1:
    raise SystemExit("expected one access-managed fixture session")
print(rows[0][0])
PY
)"
      [ -n "$bearer" ]
      printf '%s\n' "$bearer" > /scenario/journey/exposed-owner.bearer
      chmod 0644 /scenario/journey/exposed-owner.bearer
      ;;
    replay)
      [ "$(id -u)" -eq 1002 ]
      handle="$(read_handle owner)"
      expect_failure replay-request guard access show "$handle" --json
      session="$(sed -n '1p' /scenario/journey/owner.session)"
      expect_failure replay-session guard access show "$session" --json
      bearer="$(sed -n '1p' /scenario/journey/exposed-owner.bearer)"
      export GUARD_SESSION="$bearer"
      expect_failure replay-bearer guard run --json helm list --namespace access-fixture
      grep -q '"allowed": false' /scenario/journey/replay-bearer.out
      replay_handle="$(response_handle /scenario/journey/replay-bearer.out)"
      [ -n "$replay_handle" ]
      [ "$replay_handle" != "$handle" ]
      ! grep -q 'fixture-release' /scenario/journey/replay-bearer.out
      unset GUARD_SESSION
      save_request other 'Inspect the fake service'
      other="$(read_handle other)"
      [ "$other" != "$handle" ]
      ;;
    consume)
      [ "$(id -u)" -eq 1001 ]
      capture_phase owner-consume guard run --json printf 'fixture-service:active\n'
      grep -q 'fixture-service:active' /scenario/journey/owner-consume.out
      expect_failure owner-exhausted guard run --json printf 'fixture-service:active\n'
      grep -q 'use limit is exhausted' /scenario/journey/owner-exhausted.out
      ;;
    after-restart)
      [ "$(id -u)" -eq 1001 ]
      expect_failure owner-restart-exhausted guard run --json printf 'fixture-service:active\n'
      grep -q 'use limit is exhausted' /scenario/journey/owner-restart-exhausted.out
      ;;
    verify)
      [ "$(id -u)" -eq 1000 ]
      capture_phase owner-final-list guard access list --json
      grep -q '"remaining_uses": 0' /scenario/journey/owner-final-list.out
      run_test_filter access_request_is_principal_bound_coalesced_batched_and_bounded
      record_result passed 'intended policy' \
        'real agent, operator, valid bearer replay, and request-reference replay remained principal-bound across approval, exhaustion, persistence, and daemon restart'
      ;;
    *) return 2 ;;
  esac
}

phase_su15() {
  local phase="$1" maintenance delete denied_handle retry_handle hold denied_hold
  local approved_snapshot_count approved_claim_count approved_completion_count denied_execution_count
  case "$phase" in
    deny)
      [ "$(id -u)" -eq 1001 ]
      expect_failure maintenance-denied guard run --json kubectl scale deployment/access-maintenance --replicas=2 -n access-fixture
      denied_handle="$(response_handle /scenario/journey/maintenance-denied.out)"
      [ -n "$denied_handle" ]
      printf '%s\n' "$denied_handle" > /scenario/journey/maintenance.handle
      require_request_guidance /scenario/journey/maintenance-denied.out "$denied_handle"
      capture_mcp_denial
      grep -Fq '"allowed":false' /scenario/journey/maintenance-mcp.out
      grep -Fq "operator approval required for request $denied_handle" /scenario/journey/maintenance-mcp.out
      ! grep -Fq "guard access approve $denied_handle" /scenario/journey/maintenance-mcp.out
      grep -Fq "guard access show $denied_handle" /scenario/journey/maintenance-mcp.out
      expect_failure maintenance-retry guard run --json kubectl scale deployment/access-maintenance --replicas=2 -n access-fixture
      retry_handle="$(response_handle /scenario/journey/maintenance-retry.out)"
      [ "$retry_handle" = "$denied_handle" ]
      save_request delete 'Delete the fake staging tree'
      ;;
    approve)
      [ "$(id -u)" -eq 1000 ]
      maintenance="$(read_handle maintenance)"
      delete="$(read_handle delete)"
      capture_phase access-ordinary-approve guard access approve "$maintenance" "$delete" --json
      [ "$(grep -c '"success": true' /scenario/journey/access-ordinary-approve.out)" -eq 2 ]
      ;;
    hold)
      [ "$(id -u)" -eq 1001 ]
      capture_phase maintenance-provisional guard run --json kubectl scale deployment/access-maintenance --replicas=2 -n access-fixture
      grep -q '"status": "provisional"' /scenario/journey/maintenance-provisional.out
      expect_failure delete-held guard run --json kubectl delete namespace access-staging
      grep -q '"status": "held"' /scenario/journey/delete-held.out
      hold="$(response_handle /scenario/journey/delete-held.out)"
      [ -n "$hold" ]
      printf '%s\n' "$hold" > /scenario/journey/hold.handle
      require_hold_guidance /scenario/journey/delete-held.out "$hold"
      expect_failure denied-held guard run --json kubectl delete namespace denied-staging
      grep -q '"status": "held"' /scenario/journey/denied-held.out
      denied_hold="$(response_handle /scenario/journey/denied-held.out)"
      [ -n "$denied_hold" ]
      [ "$denied_hold" != "$hold" ]
      printf '%s\n' "$denied_hold" > /scenario/journey/denied-hold.handle
      require_hold_guidance /scenario/journey/denied-held.out "$denied_hold"
      [ -d /scenario/fixtures/staging ]
      ;;
    approve-held)
      [ "$(id -u)" -eq 1000 ]
      hold="$(read_handle hold)"
      capture_phase approve-held guard access approve "$hold" --once --json
      grep -q '"success": true' /scenario/journey/approve-held.out
      grep -q '"state": "armed"' /scenario/journey/approve-held.out
      [ -d /scenario/fixtures/staging ]
      ;;
    resume-held)
      [ "$(id -u)" -eq 1001 ]
      hold="$(read_handle hold)"
      capture_phase resume-held guard resume "$hold" --json
      grep -q '"type": "resume_result"' /scenario/journey/resume-held.out
      grep -q '"exit_code": 0' /scenario/journey/resume-held.out
      [ ! -d /scenario/fixtures/staging ]
      ;;
    verify)
      [ "$(id -u)" -eq 1000 ]
      hold="$(read_handle hold)"
      approved_snapshot_count="$(awk -v handle="$hold" \
        'index($0, "\"kind\":\"APPROVED\"") && index($0, "\"handle\":\"" handle "\"") && index($0, "\"cmd\":\"kubectl delete namespace access-staging\"") { count++ } END { print count + 0 }' \
        /scenario/data/audit.jsonl)"
      [ "$approved_snapshot_count" -eq 1 ]
      approved_claim_count="$(awk -v handle="$hold" \
        'index($0, "\"kind\":\"APPROVED_EXECUTED\"") && index($0, "\"handle\":\"" handle "\"") && index($0, "[\"phase\",\"requester_claimed\"]") { count++ } END { print count + 0 }' \
        /scenario/data/audit.jsonl)"
      [ "$approved_claim_count" -eq 1 ]
      approved_completion_count="$(awk -v handle="$hold" \
        'index($0, "\"kind\":\"APPROVED_EXECUTED\"") && index($0, "\"handle\":\"" handle "\"") && index($0, "[\"phase\",\"completed\"]") { count++ } END { print count + 0 }' \
        /scenario/data/audit.jsonl)"
      [ "$approved_completion_count" -eq 1 ]
      expect_failure replay-held guard access approve "$hold" --once --json
      approved_claim_count="$(awk -v handle="$hold" \
        'index($0, "\"kind\":\"APPROVED_EXECUTED\"") && index($0, "\"handle\":\"" handle "\"") && index($0, "[\"phase\",\"requester_claimed\"]") { count++ } END { print count + 0 }' \
        /scenario/data/audit.jsonl)"
      [ "$approved_claim_count" -eq 1 ]
      approved_completion_count="$(awk -v handle="$hold" \
        'index($0, "\"kind\":\"APPROVED_EXECUTED\"") && index($0, "\"handle\":\"" handle "\"") && index($0, "[\"phase\",\"completed\"]") { count++ } END { print count + 0 }' \
        /scenario/data/audit.jsonl)"
      [ "$approved_completion_count" -eq 1 ]
      denied_hold="$(read_handle denied-hold)"
      capture_phase deny-held guard access deny "$denied_hold" --reason 'fixture remains protected' --json
      grep -q '"state": "denied"' /scenario/journey/deny-held.out
      denied_execution_count="$(awk -v handle="$denied_hold" \
        'index($0, "\"kind\":\"APPROVED_EXECUTED\"") && index($0, "\"handle\":\"" handle "\"") { count++ } END { print count + 0 }' \
        /scenario/data/audit.jsonl)"
      [ "$denied_execution_count" -eq 0 ]
      run_test_filter sessionless_denied_typed_command_returns_access_request_guidance
      run_test_filter structured_guidance_preserves_access_commands_and_coverage_detail
      run_test_filter held_tool_text_returns_exact_access_commands
      record_result passed 'intended policy' \
        'one immutable held snapshot was armed with --once and resumed exactly once by its requester; a separate hold was denied without execution; denied, provisional, and structured results retained durable identifiers and exact operator commands'
      ;;
    *) return 2 ;;
  esac
}

phase_su16() {
  local phase="$1" kube_request missing_request command_request cloud_request file_request helm_request ansible_request api_request
  case "$phase" in
    request-primary)
      [ "$(id -u)" -eq 1001 ]
      save_request ssh 'Inspect the fake service'
      save_request kube 'Inspect the fake Kubernetes pods'
      save_request missing 'Run the failing fake command'
      save_request command 'Run the fake bounded command'
      save_request cloud 'Inspect the fake CloudStack virtual machines'
      save_request file 'Read the fake operator file'
      save_request ansible 'Check the fake Ansible project'
      save_request api 'Query the fake credential-backed API'
      ;;
    request-secondary)
      [ "$(id -u)" -eq 1002 ]
      save_request helm 'Inspect the fake Helm releases'
      ;;
    approve-primary-scope)
      [ "$(id -u)" -eq 1000 ]
      capture_phase approve-ordinary guard access approve "$(read_handle ssh)" --json
      grep -q '"success": true' /scenario/journey/approve-ordinary.out
      ;;
    reject-primary-cross-scope)
      [ "$(id -u)" -eq 1001 ]
      capture_phase service-before-other-approvals guard run --json printf 'fixture-service:active\n'
      grep -q 'fixture-service:active' /scenario/journey/service-before-other-approvals.out
      expect_failure cross-kube guard run --json kubectl get pods --namespace access-fixture
      [ "$(response_handle /scenario/journey/cross-kube.out)" = "$(read_handle kube)" ]
      expect_failure cross-command guard run --json printf 'bounded-command-complete\n'
      [ "$(response_handle /scenario/journey/cross-command.out)" = "$(read_handle command)" ]
      expect_failure cross-cloud guard run --json printf 'fixture-vm Running\n'
      [ "$(response_handle /scenario/journey/cross-cloud.out)" = "$(read_handle cloud)" ]
      expect_failure cross-file guard run --json cat "$PROTECTED_OPERATOR_NOTE"
      [ "$(response_handle /scenario/journey/cross-file.out)" = "$(read_handle file)" ]
      (cd /scenario/ansible && expect_failure cross-ansible guard run --json ansible-playbook /scenario/ansible/site.yml --check --diff --limit access-fixture)
      [ "$(response_handle /scenario/journey/cross-ansible.out)" = "$(read_handle ansible)" ]
      expect_failure cross-api guard run --json systemctl status access-api.service
      [ "$(response_handle /scenario/journey/cross-api.out)" = "$(read_handle api)" ]
      assert_denied_without_execution /scenario/journey/cross-*.out
      ;;
    reject-secondary-cross-scope)
      [ "$(id -u)" -eq 1002 ]
      expect_failure secondary-cross-service guard run --json printf 'fixture-service:active\n'
      ! grep -q 'fixture-service:active' /scenario/journey/secondary-cross-service.out
      expect_failure secondary-helm-before-approval guard run --json helm list --namespace access-fixture
      [ "$(response_handle /scenario/journey/secondary-helm-before-approval.out)" = "$(read_handle helm)" ]
      ;;
    approve-batch)
      [ "$(id -u)" -eq 1000 ]
      kube_request="$(read_handle kube)"
      missing_request="$(read_handle missing)"
      command_request="$(read_handle command)"
      cloud_request="$(read_handle cloud)"
      file_request="$(read_handle file)"
      ansible_request="$(read_handle ansible)"
      api_request="$(read_handle api)"
      helm_request="$(read_handle helm)"
      capture_phase approve-once guard access approve "$kube_request" --once --json
      capture_phase approve-failed-exit guard access approve "$missing_request" --once --json
      capture_phase approve-n-use guard access approve "$command_request" --uses 2 --json
      expect_failure approve-multiple-partial guard access approve "$cloud_request" "$file_request" missing-request --json
      [ "$(grep -c '"success": true' /scenario/journey/approve-multiple-partial.out)" -eq 2 ]
      grep -q '"success": false' /scenario/journey/approve-multiple-partial.out
      capture_phase approve-secondary guard access approve "$helm_request" --json
      capture_phase approve-additional guard access approve "$ansible_request" "$api_request" --json
      [ "$(grep -c '"success": true' /scenario/journey/approve-additional.out)" -eq 2 ]
      ;;
    consume-secondary)
      [ "$(id -u)" -eq 1002 ]
      expect_failure helm-first guard run --json helm list --namespace access-fixture
      grep -Eq 'fixed-identity|shared child UID' /scenario/journey/helm-first.out
      ! grep -q 'fixture-release' /scenario/journey/helm-first.out
      expect_failure helm-second guard run --json helm list --namespace access-fixture
      grep -Eq 'fixed-identity|shared child UID' /scenario/journey/helm-second.out
      ;;
    race-and-fail)
      [ "$(id -u)" -eq 1001 ]
      set +e
      guard run --json kubectl get pods --namespace access-fixture > /scenario/journey/race-a.out 2>&1 &
      local first_pid=$!
      guard run --json kubectl get pods --namespace access-fixture > /scenario/journey/race-b.out 2>&1 &
      local second_pid=$!
      wait "$first_pid"; local first_status=$?
      wait "$second_pid"; local second_status=$?
      set -e
      printf 'phase=race uid=%s exits=%s,%s\n' "$(id -u)" "$first_status" "$second_status" >> "$RAW"
      [ "$(( (first_status == 0) + (second_status == 0) ))" -eq 1 ]
      expect_failure missing-first guard run --json false
      grep -Eq '"exit_code":[[:space:]]*1' /scenario/journey/missing-first.out
      expect_failure missing-second guard run --json false
      grep -q 'use limit is exhausted' /scenario/journey/missing-second.out
      capture_phase command-first guard run --json printf 'bounded-command-complete\n'
      grep -q 'bounded-command-complete' /scenario/journey/command-first.out
      capture_phase service-first guard run --json printf 'fixture-service:active\n'
      capture_phase service-second guard run --json printf 'fixture-service:active\n'
      ;;
    after-restart)
      [ "$(id -u)" -eq 1001 ]
      capture_phase command-second guard run --json printf 'bounded-command-complete\n'
      expect_failure command-third guard run --json printf 'bounded-command-complete\n'
      grep -q 'use limit is exhausted' /scenario/journey/command-third.out
      capture_phase cloud-use guard run --json printf 'fixture-vm Running\n'
      capture_phase file-use guard run --json cat "$PROTECTED_OPERATOR_NOTE"
      (cd /scenario/ansible && expect_failure ansible-use guard run --json ansible-playbook /scenario/ansible/site.yml --check --diff --limit access-fixture)
      grep -Eq 'fixed-identity|shared child UID' /scenario/journey/ansible-use.out
      ! grep -q 'changed=0' /scenario/journey/ansible-use.out
      expect_failure api-use guard run --json systemctl status access-api.service
      grep -q 'fixed-identity execution cannot receive tool-config credentials' \
        /scenario/journey/api-use.out
      ! grep -q 'fixture-api:healthy' /scenario/journey/api-use.out
      ;;
    verify)
      [ "$(id -u)" -eq 1000 ]
      capture_phase batch-final-list guard access list --json
      run_test_filter access_request_is_principal_bound_coalesced_batched_and_bounded
      record_result passed 'intended policy' \
        'ordinary, one-time, N-use, multi-request, replay, cross-system denial, last-use race, failed execution, restart, partial-failure, and post-approval profile-boundary paths preserved independent authority'
      ;;
    *) return 2 ;;
  esac
}

phase_su17() {
  local phase="$1" handle session extension retry
  case "$phase" in
    request)
      [ "$(id -u)" -eq 1001 ]
      save_request initial 'Inspect the fake service'
      ;;
    approve-and-extend)
      [ "$(id -u)" -eq 1000 ]
      handle="$(read_handle initial)"
      capture_phase initial-approve guard access approve "$handle" --json
      session="$(response_target /scenario/journey/initial-approve.out)"
      [ -n "$session" ]
      printf '%s\n' "$session" > /scenario/journey/extend.session
      capture_phase extend-first guard access extend "$session" 'Inspect the fake Kubernetes pods' --once --json
      extension="$(sed -nE 's/.*"request": "(gr-[^"]+)".*/\1/p' /scenario/journey/extend-first.out | head -n 1)"
      [ -n "$extension" ]
      printf '%s\n' "$extension" > /scenario/journey/extension.handle
      capture_phase extend-retry guard access extend "$session" '  Inspect   the fake Kubernetes pods ' --once --json
      retry="$(sed -nE 's/.*"request": "(gr-[^"]+)".*/\1/p' /scenario/journey/extend-retry.out | head -n 1)"
      [ "$retry" = "$extension" ]
      ;;
    consume-extension)
      [ "$(id -u)" -eq 1001 ]
      capture_phase extension-consume guard run --json kubectl get pods --namespace access-fixture
      expect_failure extension-exhausted guard run --json kubectl get pods --namespace access-fixture
      grep -q 'use limit is exhausted' /scenario/journey/extension-exhausted.out
      capture_phase original-still-active guard run --json printf 'fixture-service:active\n'
      ;;
    retry-extension)
      [ "$(id -u)" -eq 1000 ]
      session="$(sed -n '1p' /scenario/journey/extend.session)"
      capture_phase extend-after-use guard access extend "$session" 'Inspect the fake Kubernetes pods' --once --json
      grep -q '"remaining_uses": 0' /scenario/journey/extend-after-use.out
      capture_phase extend-maintenance guard access extend "$session" 'Apply the fake workload maintenance operation' --json
      extension="$(sed -nE 's/.*"request": "(gr-[^"]+)".*/\1/p' /scenario/journey/extend-maintenance.out | head -n 1)"
      [ -n "$extension" ]
      printf '%s\n' "$extension" > /scenario/journey/maintenance-extension.handle
      ;;
    consume-maintenance)
      [ "$(id -u)" -eq 1001 ]
      capture_phase maintenance-contained guard run --json --confirm-within 1 kubectl scale deployment/access-maintenance --replicas=2 -n access-fixture
      grep -q '"status": "provisional"' /scenario/journey/maintenance-contained.out
      [ -f /scenario/fixtures/access-maintenance-applied ]
      sleep 5
      [ ! -e /scenario/fixtures/access-maintenance-applied ]
      ;;
    verify)
      [ "$(id -u)" -eq 1000 ]
      capture_phase extension-final-list guard access list --json
      [ "$(grep -c '"kind": "session"' /scenario/journey/extension-final-list.out)" -eq 1 ]
      extension="$(read_handle maintenance-extension)"
      capture_phase maintenance-extension-show guard access show "$extension" --json
      grep -q '"verb": "access-workload-maintenance"' /scenario/journey/maintenance-extension-show.out
      grep -q '"has_revert": true' /scenario/journey/maintenance-extension-show.out
      run_test_filter access_request_is_principal_bound_coalesced_batched_and_bounded
      record_result passed 'intended policy' \
        'stable-target extension reused typed authority, stored the missing delta, retained gates and reverts, and did not refill a consumed budget'
      ;;
    *) return 2 ;;
  esac
}

phase_su18() {
  local phase="$1" before after handle session
  case "$phase" in
    help-and-request)
      [ "$(id -u)" -eq 1001 ]
      capture_phase before-help guard access list --json
      before="$(sha256sum /scenario/journey/before-help.out | cut -d' ' -f1)"
      capture_stdout_phase bare-help guard
      [ "$(cat /scenario/journey/bare-help.status)" -eq 0 ]
      capture_stdout_phase access-help guard access
      [ "$(cat /scenario/journey/access-help.status)" -eq 0 ]
      capture_stdout_phase explicit-help guard access --help
      [ "$(cat /scenario/journey/explicit-help.status)" -eq 0 ]
      capture_phase after-help guard access list --json
      after="$(sha256sum /scenario/journey/after-help.out | cut -d' ' -f1)"
      [ "$before" = "$after" ]
      grep -q 'access request' /scenario/journey/bare-help.out
      grep -q 'access approve' /scenario/journey/access-help.out
      grep -q -- '--uses 3' /scenario/journey/explicit-help.out
      save_request inspect 'Run the fake bounded command'
      handle="$(read_handle inspect)"
      capture_phase agent-list-human guard access list
      capture_phase agent-list-json guard access list --json
      capture_phase agent-show-human guard access show "$handle"
      capture_phase agent-show-json guard access show "$handle" --json
      grep -q '"schema_version": 1' /scenario/journey/agent-list-json.out
      ;;
    inspect)
      [ "$(id -u)" -eq 1000 ]
      handle="$(read_handle inspect)"
      capture_phase operator-list-human guard access list
      capture_phase operator-list-json guard access list --json
      capture_phase operator-show-json guard access show "$handle" --json
      [ "$(wc -l < /scenario/journey/operator-list-human.out)" -le 4 ]
      capture_phase expiry-approve guard access approve "$handle" --uses 2 --json
      session="$(response_target /scenario/journey/expiry-approve.out)"
      [ -n "$session" ]
      printf '%s\n' "$session" > /scenario/journey/expiry.session
      ;;
    consume-before-expiry)
      [ "$(id -u)" -eq 1001 ]
      capture_phase expiry-first-use guard run --json printf 'bounded-command-complete\n'
      grep -q 'bounded-command-complete' /scenario/journey/expiry-first-use.out
      ;;
    after-expiry)
      [ "$(id -u)" -eq 1001 ]
      expect_failure expiry-denied guard run --json printf 'bounded-command-complete\n'
      capture_phase expiry-list guard access list --json
      ! grep -q '"kind": "session"' /scenario/journey/expiry-list.out
      save_request revocable 'Read the fake operator file'
      ;;
    revoke)
      [ "$(id -u)" -eq 1000 ]
      handle="$(read_handle revocable)"
      capture_phase revoke-approve guard access approve "$handle" --json
      session="$(response_target /scenario/journey/revoke-approve.out)"
      [ -n "$session" ]
      capture_phase revoke-session guard access revoke "$session" --json
      grep -q '"state": "revoked"' /scenario/journey/revoke-session.out
      ;;
    after-revoke)
      [ "$(id -u)" -eq 1001 ]
      expect_failure revoked-denied guard run --json cat "$PROTECTED_OPERATOR_NOTE"
      ;;
    verify)
      [ "$(id -u)" -eq 1000 ]
      capture_phase final-operator-list guard access list --json
      run_test_filter bare_access_is_non_mutating_help
      record_result passed 'intended policy' \
        'bare help stayed non-mutating; compact inspection, bounded expiry, explicit revoke, restart, and schema-versioned JSON preserved principal-scoped authority'
      ;;
    *) return 2 ;;
  esac
}

phase_su19() {
  local phase="$1" stale='gr-00000000000000000000000000000000'
  local primary_command primary_file secondary_file fresh
  case "$phase" in
    request-primary)
      [ "$(id -u)" -eq 1001 ]
      request_concurrently primary-command \
        'Run the fake bounded command' '  Run   the fake bounded command  '
      request_concurrently primary-file \
        'Read the fake operator file' ' Read  the fake operator file '
      [ "$(read_handle primary-command)" != "$(read_handle primary-file)" ]
      ;;
    request-secondary)
      [ "$(id -u)" -eq 1002 ]
      request_concurrently secondary-command \
        'Run the fake bounded command' ' Run   the fake bounded command '
      request_concurrently secondary-file \
        'Read the fake operator file' '  Read the fake operator file  '
      [ "$(read_handle secondary-command)" != "$(read_handle secondary-file)" ]
      [ "$(read_handle primary-command)" != "$(read_handle secondary-command)" ]
      [ "$(read_handle primary-file)" != "$(read_handle secondary-file)" ]
      ;;
    decide)
      [ "$(id -u)" -eq 1000 ]
      primary_command="$(read_handle primary-command)"
      primary_file="$(read_handle primary-file)"
      secondary_file="$(read_handle secondary-file)"
      capture_phase deny-primary-file guard access deny "$primary_file" \
        --reason 'this principal does not need file inspection' --json
      grep -q '"state": "denied"' /scenario/journey/deny-primary-file.out
      if capture_stdout_phase mixed-partial guard access approve \
        "$stale" "$primary_command" "$secondary_file" --uses 3 --json; then
        return 1
      fi
      [ "$(cat /scenario/journey/mixed-partial.status)" -eq 1 ]
      [ ! -s /scenario/journey/mixed-partial.stderr ]
      assert_access_decisions /scenario/journey/mixed-partial.out \
        "$stale:false" "$primary_command:true" "$secondary_file:true"
      ;;
    use-primary)
      [ "$(id -u)" -eq 1001 ]
      capture_phase primary-command-use guard run --json printf 'bounded-command-complete\n'
      grep -q 'bounded-command-complete' /scenario/journey/primary-command-use.out
      expect_failure primary-file-denied guard run --json cat "$PROTECTED_OPERATOR_NOTE"
      fresh="$(response_handle /scenario/journey/primary-file-denied.out)"
      [ -n "$fresh" ]
      [ "$fresh" != "$(read_handle primary-file)" ]
      printf '%s\n' "$fresh" > /scenario/journey/primary-file-fresh.handle
      ;;
    use-secondary)
      [ "$(id -u)" -eq 1002 ]
      capture_phase secondary-file-use guard run --json cat "$PROTECTED_OPERATOR_NOTE"
      grep -q 'synthetic operator note' /scenario/journey/secondary-file-use.out
      expect_failure secondary-command-pending guard run --json printf 'bounded-command-complete\n'
      fresh="$(response_handle /scenario/journey/secondary-command-pending.out)"
      [ -n "$fresh" ]
      [ "$fresh" = "$(read_handle secondary-command)" ]
      ;;
    verify)
      [ "$(id -u)" -eq 1000 ]
      primary_command="$(read_handle primary-command)"
      secondary_file="$(read_handle secondary-file)"
      capture_phase primary-command-show guard access show "$primary_command" --json
      capture_phase secondary-file-show guard access show "$secondary_file" --json
      grep -q '"remaining_uses": 2' /scenario/journey/primary-command-show.out
      grep -q '"remaining_uses": 2' /scenario/journey/secondary-file-show.out
      capture_phase pending-secondary-command guard access show \
        "$(read_handle secondary-command)" --json
      grep -q '"state": "pending"' /scenario/journey/pending-secondary-command.out
      capture_phase concurrent-final-list guard access list --json
      [ "$(grep -c '"kind": "session"' /scenario/journey/concurrent-final-list.out)" -eq 2 ]
      record_result passed 'intended policy' \
        'concurrent retries converged within each principal and system, references stayed independent across principals, and a stale-first partial batch preserved ordered successful decisions'
      ;;
    *) return 2 ;;
  esac
}

phase_su20() {
  local phase="$1" primary secondary primary_session fresh retry
  case "$phase" in
    request)
      [ "$(id -u)" -eq 1001 ]
      save_request durable-command 'Run the fake bounded command'
      ;;
    request-secondary)
      [ "$(id -u)" -eq 1002 ]
      save_request durable-file 'Read the fake operator file'
      ;;
    approve)
      [ "$(id -u)" -eq 1000 ]
      primary="$(read_handle durable-command)"
      secondary="$(read_handle durable-file)"
      capture_phase durable-approve guard access approve "$primary" "$secondary" --uses 3 --json
      [ "$(grep -c '"success": true' /scenario/journey/durable-approve.out)" -eq 2 ]
      primary_session="$(python3 - "$primary" <<'PY'
import json
import sys

request = sys.argv[1]
with open("/scenario/journey/durable-approve.out", encoding="utf-8") as stream:
    document = json.load(stream)
print(next(item["target"] for item in document["response"]["items"] if item["request"] == request))
PY
)"
      printf '%s\n' "$primary_session" > /scenario/journey/durable-command.session
      ;;
    consume-first)
      [ "$(id -u)" -eq 1001 ]
      capture_phase durable-command-first guard run --json printf 'bounded-command-complete\n'
      ;;
    consume-secondary-first)
      [ "$(id -u)" -eq 1002 ]
      capture_phase durable-file-first guard run --json cat "$PROTECTED_OPERATOR_NOTE"
      ;;
    revoke-after-restart)
      [ "$(id -u)" -eq 1000 ]
      primary="$(read_handle durable-command)"
      secondary="$(read_handle durable-file)"
      capture_phase durable-command-before-revoke guard access show "$primary" --json
      capture_phase durable-file-before-revoke guard access show "$secondary" --json
      grep -q '"remaining_uses": 2' /scenario/journey/durable-command-before-revoke.out
      grep -q '"remaining_uses": 2' /scenario/journey/durable-file-before-revoke.out
      primary_session="$(sed -n '1p' /scenario/journey/durable-command.session)"
      capture_phase durable-revoke guard access revoke "$primary_session" --json
      expect_failure durable-repeat-revoke guard access revoke "$primary_session" --json
      capture_phase historical-approve guard access approve "$primary" --uses 9 --json
      grep -q 'already approved; authority unchanged' /scenario/journey/historical-approve.out
      ;;
    post-revoke-primary)
      [ "$(id -u)" -eq 1001 ]
      expect_failure durable-command-revoked guard run --json printf 'bounded-command-complete\n'
      fresh="$(response_handle /scenario/journey/durable-command-revoked.out)"
      [ -n "$fresh" ]
      [ "$fresh" != "$(read_handle durable-command)" ]
      printf '%s\n' "$fresh" > /scenario/journey/durable-command-fresh.handle
      ;;
    post-revoke-secondary)
      [ "$(id -u)" -eq 1002 ]
      capture_phase durable-file-second guard run --json cat "$PROTECTED_OPERATOR_NOTE"
      ;;
    after-second-restart-primary)
      [ "$(id -u)" -eq 1001 ]
      expect_failure durable-command-retry guard run --json printf 'bounded-command-complete\n'
      retry="$(response_handle /scenario/journey/durable-command-retry.out)"
      [ "$retry" = "$(read_handle durable-command-fresh)" ]
      ;;
    after-second-restart-secondary)
      [ "$(id -u)" -eq 1002 ]
      capture_phase durable-file-third guard run --json cat "$PROTECTED_OPERATOR_NOTE"
      expect_failure durable-file-exhausted guard run --json cat "$PROTECTED_OPERATOR_NOTE"
      grep -q 'use limit is exhausted' /scenario/journey/durable-file-exhausted.out
      ;;
    verify)
      [ "$(id -u)" -eq 1000 ]
      primary_session="$(sed -n '1p' /scenario/journey/durable-command.session)"
      expect_failure durable-revoked-show guard access show "$primary_session" --json
      capture_phase durable-file-final guard access show "$(read_handle durable-file)" --json
      grep -q '"remaining_uses": 0' /scenario/journey/durable-file-final.out
      record_result passed 'intended policy' \
        'revocation before exhaustion survived two restarts without historical reapproval restoring authority, while another principal retained and exhausted its independent bounded budget'
      ;;
    *) return 2 ;;
  esac
}

phase_su21() {
  local phase="$1" stale='gr-00000000000000000000000000000000'
  local before after ssh cloud file retry
  case "$phase" in
    discover-and-request)
      [ "$(id -u)" -eq 1001 ]
      capture_phase terminal-before guard access list --json
      before="$(sha256sum /scenario/journey/terminal-before.out | cut -d' ' -f1)"
      capture_stdout_phase approve-help guard access approve --help
      capture_stdout_phase deny-help guard access deny --help
      [ ! -s /scenario/journey/approve-help.stderr ]
      [ ! -s /scenario/journey/deny-help.stderr ]
      grep -q -- '--once' /scenario/journey/approve-help.out
      grep -q -- '--uses <N>' /scenario/journey/approve-help.out
      grep -q -- '--reason <REASON>' /scenario/journey/deny-help.out
      capture_phase terminal-after guard access list --json
      after="$(sha256sum /scenario/journey/terminal-after.out | cut -d' ' -f1)"
      [ "$before" = "$after" ]
      save_request terminal-command 'Run the fake bounded command'
      save_request terminal-cloud 'Inspect the fake CloudStack virtual machines'
      save_request terminal-file 'Read the fake operator file'
      ;;
    decide)
      [ "$(id -u)" -eq 1000 ]
      ssh="$(read_handle terminal-command)"
      cloud="$(read_handle terminal-cloud)"
      file="$(read_handle terminal-file)"
      capture_phase terminal-file-deny guard access deny "$file" --json
      if capture_stdout_phase terminal-approve-partial guard access approve \
        "$stale" "$ssh" "$file" --once --json; then
        return 1
      fi
      [ ! -s /scenario/journey/terminal-approve-partial.stderr ]
      assert_access_decisions /scenario/journey/terminal-approve-partial.out \
        "$stale:false" "$ssh:true" "$file:false"
      if capture_stdout_phase terminal-deny-partial guard access deny \
        "$cloud" "$ssh" "$stale" --reason 'the remaining systems are out of scope' --json; then
        return 1
      fi
      [ ! -s /scenario/journey/terminal-deny-partial.stderr ]
      assert_access_decisions /scenario/journey/terminal-deny-partial.out \
        "$cloud:true" "$ssh:false" "$stale:false"
      ;;
    retry-and-use)
      [ "$(id -u)" -eq 1001 ]
      capture_phase terminal-command-use guard run --json printf 'bounded-command-complete\n'
      expect_failure terminal-command-exhausted guard run --json printf 'bounded-command-complete\n'
      grep -q 'use limit is exhausted' /scenario/journey/terminal-command-exhausted.out
      retry="$(response_handle /scenario/journey/terminal-command-exhausted.out)"
      [ -n "$retry" ]
      printf '%s\n' "$retry" > /scenario/journey/terminal-command-fresh.handle
      capture_phase terminal-command-retry guard access request ' Run the fake bounded command ' --json
      retry="$(request_reference /scenario/journey/terminal-command-retry.out)"
      [ "$retry" = "$(read_handle terminal-command-fresh)" ]
      [ "$retry" != "$(read_handle terminal-command)" ]
      capture_phase terminal-cloud-retry guard access request \
        'Inspect the fake CloudStack virtual machines' --json
      retry="$(request_reference /scenario/journey/terminal-cloud-retry.out)"
      [ "$retry" != "$(read_handle terminal-cloud)" ]
      expect_failure terminal-file-run guard run --json cat "$PROTECTED_OPERATOR_NOTE"
      [ "$(response_handle /scenario/journey/terminal-file-run.out)" != "$(read_handle terminal-file)" ]
      ;;
    stale-and-verify)
      [ "$(id -u)" -eq 1000 ]
      if capture_stdout_phase terminal-stale-show guard access show "$stale" --json; then
        return 1
      fi
      [ "$(cat /scenario/journey/terminal-stale-show.status)" -eq 125 ]
      [ ! -s /scenario/journey/terminal-stale-show.stderr ]
      python3 - <<'PY'
import json

with open("/scenario/journey/terminal-stale-show.out", encoding="utf-8") as stream:
    document = json.load(stream)
assert document["schema_version"] == 1
assert document["type"] == "access_error"
assert "unknown or unauthorized access reference" in document["error"]
PY
      capture_phase terminal-exhausted-show guard access show \
        "$(read_handle terminal-command)" --json
      grep -q '"remaining_uses": 0' /scenario/journey/terminal-exhausted-show.out
      record_result passed 'intended policy' \
        'approve and deny help remained non-mutating; ordered partial decisions committed valid items, exhausted approvals did not refill on retry, denied intent produced fresh requests, and stale JSON stayed machine-readable'
      ;;
    *) return 2 ;;
  esac
}

phase_su22() {
  local phase="$1" stale='gr-00000000000000000000000000000000'
  local command_request kube_request candidate_status pid executable
  case "$phase" in
    install)
      [ "$(id -u)" -eq 1000 ]
      mkdir -p "$PRIVATE_ROOT/stage" "$PRIVATE_ROOT/releases/v1" "$PRIVATE_ROOT/releases/v2"
      printf 'invalid candidate\n' > "$PRIVATE_ROOT/stage/guard.bad"
      chmod 0755 "$PRIVATE_ROOT/stage/guard.bad"
      set +e
      "$PRIVATE_ROOT/stage/guard.bad" --version \
        > "$PRIVATE_ROOT/log-invalid-candidate.out" 2>&1
      candidate_status=$?
      set -e
      [ "$candidate_status" -ne 0 ]
      rm -f "$PRIVATE_ROOT/stage/guard.bad"
      [ ! -e "$PRIVATE_ROOT/stage/guard.bad" ]
      cp /usr/local/bin/guard "$PRIVATE_ROOT/stage/guard"
      chmod 0755 "$PRIVATE_ROOT/stage/guard"
      cmp /usr/local/bin/guard "$PRIVATE_ROOT/stage/guard"
      "$PRIVATE_ROOT/stage/guard" --version > "$PRIVATE_ROOT/stage/version.out"
      mv "$PRIVATE_ROOT/stage/guard" "$PRIVATE_ROOT/releases/v1/guard"
      cp "$PRIVATE_ROOT/releases/v1/guard" "$PRIVATE_ROOT/releases/v2/guard"
      chmod 0755 "$PRIVATE_ROOT/releases/v2/guard"
      ln -s releases/v1/guard "$PRIVATE_ROOT/current"
      private_daemon_start "$PRIVATE_ROOT/current" install
      ;;
    request)
      [ "$(id -u)" -eq 1001 ]
      capture_phase private-command-request guard access request \
        'Run the fake bounded command' --socket "$PRIVATE_SOCKET" --json
      command_request="$(request_reference /scenario/journey/private-command-request.out)"
      [ -n "$command_request" ]
      printf '%s\n' "$command_request" > /scenario/journey/private-command.handle
      capture_phase private-kube-request guard access request \
        'Inspect the fake Kubernetes pods' --socket "$PRIVATE_SOCKET" --json
      kube_request="$(request_reference /scenario/journey/private-kube-request.out)"
      [ -n "$kube_request" ]
      printf '%s\n' "$kube_request" > /scenario/journey/private-kube.handle
      ;;
    approve-and-use)
      [ "$(id -u)" -eq 1000 ]
      capture_phase private-command-approve guard access approve \
        "$(read_handle private-command)" --uses 2 --socket "$PRIVATE_SOCKET" --json
      ;;
    consume-before-upgrade)
      [ "$(id -u)" -eq 1001 ]
      capture_phase private-command-first private_guard run --json \
        printf 'bounded-command-complete\n'
      ;;
    fail-and-rollback)
      [ "$(id -u)" -eq 1000 ]
      private_daemon_stop
      ln -s releases/v2/guard "$PRIVATE_ROOT/current.next"
      mv -T "$PRIVATE_ROOT/current.next" "$PRIVATE_ROOT/current"
      touch "$PRIVATE_ROOT/not-a-directory"
      set +e
      HOME="$PRIVATE_ROOT/home" XDG_CONFIG_HOME="$PRIVATE_ROOT/config" \
        XDG_DATA_HOME="$PRIVATE_ROOT/data" \
        timeout 5 "$PRIVATE_ROOT/current" server start --no-llm \
          --gate consequence \
          --socket "$PRIVATE_ROOT/not-a-directory/guard.sock" \
          --verbs "$PROTECTED_CATALOG" \
          --immutable-verbs-lock "$PROTECTED_CATALOG_LOCK" \
          --state-db "$PRIVATE_ROOT/data/state.db" \
          --audit-log "$PRIVATE_ROOT/data/audit.jsonl" \
          --exec-user guardexec \
          --users 1001,1002 \
          > "$PRIVATE_ROOT/log/failed-upgrade.log" 2>&1
      candidate_status=$?
      set -e
      [ "$candidate_status" -ne 0 ]
      [ ! -S "$PRIVATE_ROOT/not-a-directory/guard.sock" ]
      expect_failure private-outage guard access list --socket "$PRIVATE_SOCKET" --json
      ln -s releases/v1/guard "$PRIVATE_ROOT/current.next"
      mv -T "$PRIVATE_ROOT/current.next" "$PRIVATE_ROOT/current"
      private_daemon_start "$PRIVATE_ROOT/current" rollback
      capture_phase private-command-after-rollback guard access show \
        "$(read_handle private-command)" --socket "$PRIVATE_SOCKET" --json
      grep -q '"remaining_uses": 1' /scenario/journey/private-command-after-rollback.out
      ;;
    retry-after-rollback)
      [ "$(id -u)" -eq 1001 ]
      capture_phase private-kube-retry guard access request \
        ' Inspect the fake Kubernetes pods ' --socket "$PRIVATE_SOCKET" --json
      [ "$(request_reference /scenario/journey/private-kube-retry.out)" = "$(read_handle private-kube)" ]
      ;;
    promote-upgrade)
      [ "$(id -u)" -eq 1000 ]
      kube_request="$(read_handle private-kube)"
      if capture_stdout_phase private-kube-partial guard access approve \
        "$stale" "$kube_request" --once --socket "$PRIVATE_SOCKET" --json; then
        return 1
      fi
      assert_access_decisions /scenario/journey/private-kube-partial.out \
        "$stale:false" "$kube_request:true"
      private_daemon_stop
      ln -s releases/v2/guard "$PRIVATE_ROOT/current.next"
      mv -T "$PRIVATE_ROOT/current.next" "$PRIVATE_ROOT/current"
      private_daemon_start "$PRIVATE_ROOT/current" upgraded
      pid="$(sed -n '1p' "$PRIVATE_ROOT/run/daemon.pid")"
      executable="$(readlink "/proc/$pid/exe")"
      [ "$executable" = "$PRIVATE_ROOT/releases/v2/guard" ]
      ;;
    verify-client)
      [ "$(id -u)" -eq 1001 ]
      capture_phase private-command-second private_guard run --json \
        printf 'bounded-command-complete\n'
      expect_failure private-command-exhausted private_guard run --json \
        printf 'bounded-command-complete\n'
      grep -q 'use limit is exhausted' /scenario/journey/private-command-exhausted.out
      capture_phase private-kube-use private_guard run --json \
        kubectl get pods --namespace access-fixture
      expect_failure private-kube-exhausted private_guard run --json \
        kubectl get pods --namespace access-fixture
      grep -q 'use limit is exhausted' /scenario/journey/private-kube-exhausted.out
      ;;
    cleanup)
      [ "$(id -u)" -eq 1000 ]
      private_daemon_stop
      [ ! -S "$PRIVATE_SOCKET" ]
      [ ! -e "$PRIVATE_ROOT/current.next" ]
      [ ! -e "$PRIVATE_ROOT/stage/guard" ]
      [ ! -e "$PRIVATE_ROOT/stage/guard.bad" ]
      record_result passed 'intended policy' \
        'a private staged install rejected an invalid candidate, a failed upgrade left no daemon or socket, rollback preserved pending requests and remaining uses, and the verified replacement binary completed the bounded workflows before deterministic cleanup'
      ;;
    *) return 2 ;;
  esac
}

run_phase() {
  export GUARD_SOCKET="$SOCKET"
  prepare_principal_output
  RAW="$PHASE_OUTPUT/$SCENARIO.log"
  trap '[ -s "$FAILURE" ] || printf "phase=%s line=%s\n" "${3:-unknown}" "$LINENO" > "$FAILURE"' ERR
  trap 'status=$?; if [ "$status" -ne 0 ] && [ ! -s "$FAILURE" ]; then printf "phase=%s line=%s\n" "${3:-unknown}" "$LINENO" > "$FAILURE"; fi' EXIT
  mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME"
  cd /
  case "$SCENARIO" in
    SU-13) phase_su13 "$3" ;;
    SU-14) phase_su14 "$3" ;;
    SU-15) phase_su15 "$3" ;;
    SU-16) phase_su16 "$3" ;;
    SU-17) phase_su17 "$3" ;;
    SU-18) phase_su18 "$3" ;;
    SU-19) phase_su19 "$3" ;;
    SU-20) phase_su20 "$3" ;;
    SU-21) phase_su21 "$3" ;;
    SU-22) phase_su22 "$3" ;;
    *)
      [ "$3" = contract ]
      run
      ;;
  esac
}

run_journey() {
  local verb="$1" expected="$2" cwd="${3:-/}"
  printf 'authority=typed-verb:%s consequence=catalog-bound cwd=%s\n' "$verb" "$cwd" >> "$RAW"
  (cd "$cwd" && guard verb run "$verb" --socket "$SOCKET") >>"$RAW" 2>&1
  grep -q "$expected" "$RAW"
}

assert_child_capability_contract() {
  local expected_uid="$1" output
  output="$(guard verb run child-capability-contract --socket "$SOCKET" 2>&1)"
  printf '%s\n' "$output" >> "$RAW"
  printf '%s\n' "$output" | grep -qx "uid=$expected_uid"
  printf '%s\n' "$output" | grep -Eq '^cap_eff=0+$'
}

expect_profile_tool_denial() {
  local mode="$1" verb="$2" cwd="${3:-/}" output
  output="/scenario/raw/$SCENARIO-$mode-$verb.out"
  if (cd "$cwd" && guard verb run "$verb" --socket "$SOCKET") >"$output" 2>&1; then
    printf 'typed profile tool unexpectedly executed: mode=%s verb=%s\n' "$mode" "$verb" > "$FAILURE"
    return 1
  fi
  cat "$output" >> "$RAW"
  case "$mode" in
    fixed) grep -Eq 'fixed-identity|shared child UID' "$output" ;;
    caller) grep -Eq 'exec-as-caller|caller profile|immutable profile|unavailable' "$output" ;;
    *) return 2 ;;
  esac
  ! grep -Eq 'fixture-release|changed=0|fixture-pod' "$output"
}

run_su12() {
  case "$SCENARIO" in
    SU-12-service) run_journey service-status fixture-service:active ;;
    SU-12-cloudstack) run_journey cloudstack-inventory fixture-vm ;;
    SU-12-kubernetes)
      assert_child_capability_contract 1003
      run_journey kubernetes-list fixture-pod
      ;;
    SU-12-helm)
      expect_profile_tool_denial fixed helm-list-direct
      expect_profile_tool_denial fixed ansible-check /scenario/ansible
      ;;
    SU-12-ansible)
      assert_child_capability_contract 1001
      expect_profile_tool_denial caller ansible-check /scenario/ansible
      expect_profile_tool_denial caller helm-list-direct
      expect_profile_tool_denial caller kubernetes-list
      ;;
    SU-12-workload-maintenance)
      printf 'authority=typed-verb:workload-maintenance consequence=recoverable cwd=/scenario/fixtures\n' >> "$RAW"
      guard verb run workload-maintenance --confirm-within 1 --socket "$SOCKET" >>"$RAW" 2>&1
      [ -f /scenario/fixtures/maintenance-applied ]
      sleep 5
      [ ! -e /scenario/fixtures/maintenance-applied ]
      ;;
    SU-12-api)
      mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME"
      expect_failure fixture-api-raw guard run --json fixture-api status
      ! grep -q 'fixture-api:healthy' /scenario/journey/fixture-api-raw.out
      expect_failure fixture-api-extra guard run --json \
        systemctl status fixture-api.service --output=json
      ! grep -q 'fixture-api:healthy' /scenario/journey/fixture-api-extra.out
      run_journey fixture-api-status 'fixture-api:healthy uid=1001'
      grep -Fq '[REDACTED]' "$RAW"
      ;;
    *) return 2 ;;
  esac
}

postcheck() {
  case "$SCENARIO" in
    SU-12-api)
      if [ "$(id -u)" -eq 0 ] \
        && [ "$(stat -c '%u:%g:%a' "$FIXTURE_API_AUTHORITY_DIR")" = 0:0:755 ] \
        && [ "$(stat -c '%u:%g:%a' "$FIXTURE_API_TOKEN_FILE")" = 0:0:600 ] \
        && [ "$(stat -c '%u:%g:%a' "$FIXTURE_API_TOKEN_DIGEST_FILE")" = 0:0:444 ] \
        && ! grep -Fq -f "$FIXTURE_API_TOKEN_FILE" "$RAW" \
        && ! grep -Fq -f "$FIXTURE_API_TOKEN_FILE" /scenario/data/audit.jsonl \
        && grep -q 'fixture/api-token' /scenario/data/audit.jsonl; then
        return 0
      fi
      record_result failed "Guard defect" \
        "the operator-only audit postcheck found a value leak or a missing secret reference"
      return 1
      ;;
    *) return 0 ;;
  esac
}

run() {
  export GUARD_SOCKET="$SOCKET"
  mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME"
  : > "$RAW"
  if [[ "$SCENARIO" = SU-12-* ]]; then
    if run_su12; then
      record_result passed "intended policy" "the isolated workload observed the configured execution and profile boundary"
      echo "$SCENARIO: passed"
      return 0
    fi
  elif run_contracts; then
    record_result passed "regression contract" "the reduced deterministic contract passed against the integrated source"
    echo "$SCENARIO: passed"
    return 0
  fi
  record_result failed "Guard defect, fixture defect, or underlying-tool failure pending reduction" \
    "$(sed -n '1p' "$FAILURE" 2>/dev/null || printf 'the deterministic reproducer failed')"
  echo "$SCENARIO: failed" >&2
  return 1
}

prepare_principal_output() {
  [ -d "$PRINCIPAL_ROOT" ] && [ -O "$PRINCIPAL_ROOT" ]
  [ -d "$PHASE_OUTPUT" ] && [ -d "$(dirname "$RESULT")" ]
  umask 022
}

prepare_principals() {
  local daemon_owner token_mode uid root
  [ "$(id -u)" -eq 0 ]
  setup_fixture
  mkdir -p "$FIXTURE_API_AUTHORITY_DIR"
  chmod 0755 "$FIXTURE_API_AUTHORITY_DIR"
  generate_fixture_value > "$FIXTURE_API_TOKEN_FILE"
  sha256sum "$FIXTURE_API_TOKEN_FILE" | awk '{print $1}' > "$FIXTURE_API_TOKEN_DIGEST_FILE"
  chmod 0600 "$FIXTURE_API_TOKEN_FILE"
  chmod 0444 "$FIXTURE_API_TOKEN_DIGEST_FILE"
  chown -R 0:0 "$FIXTURE_API_AUTHORITY_DIR"
  [ "$(stat -c '%u:%g:%a' "$FIXTURE_API_AUTHORITY_DIR")" = 0:0:755 ]
  [ "$(stat -c '%u:%g:%a' "$FIXTURE_API_TOKEN_FILE")" = 0:0:600 ]
  [ "$(stat -c '%u:%g:%a' "$FIXTURE_API_TOKEN_DIGEST_FILE")" = 0:0:444 ]
  for uid in 1000 1001 1002; do
    root="/scenario/principals/$uid"
    mkdir -p "$root/phase-output" "$root/results"
    chmod 0710 "$root"
    chmod 0750 "$root/phase-output" "$root/results"
    chown -R "$uid:0" "$root"
  done
  mkdir -p "$COLLECTOR_RESULTS" "$COLLECTOR_PHASES"
  # The operator persona retains token access. Caller mode grants the
  # capability-bounded daemon group-read access for its startup redirection;
  # uids 1001/1002 hold neither the file nor the value.
  write_generated_fixture_value /scenario/run/admin.token
  if caller_identity_scenario; then
    daemon_owner=0:0
    token_mode=0440
  else
    daemon_owner=1000:1000
    token_mode=0400
  fi
  chmod "$token_mode" /scenario/run/admin.token
  chown 1000:0 /scenario/run/admin.token
  chown -R 0:0 "$COLLECTOR_ROOT"
  chmod 0700 "$COLLECTOR_ROOT" "$COLLECTOR_RESULTS" "$COLLECTOR_PHASES"
  chown -R "$daemon_owner" /scenario/home /scenario/config /scenario/data /scenario/raw \
    /scenario/fixtures /scenario/bin /scenario/ansible
  chmod 0700 /scenario/data
  mkdir -p "$PRIVATE_ROOT/run"
  chown "$daemon_owner" /scenario
  : > "$BROKERED_KUBECONFIG"
  : > "$PRIVATE_ROOT/run/brokered.kubeconfig"
  chmod 0640 "$BROKERED_KUBECONFIG" "$PRIVATE_ROOT/run/brokered.kubeconfig"
  chown 1000:guardexec "$BROKERED_KUBECONFIG" \
    "$PRIVATE_ROOT/run/brokered.kubeconfig"
  chmod 0755 "$PRIVATE_ROOT" "$PRIVATE_ROOT/run"
  chown 1000:1000 "$PRIVATE_ROOT"
  chown 1000:guard-clients "$PRIVATE_ROOT/run"
  chmod 0755 /scenario/run
  if caller_identity_scenario; then
    chown 0:guard-clients /scenario/run
  else
    chown 1000:guard-clients /scenario/run
  fi

  # A separate authority volume prepares trusted source ownership without
  # exposing its writable source path to the daemon. The daemon sees this
  # directory only at the rootfs-backed read-only /authority mountpoint, with
  # the pre-created lock inode layered writable.
  mkdir -p "$PROTECTED_CATALOG_DIR"
  chmod 0755 "$PROTECTED_CATALOG_DIR"
  cp /etc/guard/verbs.yaml "$PROTECTED_CATALOG"
  printf 'synthetic operator note\n' > "$PROTECTED_OPERATOR_NOTE"
  chmod 0444 "$PROTECTED_CATALOG"
  chmod 0444 "$PROTECTED_OPERATOR_NOTE"
  install -m 0600 /dev/null "$PROTECTED_CATALOG_LOCK"
  chmod 0555 "$PROTECTED_CATALOG_DIR"
  chown "$daemon_owner" \
    "$PROTECTED_CATALOG_DIR" "$PROTECTED_CATALOG" "$PROTECTED_CATALOG_LOCK" \
    "$PROTECTED_OPERATOR_NOTE"

  [ "$(stat -c '%u:%g:%a' "$PROTECTED_CATALOG_DIR")" = \
    "$daemon_owner:555" ]
  [ "$(stat -c '%u:%g:%a' "$PROTECTED_CATALOG")" = \
    "$daemon_owner:444" ]
  [ "$(stat -c '%u:%g:%a' "$PROTECTED_OPERATOR_NOTE")" = \
    "$daemon_owner:444" ]
  [ "$(stat -c '%u:%g:%a' "$PROTECTED_CATALOG_LOCK")" = \
    "$daemon_owner:600" ]
  [ "$(sha256sum "$PROTECTED_CATALOG" | awk '{print $1}')" = \
    "$(sha256sum /etc/guard/verbs.yaml | awk '{print $1}')" ]
}

collect_phase() {
  local scenario="$2" uid="$3" phase="$4" status="$5" source destination
  [ "$(id -u)" -eq 0 ]
  source="/scenario/principals/$uid/phase-output"
  destination="$COLLECTOR_PHASES/$scenario/$uid/$phase"
  [ -d "$source" ]
  mkdir -p "$COLLECTOR_PHASES/$scenario/$uid"
  mkdir "$destination"
  find "$source" -maxdepth 1 -type f -exec cp {} "$destination"/ \;
  find "$destination" -maxdepth 1 -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum \
    > "$destination.sha256"
  printf 'scenario=%s uid=%s phase=%s runner_exit=%s\n' \
    "$scenario" "$uid" "$phase" "$status" >> "$destination.sha256"
}

collect_result() {
  local scenario="$2" expected="$3" candidate temporary phase_manifest phase_digest
  local failure_file failure_signal=''
  local -a candidates=()
  local uid
  [ "$(id -u)" -eq 0 ]
  for uid in 1000 1001 1002; do
    candidate="/scenario/principals/$uid/results/$scenario.md"
    if [ -f "$candidate" ]; then
      candidates+=("$candidate")
    fi
  done
  temporary="$(mktemp "$COLLECTOR_RESULTS/.${scenario}.XXXXXX")"
  if [ "$expected" = passed ] && [ "${#candidates[@]}" -eq 1 ] \
    && grep -Fqx -- "# $scenario" "${candidates[0]}" \
    && grep -Fqx -- '- Result: passed' "${candidates[0]}"; then
    head -c 131072 "${candidates[0]}" > "$temporary"
  else
    for uid in 1000 1001 1002; do
      failure_file="/scenario/principals/$uid/failure.txt"
      [ -f "$failure_file" ] || continue
      candidate="$(sed -n '1p' "$failure_file")"
      case "$candidate" in
        'test filter failed: '*|'test filter matched no tests: '*)
          if [[ "$candidate" =~ ^test\ filter\ (failed|matched\ no\ tests):\ [A-Za-z0-9_]+$ ]]; then
            failure_signal="$candidate"
          fi
          ;;
        'access request failed: '*)
          if [[ "$candidate" =~ ^access\ request\ failed:\ [A-Za-z0-9_-]+-(command|reference|guidance)$ ]]; then
            failure_signal="$candidate"
          fi
          ;;
        'private daemon failed: '*)
          if [[ "$candidate" =~ ^private\ daemon\ failed:\ [A-Za-z0-9_-]+-(socket-readiness|process-exit|socket-contract|capability-contract)$ ]]; then
            failure_signal="$candidate"
          fi
          ;;
        'phase='*)
          if [[ "$candidate" =~ ^phase=[A-Za-z0-9_-]+\ line=[0-9]+$ ]]; then
            failure_signal="$candidate"
          fi
          ;;
        'caller could not inspect its own live provisional'|\
        'live failing revert did not surface revert_failed')
          failure_signal="$candidate"
          ;;
        'live failing-revert verb did not enter the provisional state: '*)
          failure_signal='live failing-revert verb did not enter the provisional state'
          ;;
        'typed profile tool unexpectedly executed: '*)
          if [[ "$candidate" =~ ^typed\ profile\ tool\ unexpectedly\ executed:\ mode=(fixed|caller)\ verb=[A-Za-z0-9_-]+$ ]]; then
            failure_signal="$candidate"
          fi
          ;;
      esac
      [ -z "$failure_signal" ] || break
    done
    {
      echo "# $scenario"
      echo
      echo "- Result: failed"
      echo "- Classification: fixture defect"
      echo "- Evidence: the root collector did not receive one matching successful candidate result"
      echo "- Isolation: rootless container, private daemon/socket/database/fixtures/principal/network namespace, network disabled"
      echo "- Raw transcript: retained only in the ephemeral scenario volume and removed during teardown"
      if [ -n "$failure_signal" ]; then
        printf '%s\n' "- Failure signal: \`$failure_signal\`"
      fi
    } > "$temporary"
  fi
  phase_manifest="$COLLECTOR_ROOT/$scenario.phase-output.sha256"
  find "$COLLECTOR_PHASES/$scenario" -type f -name '*.sha256' -print0 2>/dev/null \
    | LC_ALL=C sort -z | xargs -0 -r sha256sum > "$phase_manifest"
  phase_digest="$(sha256sum "$phase_manifest" | cut -d ' ' -f 1)"
  printf '%s\n' "- Principal phase output digest: \`$phase_digest\`" >> "$temporary"
  printf '%s\n' '- Final result: finalized by the root collector' >> "$temporary"
  chmod 0600 "$temporary"
  mv "$temporary" "$COLLECTOR_RESULTS/$scenario.md"
}

case "${1:-}" in
  daemon) daemon ;;
  run) run ;;
  phase) run_phase "$@" ;;
  provision-api-secret) provision_fixture_api_token ;;
  failure)
    record_result failed 'Guard defect, fixture defect, or underlying-tool failure pending reduction' \
      "$(sed -n '1p' "$FAILURE" 2>/dev/null || printf 'a live role-separated journey phase failed')"
    ;;
  postcheck) postcheck ;;
  prepare-principals)
    [ "$(id -u)" -eq 0 ] || { echo 'prepare-principals requires container root' >&2; exit 2; }
    prepare_principals
    ;;
  collect-phase)
    [ "$(id -u)" -eq 0 ] || { echo 'collect-phase requires container root' >&2; exit 2; }
    collect_phase "$@"
    ;;
  collect-result)
    [ "$(id -u)" -eq 0 ] || { echo 'collect-result requires container root' >&2; exit 2; }
    collect_result "$@"
    ;;
  *) echo "usage: synthetic-user.sh daemon|run|phase SCENARIO [PHASE]|provision-api-secret" >&2; exit 2 ;;
esac
