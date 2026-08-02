#!/bin/bash
# Container-side synthetic-user fixture and deterministic contract runner.
set -euo pipefail

SOCKET=/scenario/run/guard.sock
SCENARIO="${2:-}"
RAW="/scenario/raw/$SCENARIO.log"
PRINCIPAL_ROOT="/scenario/principals/$(id -u)"
PHASE_OUTPUT="$PRINCIPAL_ROOT/phase-output"
RESULT="$PRINCIPAL_ROOT/results/$SCENARIO.md"
FAILURE="$PRINCIPAL_ROOT/failure.txt"
COLLECTOR_ROOT=/scenario/collector
COLLECTOR_RESULTS="$COLLECTOR_ROOT/results"
COLLECTOR_PHASES="$COLLECTOR_ROOT/phases"

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
  printf 'synthetic operator note\n' > /scenario/fixtures/operator-note
  printf 'apiVersion: v1\nkind: Config\nsynthetic: true\n' > /scenario/fixtures/daemon.kubeconfig
  printf '[fixture]\nlocalhost\n' > /scenario/ansible/inventory
  printf '[defaults]\ninventory = inventory\n' > /scenario/ansible/ansible.cfg
  printf '%s\n' '---' '- hosts: fixture' '  gather_facts: false' '  tasks: []' > /scenario/ansible/site.yml
  cat > /scenario/config/guard/tools.yaml <<'EOF'
tools:
  fixture-api:
    secrets:
      FIXTURE_API_TOKEN: fixture/api-token
EOF
  cat > /scenario/bin/ssh <<'EOF'
#!/bin/sh
[ -n "${GUARD_DEPTH:-}" ] || exit 41
[ -z "${SSH_AUTH_SOCK:-}" ] || exit 42
printf 'fixture-service:active\n'
EOF
  cat > /scenario/bin/cloudstack <<'EOF'
#!/bin/sh
printf '{"virtualmachine":[{"id":"fixture-vm","state":"Running"}]}\n'
EOF
  cat > /scenario/bin/kubectl <<'EOF'
#!/bin/sh
[ "${KUBECONFIG:-}" = /scenario/fixtures/daemon.kubeconfig ] || exit 43
printf 'fixture-pod Running\n'
EOF
  cat > /scenario/bin/helm <<'EOF'
#!/bin/sh
[ "${KUBECONFIG:-}" = /scenario/fixtures/daemon.kubeconfig ] || exit 44
printf 'fixture-release deployed\n'
EOF
  cat > /scenario/bin/ansible-playbook <<'EOF'
#!/bin/sh
[ "$(pwd)" = /scenario/ansible ] || exit 45
[ -z "${ANSIBLE_CONFIG:-}" ] || exit 46
printf 'fixture ok changed=0\n'
EOF
  cat > /scenario/bin/hostctl <<'EOF'
#!/bin/sh
[ "$1" = apply ] || exit 47
touch "$2"
printf 'maintenance applied\n'
EOF
  cat > /scenario/bin/fixture-api <<'EOF'
#!/bin/sh
[ "$1" = status ] || [ "$1" = access-status ] || exit 48
[ "${FIXTURE_API_TOKEN:-}" = synthetic-fixture-token ] || exit 49
printf 'fixture-api:healthy\n'
EOF
  cat > /scenario/bin/novelctl <<'EOF'
#!/bin/sh
[ "$1" = status ] || exit 50
printf 'novel-diagnostic:healthy\n'
EOF
  chmod 0755 /scenario/bin/*
}

daemon() {
  setup_fixture
  export HOME=/scenario/home
  export XDG_CONFIG_HOME=/scenario/config
  export XDG_DATA_HOME=/scenario/data
  export PATH=/scenario/bin:/usr/local/bin:/usr/bin:/bin
  export KUBECONFIG=/scenario/fixtures/daemon.kubeconfig
  local evaluator_args=(--no-llm)
  if [ "$SCENARIO" = SU-13 ]; then
    guard-fake-llm >>/scenario/raw/fake-llm.log 2>&1 &
    export GUARD_LLM_API_KEY=fake-container-credential
    evaluator_args=(
      --llm
      --llm-api-url http://127.0.0.1:38473
      --llm-model fake-synthesis-model
      --llm-retries 0
    )
  fi
  exec guard server start \
    "${evaluator_args[@]}" \
    --gate consequence \
    --socket "$SOCKET" \
    --verbs /etc/guard/verbs.yaml \
    --state-db /scenario/data/state.db \
    --audit-log /scenario/data/audit.jsonl \
    --history-retention 3600 \
    --child-env KUBECONFIG \
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
    [ -f "$binary" ] && [ -x "$binary" ] || continue
    case "$binary" in
      *.so) continue ;;
    esac
    listing="$("$binary" --list 2>/dev/null || true)"
    printf '%s\n' "$listing" | grep -Eq '[0-9]+ tests, [0-9]+ benchmarks$' || continue
    output="$("$binary" "$filter" --nocapture 2>&1)" || {
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
      run_test_filter ansible_discovers_config_from_cwd_without_inherited_ansible_config
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
      if ! live_output="$(guard verb run failing-revert --confirm-within 1 --socket "$SOCKET" 2>&1)"; then
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
      if ! live_output="$(guard verb run ssh-diagnose --socket "$SOCKET" 2>&1)"; then
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
    printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"guard_run","arguments":{"binary":"hostctl","args":["apply","/scenario/fixtures/access-maintenance-applied"]}}}'
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
  local file="$1" handle="$2"
  grep -Fq "guard access approve $handle" "$file"
  grep -Fq "guard access approve $handle --once" "$file"
  grep -Fq "guard access approve $handle --uses 3" "$file"
}

require_hold_guidance() {
  local file="$1" handle="$2"
  grep -Fq "guard access approve $handle --once" "$file"
  ! grep -Fq "guard access approve $handle --uses" "$file"
}

save_request() {
  local name="$1" intent="$2" output="/scenario/journey/$1-request.out" handle
  capture_phase "$name-request" guard access request "$intent" --json || return 1
  handle="$(request_reference "$output")"
  [ -n "$handle" ] || return 1
  printf '%s\n' "$handle" > "/scenario/journey/$name.handle"
  require_request_guidance "$output" "$handle"
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

private_daemon_start() {
  local binary="$1" log_name="$2" pid ready=false
  mkdir -p "$PRIVATE_ROOT/home" "$PRIVATE_ROOT/config" "$PRIVATE_ROOT/data" \
    "$PRIVATE_ROOT/run" "$PRIVATE_ROOT/log"
  rm -f "$PRIVATE_SOCKET"
  HOME="$PRIVATE_ROOT/home" \
    XDG_CONFIG_HOME="$PRIVATE_ROOT/config" \
    XDG_DATA_HOME="$PRIVATE_ROOT/data" \
    PATH="/scenario/bin:/usr/local/bin:/usr/bin:/bin" \
    KUBECONFIG=/scenario/fixtures/daemon.kubeconfig \
    nohup "$binary" server start \
      --no-llm \
      --gate consequence \
      --socket "$PRIVATE_SOCKET" \
      --verbs /etc/guard/verbs.yaml \
      --state-db "$PRIVATE_ROOT/data/state.db" \
      --audit-log "$PRIVATE_ROOT/data/audit.jsonl" \
      --history-retention 3600 \
      --child-env KUBECONFIG \
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
  [ "$ready" = true ]
  chmod 0711 "$PRIVATE_ROOT/run"
  chmod 0666 "$PRIVATE_SOCKET"
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
      sha256sum /etc/guard/verbs.yaml | awk '{print $1}' > /scenario/journey/catalog.before
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
      grep -Eq 'expired|revoked' /scenario/journey/synthesized-revoked-hold-approve.out
      capture_phase synthesized-revoked-hold-deny \
        guard access deny "$handle" --reason 'originating access revoked' --json
      grep -q '"state": "denied"' /scenario/journey/synthesized-revoked-hold-deny.out
      ;;
    after-revoke)
      [ "$(id -u)" -eq 1001 ]
      expect_failure synthesized-revoked guard run --json novelctl status
      ! grep -q 'novel-diagnostic:healthy' /scenario/journey/synthesized-revoked.out
      ;;
    verify)
      [ "$(id -u)" -eq 1000 ]
      sha256sum /etc/guard/verbs.yaml | awk '{print $1}' > /scenario/journey/catalog.after
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
      save_request owner 'Inspect the fake SSH service'
      handle="$(read_handle owner)"
      capture_phase owner-retry guard access request '  Inspect   the fake SSH service  ' --json
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
      save_request other 'Inspect the fake SSH service'
      other="$(read_handle other)"
      [ "$other" != "$handle" ]
      ;;
    consume)
      [ "$(id -u)" -eq 1001 ]
      capture_phase owner-consume guard run --json ssh access-fixture-host systemctl is-active fixture-service
      grep -q 'fixture-service:active' /scenario/journey/owner-consume.out
      expect_failure owner-exhausted guard run --json ssh access-fixture-host systemctl is-active fixture-service
      grep -q 'use limit is exhausted' /scenario/journey/owner-exhausted.out
      ;;
    after-restart)
      [ "$(id -u)" -eq 1001 ]
      expect_failure owner-restart-exhausted guard run --json ssh access-fixture-host systemctl is-active fixture-service
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
      expect_failure maintenance-denied guard run --json hostctl apply /scenario/fixtures/access-maintenance-applied
      denied_handle="$(response_handle /scenario/journey/maintenance-denied.out)"
      [ -n "$denied_handle" ]
      printf '%s\n' "$denied_handle" > /scenario/journey/maintenance.handle
      require_request_guidance /scenario/journey/maintenance-denied.out "$denied_handle"
      capture_mcp_denial
      grep -Fq '"allowed":false' /scenario/journey/maintenance-mcp.out
      grep -Fq "\`guard access approve $denied_handle\`" /scenario/journey/maintenance-mcp.out
      grep -Fq "\`guard access approve $denied_handle --once\`" /scenario/journey/maintenance-mcp.out
      grep -Fq "\`guard access approve $denied_handle --uses 3\`" /scenario/journey/maintenance-mcp.out
      grep -Fq "\`guard access show $denied_handle\`" /scenario/journey/maintenance-mcp.out
      expect_failure maintenance-retry guard run --json hostctl apply /scenario/fixtures/access-maintenance-applied
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
      capture_phase maintenance-provisional guard run --json hostctl apply /scenario/fixtures/access-maintenance-applied
      grep -q '"status": "provisional"' /scenario/journey/maintenance-provisional.out
      expect_failure delete-held guard run --json rm -rf /scenario/fixtures/staging
      grep -q '"status": "held"' /scenario/journey/delete-held.out
      hold="$(response_handle /scenario/journey/delete-held.out)"
      [ -n "$hold" ]
      printf '%s\n' "$hold" > /scenario/journey/hold.handle
      require_hold_guidance /scenario/journey/delete-held.out "$hold"
      expect_failure denied-held guard run --json rm -rf /work/staging-denied
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
        'index($0, "\"kind\":\"APPROVED\"") && index($0, "\"handle\":\"" handle "\"") && index($0, "\"cmd\":\"rm -rf /scenario/fixtures/staging\"") { count++ } END { print count + 0 }' \
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
      save_request ssh 'Inspect the fake SSH service'
      save_request kube 'Inspect the fake Kubernetes pods'
      save_request missing 'Run the missing fake command'
      save_request command 'Run the fake bounded command'
      save_request cloud 'Inspect the fake CloudStack virtual machines'
      save_request file 'Read the fake operator file'
      save_request ansible 'Check the fake Ansible project'
      save_request api 'Query the fake credential-backed API'
      printf '%s' synthetic-fixture-token | guard secrets add fixture/api-token >> "$RAW" 2>&1
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
      capture_phase ssh-before-other-approvals guard run --json ssh access-fixture-host systemctl is-active fixture-service
      grep -q 'fixture-service:active' /scenario/journey/ssh-before-other-approvals.out
      expect_failure cross-kube guard run --json kubectl get pods --namespace access-fixture
      [ "$(response_handle /scenario/journey/cross-kube.out)" = "$(read_handle kube)" ]
      expect_failure cross-command guard run --json printf 'bounded-command-complete\n'
      [ "$(response_handle /scenario/journey/cross-command.out)" = "$(read_handle command)" ]
      expect_failure cross-cloud guard run --json cloudstack list virtualmachines zoneid=access-fixture-zone
      [ "$(response_handle /scenario/journey/cross-cloud.out)" = "$(read_handle cloud)" ]
      expect_failure cross-file guard run --json cat /scenario/fixtures/operator-note
      [ "$(response_handle /scenario/journey/cross-file.out)" = "$(read_handle file)" ]
      (cd /scenario/ansible && expect_failure cross-ansible guard run --json ansible-playbook /scenario/ansible/site.yml --check --diff --limit access-fixture)
      [ "$(response_handle /scenario/journey/cross-ansible.out)" = "$(read_handle ansible)" ]
      expect_failure cross-api guard run --json fixture-api access-status
      [ "$(response_handle /scenario/journey/cross-api.out)" = "$(read_handle api)" ]
      assert_denied_without_execution /scenario/journey/cross-*.out
      ;;
    reject-secondary-cross-scope)
      [ "$(id -u)" -eq 1002 ]
      expect_failure secondary-cross-ssh guard run --json ssh access-fixture-host systemctl is-active fixture-service
      ! grep -q 'fixture-service:active' /scenario/journey/secondary-cross-ssh.out
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
      capture_phase approve-spawn-failure guard access approve "$missing_request" --once --json
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
      capture_phase helm-first guard run --json helm list --namespace access-fixture
      capture_phase helm-second guard run --json helm list --namespace access-fixture
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
      expect_failure missing-first guard run --json guard-missing-fixture-binary
      grep -q 'execution error' /scenario/journey/missing-first.out
      expect_failure missing-second guard run --json guard-missing-fixture-binary
      grep -q 'use limit is exhausted' /scenario/journey/missing-second.out
      capture_phase command-first guard run --json printf 'bounded-command-complete\n'
      grep -q 'bounded-command-complete' /scenario/journey/command-first.out
      capture_phase ssh-first guard run --json ssh access-fixture-host systemctl is-active fixture-service
      capture_phase ssh-second guard run --json ssh access-fixture-host systemctl is-active fixture-service
      ;;
    after-restart)
      [ "$(id -u)" -eq 1001 ]
      capture_phase command-second guard run --json printf 'bounded-command-complete\n'
      expect_failure command-third guard run --json printf 'bounded-command-complete\n'
      grep -q 'use limit is exhausted' /scenario/journey/command-third.out
      capture_phase cloud-use guard run --json cloudstack list virtualmachines zoneid=access-fixture-zone
      capture_phase file-use guard run --json cat /scenario/fixtures/operator-note
      (cd /scenario/ansible && capture_phase ansible-use guard run --json ansible-playbook /scenario/ansible/site.yml --check --diff --limit access-fixture)
      printf '%s' synthetic-fixture-token | guard secrets add fixture/api-token >> "$RAW" 2>&1
      capture_phase api-use guard run --json fixture-api access-status
      grep -q 'fixture-api:healthy' /scenario/journey/api-use.out
      ! grep -q 'synthetic-fixture-token' /scenario/journey/api-use.out
      ;;
    verify)
      [ "$(id -u)" -eq 1000 ]
      capture_phase batch-final-list guard access list --json
      run_test_filter access_request_is_principal_bound_coalesced_batched_and_bounded
      record_result passed 'intended policy' \
        'ordinary, one-time, N-use, multi-request, replay, cross-system denial, last-use race, failed spawn, restart, and partial-failure paths preserved independent authority'
      ;;
    *) return 2 ;;
  esac
}

phase_su17() {
  local phase="$1" handle session extension retry
  case "$phase" in
    request)
      [ "$(id -u)" -eq 1001 ]
      save_request initial 'Inspect the fake SSH service'
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
      capture_phase original-still-active guard run --json ssh access-fixture-host systemctl is-active fixture-service
      ;;
    retry-extension)
      [ "$(id -u)" -eq 1000 ]
      session="$(sed -n '1p' /scenario/journey/extend.session)"
      capture_phase extend-after-use guard access extend "$session" 'Inspect the fake Kubernetes pods' --once --json
      grep -q '"remaining_uses": 0' /scenario/journey/extend-after-use.out
      capture_phase extend-maintenance guard access extend "$session" 'Apply the fake host maintenance operation' --json
      extension="$(sed -nE 's/.*"request": "(gr-[^"]+)".*/\1/p' /scenario/journey/extend-maintenance.out | head -n 1)"
      [ -n "$extension" ]
      printf '%s\n' "$extension" > /scenario/journey/maintenance-extension.handle
      ;;
    consume-maintenance)
      [ "$(id -u)" -eq 1001 ]
      capture_phase maintenance-contained guard run --json --confirm-within 1 hostctl apply /scenario/fixtures/access-maintenance-applied
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
      grep -q '"verb": "access-host-maintenance"' /scenario/journey/maintenance-extension-show.out
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
      expect_failure revoked-denied guard run --json cat /scenario/fixtures/operator-note
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
      expect_failure primary-file-denied guard run --json cat /scenario/fixtures/operator-note
      fresh="$(response_handle /scenario/journey/primary-file-denied.out)"
      [ -n "$fresh" ]
      [ "$fresh" != "$(read_handle primary-file)" ]
      printf '%s\n' "$fresh" > /scenario/journey/primary-file-fresh.handle
      ;;
    use-secondary)
      [ "$(id -u)" -eq 1002 ]
      capture_phase secondary-file-use guard run --json cat /scenario/fixtures/operator-note
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
      capture_phase durable-file-first guard run --json cat /scenario/fixtures/operator-note
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
      capture_phase durable-file-second guard run --json cat /scenario/fixtures/operator-note
      ;;
    after-second-restart-primary)
      [ "$(id -u)" -eq 1001 ]
      expect_failure durable-command-retry guard run --json printf 'bounded-command-complete\n'
      retry="$(response_handle /scenario/journey/durable-command-retry.out)"
      [ "$retry" = "$(read_handle durable-command-fresh)" ]
      ;;
    after-second-restart-secondary)
      [ "$(id -u)" -eq 1002 ]
      capture_phase durable-file-third guard run --json cat /scenario/fixtures/operator-note
      expect_failure durable-file-exhausted guard run --json cat /scenario/fixtures/operator-note
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
      expect_failure terminal-file-run guard run --json cat /scenario/fixtures/operator-note
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
          --verbs /etc/guard/verbs.yaml \
          --state-db "$PRIVATE_ROOT/data/state.db" \
          --audit-log "$PRIVATE_ROOT/data/audit.jsonl" \
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
  trap 'printf "phase=%s line=%s\n" "${3:-unknown}" "$LINENO" > "$FAILURE"' ERR
  mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME"
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
  local verb="$1" expected="$2" cwd="${3:-/scenario/fixtures}"
  printf 'authority=typed-verb:%s consequence=catalog-bound cwd=%s\n' "$verb" "$cwd" >> "$RAW"
  (cd "$cwd" && guard verb run "$verb" --socket "$SOCKET") >>"$RAW" 2>&1
  grep -q "$expected" "$RAW"
}

run_su12() {
  case "$SCENARIO" in
    SU-12-ssh) run_journey ssh-diagnose fixture-service:active ;;
    SU-12-cloudstack) run_journey cloudstack-inventory fixture-vm ;;
    SU-12-kubernetes) run_journey kubernetes-list fixture-pod ;;
    SU-12-helm) run_journey helm-list-direct fixture-release ;;
    SU-12-ansible) run_journey ansible-check 'changed=0' /scenario/ansible ;;
    SU-12-host-maintenance)
      printf 'authority=typed-verb:host-maintenance consequence=recoverable cwd=/scenario/fixtures\n' >> "$RAW"
      guard verb run host-maintenance --confirm-within 1 --socket "$SOCKET" >>"$RAW" 2>&1
      [ -f /scenario/fixtures/maintenance-applied ]
      sleep 5
      [ ! -e /scenario/fixtures/maintenance-applied ]
      ;;
    SU-12-api)
      mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME"
      printf '%s' synthetic-fixture-token | guard secrets add fixture/api-token >>"$RAW" 2>&1
      run_journey fixture-api-status fixture-api:healthy
      ! grep -q 'synthetic-fixture-token' "$RAW"
      ;;
    *) return 2 ;;
  esac
}

postcheck() {
  case "$SCENARIO" in
    SU-12-api)
      if ! grep -q 'synthetic-fixture-token' /scenario/data/audit.jsonl \
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
      record_result passed "intended policy" "the typed workload completed inside the isolated fake environment"
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
  local uid root
  [ "$(id -u)" -eq 0 ]
  setup_fixture
  for uid in 1000 1001 1002; do
    root="/scenario/principals/$uid"
    mkdir -p "$root/phase-output" "$root/results"
    chmod 0710 "$root"
    chmod 0750 "$root/phase-output" "$root/results"
    chown -R "$uid:0" "$root"
  done
  mkdir -p "$COLLECTOR_RESULTS" "$COLLECTOR_PHASES"
  # The operator persona (uid 1000) is the only principal that can read the
  # admin token; the daemon receives it through stdin, and uids 1001/1002
  # hold neither the file nor the value.
  printf 'synthetic-operator-token\n' > /scenario/run/admin.token
  chmod 0400 /scenario/run/admin.token
  chown 1000:0 /scenario/run/admin.token
  chown -R 0:0 "$COLLECTOR_ROOT"
  chmod 0700 "$COLLECTOR_ROOT" "$COLLECTOR_RESULTS" "$COLLECTOR_PHASES"
  chown -R 1000:1000 /scenario/home /scenario/config /scenario/data /scenario/raw \
    /scenario/fixtures /scenario/bin /scenario/ansible /scenario/run
  chown 1000:1000 /scenario
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
    {
      echo "# $scenario"
      echo
      echo "- Result: failed"
      echo "- Classification: fixture defect"
      echo "- Evidence: the root collector did not receive one matching successful candidate result"
      echo "- Isolation: rootless container, private daemon/socket/database/fixtures/principal/network namespace, network disabled"
      echo "- Raw transcript: retained only in the ephemeral scenario volume and removed during teardown"
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
  *) echo "usage: synthetic-user.sh daemon|run|phase SCENARIO [PHASE]" >&2; exit 2 ;;
esac
