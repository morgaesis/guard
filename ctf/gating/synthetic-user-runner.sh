#!/bin/bash
# Run each synthetic-user contract in a separate rootless Podman container.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE="${GUARD_SU_IMAGE:-localhost/guard-gating}"
CATALOG_SOURCE="$REPO_ROOT/ctf/gating/verbs.yaml"
CATALOG_DIRECTORY_DESTINATION=/authority
CATALOG_LOCK_DESTINATION="$CATALOG_DIRECTORY_DESTINATION/.verbs.yaml.learning-lock"
EVIDENCE_ROOT="$REPO_ROOT/.cache/synthetic-user"
RESULTS_DIR="$EVIDENCE_ROOT/scenarios"
STATUS_FILE="$EVIDENCE_ROOT/status.md"
MEMORY="${GUARD_SU_MEMORY:-2g}"
CPUS="${GUARD_SU_CPUS:-2}"
PIDS="${GUARD_SU_PIDS:-256}"
PREFIX="guard-su"
ACTIVE_SCENARIO=""
RUN_ID="${GUARD_SU_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
RUN_DIR=""
MANIFEST=""
OUTCOMES_FILE=""
CLEANUP_MANIFEST=""
HOST_FAILURE_PHASE=""
HOST_FAILURE_CATEGORY=""
HOST_FAILURE_EXEC_STATUS=""
HOST_FAILURE_EVIDENCE=""

ensure_private_directory() {
  mkdir -p "$1"
  chmod 0700 "$1"
}

ensure_private_file() {
  chmod 0600 "$1"
}

write_status() {
  local scenario="$1" container="$2" volume="$3" result="$4" issue="$5" next="$6"
  {
    echo "# Synthetic-user status"
    echo
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
  ensure_private_file "$STATUS_FILE"
}

finalize_manifest_status() {
  local status="$1" outcomes="$2" temporary="${MANIFEST}.tmp"
  sed "s/^- Status: running$/- Status: $status/" "$MANIFEST" > "$temporary"
  cat "$outcomes" >> "$temporary"
  ensure_private_file "$temporary"
  mv "$temporary" "$MANIFEST"
  ensure_private_file "$MANIFEST"
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
  ensure_private_file "$evidence"
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
  podman cp "$container:/scenario/collector/results/$scenario.md" "$RESULTS_DIR/$scenario.md"
  ensure_private_file "$RESULTS_DIR/$scenario.md"
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
  ensure_private_file "$RESULTS_DIR/$scenario.md"
}

expected_container_mounts() {
  local volume_source="$1" catalog_directory_source="$2" catalog_lock_source="$3"
  printf 'bind\t%s\tfalse\t%s\n' \
    "$CATALOG_DIRECTORY_DESTINATION" "$catalog_directory_source"
  printf 'bind\t%s\ttrue\t%s\n' \
    "$CATALOG_LOCK_DESTINATION" "$catalog_lock_source"
  printf 'volume\t/scenario\ttrue\t%s\n' "$volume_source"
}

normalize_container_mounts() {
  LC_ALL=C sort
}

validate_container_mounts() {
  local observed="$1" volume_source="$2" catalog_directory_source="$3" catalog_lock_source="$4"
  local normalized expected
  normalized="$(printf '%s\n' "$observed" | normalize_container_mounts)"
  expected="$(expected_container_mounts \
    "$volume_source" "$catalog_directory_source" "$catalog_lock_source" |
    normalize_container_mounts)"
  [ "$normalized" = "$expected" ]
}

reject_mount_mutation() {
  local description="$1" observed="$2" volume_source="$3"
  local catalog_directory_source="$4" catalog_lock_source="$5"
  if validate_container_mounts "$observed" \
    "$volume_source" "$catalog_directory_source" "$catalog_lock_source"; then
    echo "synthetic-user mount mutation was accepted: $description" >&2
    return 1
  fi
}

assert_isolated_container() {
  local container="$1" scenario="$2" volume_source="$3"
  local catalog_directory_source="$4" catalog_lock_source="$5"
  local expected_user mounts capabilities groups observed_catalog_source observed_lock_source
  if caller_identity_scenario "$scenario"; then
    expected_user=0:0
  else
    expected_user=1000:1000
  fi
  [ "$(podman inspect --format '{{.HostConfig.NetworkMode}}' "$container")" = none ]
  [ "$(podman inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container")" = true ]
  [ "$(podman inspect --format '{{.Config.User}}' "$container")" = "$expected_user" ]
  podman inspect --format '{{json .HostConfig.SecurityOpt}}' "$container" | grep -Fq 'no-new-privileges'
  podman inspect --format '{{json .HostConfig.CapDrop}}' "$container" | grep -Fq 'ALL'
  capabilities="$(podman inspect --format '{{json .HostConfig.CapAdd}}' "$container")"
  [ "$capabilities" = '["CAP_SETGID","CAP_SETUID"]' ] \
    || [ "$capabilities" = '["CAP_SETUID","CAP_SETGID"]' ]
  groups="$(podman inspect --format '{{range .HostConfig.GroupAdd}}{{println .}}{{end}}' "$container")"
  validate_supplementary_groups "$scenario" "$groups"
  mounts="$(podman inspect --format '{{range .Mounts}}{{printf "%s\t%s\t%t\t%s\n" .Type .Destination .RW .Source}}{{end}}' "$container")"
  validate_container_mounts "$mounts" \
    "$volume_source" "$catalog_directory_source" "$catalog_lock_source"
  observed_catalog_source="$(podman inspect --format '{{range .Mounts}}{{if eq .Destination "/authority"}}{{.Source}}{{end}}{{end}}' "$container")"
  observed_lock_source="$(podman inspect --format '{{range .Mounts}}{{if eq .Destination "/authority/.verbs.yaml.learning-lock"}}{{.Source}}{{end}}{{end}}' "$container")"
  [ "$(readlink -f "$observed_catalog_source")" = \
    "$(readlink -f "$catalog_directory_source")" ]
  [ "$(readlink -f "$observed_lock_source")" = \
    "$(readlink -f "$catalog_lock_source")" ]
  [ "$(sha256sum "$catalog_directory_source/verbs.yaml" | awk '{print $1}')" = \
    "$(sha256sum "$CATALOG_SOURCE" | awk '{print $1}')" ]
}

caller_identity_scenario() {
  case "$1" in
    SU-12-api|SU-12-ansible) return 0 ;;
    *) return 1 ;;
  esac
}

daemon_container_user() {
  if caller_identity_scenario "$1"; then
    printf '%s\n' 0:0
  else
    printf '%s\n' 1000:1000
  fi
}

daemon_group_arguments() {
  printf '%s\n' --group-add 2000
  if ! caller_identity_scenario "$1"; then
    printf '%s\n' --group-add 1003
  fi
}

expected_supplementary_groups() {
  if caller_identity_scenario "$1"; then
    printf '%s\n' 2000
  else
    printf '%s\n' 1003,2000
  fi
}

normalize_supplementary_groups() {
  awk '
    NF == 0 { next }
    NF != 1 || $1 !~ /^[0-9]+$/ { invalid = 1; next }
    { print $1 }
    END { if (invalid) exit 1 }
  ' | LC_ALL=C sort -n | paste -sd, -
}

validate_supplementary_groups() {
  local scenario="$1" observed="$2" normalized
  normalized="$(printf '%s\n' "$observed" | normalize_supplementary_groups)" || return 1
  [ "$normalized" = "$(expected_supplementary_groups "$scenario")" ]
}

reject_group_mutation() {
  local description="$1" scenario="$2" observed="$3"
  if validate_supplementary_groups "$scenario" "$observed"; then
    echo "synthetic-user group mutation was accepted: $description" >&2
    return 1
  fi
}

principal_name_for_uid() {
  case "$1" in
    1000) printf '%s\n' guarddaemon ;;
    1001) printf '%s\n' agent ;;
    1002) printf '%s\n' other-agent ;;
    *) return 2 ;;
  esac
}

assert_daemon_runtime_boundary() {
  local container="$1" scenario="$2" daemon_uid mode expected_groups
  if caller_identity_scenario "$scenario"; then
    daemon_uid=0
    mode=caller
  else
    daemon_uid=1000
    mode=fixed
  fi
  expected_groups="$(expected_supplementary_groups "$scenario")"
  podman exec --user 0:0 \
    --env "GUARD_SU_DAEMON_UID=$daemon_uid" \
    --env "GUARD_SU_DAEMON_MODE=$mode" \
    --env "GUARD_SU_EXPECTED_GROUPS=$expected_groups" \
    "$container" /bin/sh -c '
    set -eu
    pids=$(pgrep -u "$GUARD_SU_DAEMON_UID" -x guard)
    [ "$(printf "%s\n" "$pids" | sed "/^$/d" | wc -l)" -eq 1 ] || exit 1
    cap_eff=$(awk "/^CapEff:/ { value = tolower(\$2); sub(/^0+/, \"\", value); print value == \"\" ? \"0\" : value }" /proc/$pids/status)
    [ "$cap_eff" = c0 ]
    groups=$(awk "/^Groups:/ { for (field = 2; field <= NF; field++) print \$field }" /proc/$pids/status |
      LC_ALL=C sort -n | paste -sd, -)
    [ "$groups" = "$GUARD_SU_EXPECTED_GROUPS" ]
    if [ "$GUARD_SU_DAEMON_MODE" = caller ]; then
      [ "$(stat -c "%u:%g:%a" /scenario/run/admin.token)" = 1000:0:440 ]
    else
      [ "$(stat -c "%u:%g:%a" /scenario/run/admin.token)" = 1000:0:400 ]
    fi
    [ "$(stat -c "%a:%G" /scenario/run/guard.sock)" = 660:guard-clients ]
  '
  podman exec --user agent "$container" test -S /scenario/run/guard.sock
  podman exec --user other-agent "$container" test -S /scenario/run/guard.sock
  podman exec --user guarddaemon "$container" test -r /scenario/run/admin.token
  if podman exec --user agent "$container" test -r /scenario/run/admin.token; then
    return 1
  fi
  if podman exec --user other-agent "$container" test -r /scenario/run/admin.token; then
    return 1
  fi
  podman exec --user agent "$container" test -r /scenario/api-contract/token.sha256
  podman exec --user other-agent "$container" test -r /scenario/api-contract/token.sha256
  if podman exec --user agent "$container" test -r /scenario/api-contract/token; then
    return 1
  fi
  if podman exec --user other-agent "$container" test -r /scenario/api-contract/token; then
    return 1
  fi
}

sanitize_startup_diagnostics() {
  sed -E \
    -e 's/[[:cntrl:]]/ /g' \
    -e 's/([A-Za-z_][A-Za-z0-9_]*(TOKEN|KEY|SECRET|PASS(WORD)?|CRED(ENTIAL)?)[A-Za-z0-9_]*)=[^[:space:]]+/\1=[redacted-value]/g' \
    -e 's/((Bearer|token|key|secret|password|credential)[[:space:]:=]+)[^[:space:]]+/\1[redacted-value]/gI' \
    -e 's/gr-[A-Za-z0-9_-]+/[redacted-handle]/g' \
    -e 's/[0-9A-Fa-f]{24,}/[redacted-value]/g' \
    -e 's/[A-Za-z0-9+/_-]{32,}={0,2}/[redacted-value]/g' \
    -e 's#/(scenario|tmp)/[^[:space:]]*#[redacted-path]#g' |
    cut -c 1-240
}

collect_startup_diagnostics() {
  local container="$1" scenario="$2" evidence
  evidence="$RESULTS_DIR/$scenario.startup-diagnostics.md"
  {
    echo "# $scenario daemon startup diagnostics"
    echo
    echo '## Container output'
    timeout --kill-after=1s 5s podman logs --tail 120 "$container" 9>&- 2>&1 \
      || echo '[container log unavailable]'
    echo
    echo '## Daemon log'
    timeout --kill-after=1s 5s podman cp \
      "$container:/scenario/raw/daemon.log" - 9>&- 2>/dev/null \
      | tar -xOf - 2>/dev/null \
      | tail -n 160 \
      || echo '[daemon log collection unavailable]'
  } | sanitize_startup_diagnostics > "$evidence"
  ensure_private_file "$evidence"
}

resource_exists() {
  local type="$1" name="$2"
  case "$type" in
    container) podman container inspect "$name" >/dev/null 2>&1 ;;
    volume) podman volume inspect "$name" >/dev/null 2>&1 ;;
    *) return 2 ;;
  esac
}

resource_label() {
  local type="$1" name="$2" label="$3"
  case "$type" in
    container) podman container inspect --format "{{index .Config.Labels \"$label\"}}" "$name" ;;
    volume) podman volume inspect --format "{{index .Labels \"$label\"}}" "$name" ;;
    *) return 2 ;;
  esac
}

resource_matches_manifest_labels() {
  local type="$1" name="$2" scenario="$3"
  [ "$(resource_label "$type" "$name" guard.synthetic-user.run)" = "$RUN_ID" ] \
    && [ "$(resource_label "$type" "$name" guard.synthetic-user.scenario)" = "$scenario" ]
}

manifest_has_resource() {
  local type="$1" name="$2" scenario="$3"
  awk -F '\t' -v type="$type" -v name="$name" -v scenario="$scenario" \
    '($1 == "pending" || $1 == "resource") && $2 == type && $3 == name && $4 == scenario { found = 1 } END { exit !found }' \
    "$CLEANUP_MANIFEST"
}

manifest_has_created_resource() {
  local type="$1" name="$2" scenario="$3"
  awk -F '\t' -v type="$type" -v name="$name" -v scenario="$scenario" \
    '$1 == "resource" && $2 == type && $3 == name && $4 == scenario { found = 1 } END { exit !found }' \
    "$CLEANUP_MANIFEST"
}

scenario_is_preserved() {
  local scenario="$1"
  awk -F '\t' -v scenario="$scenario" \
    '$1 == "preserve" && $2 == scenario { found = 1 } END { exit !found }' "$CLEANUP_MANIFEST"
}

register_resource() {
  local type="$1" name="$2" scenario="$3"
  if ! resource_matches_manifest_labels "$type" "$name" "$scenario"; then
    echo "synthetic-user resource labels do not match the active run: $type $name" >&2
    return 1
  fi
  if ! manifest_has_created_resource "$type" "$name" "$scenario"; then
    printf 'resource\t%s\t%s\t%s\n' "$type" "$name" "$scenario" >> "$CLEANUP_MANIFEST"
  fi
}

register_pending_resource() {
  local type="$1" name="$2" scenario="$3"
  if ! manifest_has_resource "$type" "$name" "$scenario"; then
    printf 'pending\t%s\t%s\t%s\n' "$type" "$name" "$scenario" >> "$CLEANUP_MANIFEST"
  fi
}

mark_preserved() {
  local scenario="$1"
  if ! scenario_is_preserved "$scenario"; then
    printf 'preserve\t%s\n' "$scenario" >> "$CLEANUP_MANIFEST"
  fi
}

cleanup_registered_resource() {
  local type="$1" name="$2" scenario="$3" running
  if ! manifest_has_resource "$type" "$name" "$scenario"; then
    echo "synthetic-user cleanup refused an unmanifested resource: $type $name" >&2
    return 1
  fi
  if ! resource_exists "$type" "$name"; then
    return 0
  fi
  if ! resource_matches_manifest_labels "$type" "$name" "$scenario"; then
    echo "synthetic-user cleanup refused a resource with unexpected labels: $type $name" >&2
    return 1
  fi
  case "$type" in
    container)
      running="$(podman container inspect --format '{{.State.Running}}' "$name")"
      if [ "$running" = true ] && ! podman stop --time 5 "$name"; then
        echo "synthetic-user cleanup could not stop container: $name" >&2
        return 1
      fi
      if ! podman rm "$name"; then
        echo "synthetic-user cleanup could not remove container: $name" >&2
        return 1
      fi
      ;;
    volume)
      if ! podman volume rm "$name"; then
        echo "synthetic-user cleanup could not remove volume: $name" >&2
        return 1
      fi
      ;;
  esac
}

cleanup_scenario() {
  local scenario="$1" type name cleanup_failed=0
  if scenario_is_preserved "$scenario"; then
    return 0
  fi
  for type in container volume; do
    while IFS=$'\t' read -r _ manifest_type name manifest_scenario; do
      if [ "$manifest_type" != "$type" ] || [ "$manifest_scenario" != "$scenario" ]; then
        continue
      fi
      if ! cleanup_registered_resource "$manifest_type" "$name" "$manifest_scenario"; then
        cleanup_failed=1
      fi
    done < "$CLEANUP_MANIFEST"
  done
  return "$cleanup_failed"
}

recover_interrupted_run() {
  local scenario cleanup_failed=0
  [ -f "$CLEANUP_MANIFEST" ] || return 0
  while IFS= read -r scenario; do
    if ! cleanup_scenario "$scenario"; then
      cleanup_failed=1
    fi
  done < <(awk -F '\t' '($1 == "pending" || $1 == "resource") { print $4 }' "$CLEANUP_MANIFEST" | LC_ALL=C sort -u)
  return "$cleanup_failed"
}

assert_cleanup_invariants() {
  local type name scenario cleanup_failed=0
  for type in container volume; do
    if [ "$type" = container ]; then
      while IFS= read -r name; do
        [ -n "$name" ] || continue
        scenario="$(resource_label "$type" "$name" guard.synthetic-user.scenario)"
        if ! manifest_has_resource "$type" "$name" "$scenario" \
          || ! resource_matches_manifest_labels "$type" "$name" "$scenario" \
          || ! scenario_is_preserved "$scenario"; then
          echo "synthetic-user cleanup invariant failed for labeled $type: $name" >&2
          cleanup_failed=1
        fi
      done < <(podman ps -a --filter "label=guard.synthetic-user.run=$RUN_ID" --format '{{.Names}}')
    else
      while IFS= read -r name; do
        [ -n "$name" ] || continue
        scenario="$(resource_label "$type" "$name" guard.synthetic-user.scenario)"
        if ! manifest_has_resource "$type" "$name" "$scenario" \
          || ! resource_matches_manifest_labels "$type" "$name" "$scenario" \
          || ! scenario_is_preserved "$scenario"; then
          echo "synthetic-user cleanup invariant failed for labeled $type: $name" >&2
          cleanup_failed=1
        fi
      done < <(podman volume ls --filter "label=guard.synthetic-user.run=$RUN_ID" --format '{{.Name}}')
    fi
  done
  while IFS=$'\t' read -r _ type name scenario; do
    scenario_is_preserved "$scenario" || continue
    if resource_exists "$type" "$name" \
      && ! resource_matches_manifest_labels "$type" "$name" "$scenario"; then
      echo "synthetic-user preserved resource is relabeled: $type $name" >&2
      cleanup_failed=1
    fi
  done < "$CLEANUP_MANIFEST"
  return "$cleanup_failed"
}

self_test() {
  local test_dir test_evidence generated groups mount_contract
  local test_volume_source=/fixture/volume
  local test_catalog_directory_source=/fixture/authority
  local test_catalog_lock_source=/fixture/authority/.verbs.yaml.learning-lock
  case "$IMAGE" in
    localhost/*) ;;
    *)
      echo "synthetic-user image must use a localhost-qualified local reference" >&2
      return 1
      ;;
  esac
  test_dir="$(mktemp -d)"
  [ "$(stat -c '%a' "$test_dir")" = 700 ]
  RESULTS_DIR="$test_dir"
  STATUS_FILE="$test_dir/status.md"
  RUN_DIR="$REPO_ROOT/.cache/synthetic-user/runs/self-test"
  write_status SU-TEST none none testing none verify
  [ "$(stat -c '%a' "$STATUS_FILE")" = 600 ]
  grep -Fq -- "- Run evidence: \`.cache/synthetic-user/runs/self-test\`" "$STATUS_FILE"
  if grep -Eq '^- (Worktree|Branch):' "$STATUS_FILE" \
    || grep -Fq "$REPO_ROOT" "$STATUS_FILE"; then
    return 1
  fi
  record_host_failure SU-TEST 'phase-gr-test-handle /scenario/private' access 125
  test_evidence="$RESULTS_DIR/SU-TEST.host-failure.md"
  [ "$(stat -c '%a' "$test_evidence")" = 600 ]
  grep -Fq "Phase: \`phase-[redacted-handle] [redacted-path]\`" "$test_evidence"
  grep -Fq "Command category: \`access\`" "$test_evidence"
  grep -Fq "Podman exec status: \`125\`" "$test_evidence"
  if grep -Fq 'gr-test-handle' "$test_evidence"; then
    return 1
  fi
  if grep -Fq '/scenario/private' "$test_evidence"; then
    return 1
  fi
  [ "$(daemon_container_user SU-01)" = 1000:1000 ]
  [ "$(daemon_container_user SU-12-api)" = 0:0 ]
  [ "$(daemon_container_user SU-12-ansible)" = 0:0 ]
  groups="$(daemon_group_arguments SU-01)"
  [ "$groups" = $'--group-add\n2000\n--group-add\n1003' ]
  groups="$(daemon_group_arguments SU-12-api)"
  [ "$groups" = $'--group-add\n2000' ]
  mount_contract="$(expected_container_mounts \
    "$test_volume_source" "$test_catalog_directory_source" "$test_catalog_lock_source")"
  validate_container_mounts "$mount_contract" \
    "$test_volume_source" "$test_catalog_directory_source" "$test_catalog_lock_source"
  reject_mount_mutation 'a writable catalog-directory bind' \
    $'bind\t/authority\ttrue\t/fixture/authority\nbind\t/authority/.verbs.yaml.learning-lock\ttrue\t/fixture/authority/.verbs.yaml.learning-lock\nvolume\t/scenario\ttrue\t/fixture/volume' \
    "$test_volume_source" "$test_catalog_directory_source" "$test_catalog_lock_source"
  reject_mount_mutation 'a read-only learning-lock bind' \
    $'bind\t/authority\tfalse\t/fixture/authority\nbind\t/authority/.verbs.yaml.learning-lock\tfalse\t/fixture/authority/.verbs.yaml.learning-lock\nvolume\t/scenario\ttrue\t/fixture/volume' \
    "$test_volume_source" "$test_catalog_directory_source" "$test_catalog_lock_source"
  reject_mount_mutation 'a missing catalog-directory bind' \
    $'bind\t/authority/.verbs.yaml.learning-lock\ttrue\t/fixture/authority/.verbs.yaml.learning-lock\nvolume\t/scenario\ttrue\t/fixture/volume' \
    "$test_volume_source" "$test_catalog_directory_source" "$test_catalog_lock_source"
  reject_mount_mutation 'a missing learning-lock bind' \
    $'bind\t/authority\tfalse\t/fixture/authority\nvolume\t/scenario\ttrue\t/fixture/volume' \
    "$test_volume_source" "$test_catalog_directory_source" "$test_catalog_lock_source"
  reject_mount_mutation 'a redirected catalog-directory source' \
    $'bind\t/authority\tfalse\t/fixture/redirected\nbind\t/authority/.verbs.yaml.learning-lock\ttrue\t/fixture/authority/.verbs.yaml.learning-lock\nvolume\t/scenario\ttrue\t/fixture/volume' \
    "$test_volume_source" "$test_catalog_directory_source" "$test_catalog_lock_source"
  reject_mount_mutation 'a redirected learning-lock source' \
    $'bind\t/authority\tfalse\t/fixture/authority\nbind\t/authority/.verbs.yaml.learning-lock\ttrue\t/fixture/redirected-lock\nvolume\t/scenario\ttrue\t/fixture/volume' \
    "$test_volume_source" "$test_catalog_directory_source" "$test_catalog_lock_source"
  reject_mount_mutation 'an additional writable catalog child' \
    "$mount_contract"$'\nbind\t/authority/extra\ttrue\t/fixture/extra' \
    "$test_volume_source" "$test_catalog_directory_source" "$test_catalog_lock_source"
  reject_mount_mutation 'an additional host bind' \
    "$mount_contract"$'\nbind\t/host\tfalse\t/host' \
    "$test_volume_source" "$test_catalog_directory_source" "$test_catalog_lock_source"
  validate_supplementary_groups SU-01 $'2000\n1003'
  validate_supplementary_groups SU-12-api 2000
  reject_group_mutation 'missing fixed private group' SU-01 2000
  reject_group_mutation 'unexpected fixed root group' SU-01 $'0\n1003\n2000'
  reject_group_mutation 'unexpected fixed group' SU-01 $'1002\n1003\n2000'
  reject_group_mutation 'duplicate fixed group' SU-01 $'1003\n2000\n2000'
  reject_group_mutation 'missing caller client group' SU-12-api ''
  reject_group_mutation 'unexpected caller root group' SU-12-api $'0\n2000'
  reject_group_mutation 'unexpected caller private group' SU-12-api $'1003\n2000'
  if caller_identity_scenario SU-01; then
    return 1
  fi
  generated="$(printf '%032x' 0)"
  test_evidence="$test_dir/startup-diagnostics.md"
  printf 'FIXTURE_API_TOKEN=%s /scenario/private gr-%s\n' "$generated" "$generated" |
    sanitize_startup_diagnostics > "$test_evidence"
  ensure_private_file "$test_evidence"
  [ "$(stat -c '%a' "$test_evidence")" = 600 ]
  grep -Fq 'FIXTURE_API_TOKEN=[redacted-value]' "$test_evidence"
  grep -Fq '[redacted-path]' "$test_evidence"
  grep -Fq '[redacted-handle]' "$test_evidence"
  if grep -Fq "$generated" "$test_evidence"; then
    return 1
  fi
  [ "$(command_category_for_phase hold)" = access ]
  GUARD_SU_TEST_COPY_FAILURE=1
  export GUARD_SU_TEST_COPY_FAILURE
  if copy_scenario_result ignored SU-TEST; then
    return 1
  fi
  unset GUARD_SU_TEST_COPY_FAILURE
  MANIFEST="$test_dir/manifest.md"
  local outcomes="$test_dir/outcomes.md"
  printf '%s\n' '# Synthetic-user run manifest' '- Status: running' > "$MANIFEST"
  ensure_private_file "$MANIFEST"
  printf '%s\n' '' '## Outcomes' '- Status: complete catalog passed' > "$outcomes"
  ensure_private_file "$outcomes"
  finalize_manifest_status complete "$outcomes"
  grep -Fq -- '- Status: complete' "$MANIFEST"
  grep -Fq -- '- Status: complete catalog passed' "$MANIFEST"
  if grep -Fq -- '- Status: running' "$MANIFEST"; then
    return 1
  fi
  CLEANUP_MANIFEST="$test_dir/cleanup.manifest"
  printf 'resource\tcontainer\tguard-su-test\tSU-TEST\n' > "$CLEANUP_MANIFEST"
  ensure_private_file "$CLEANUP_MANIFEST"
  manifest_has_resource container guard-su-test SU-TEST
  if manifest_has_resource volume guard-su-test SU-TEST; then
    return 1
  fi
  mark_preserved SU-TEST
  scenario_is_preserved SU-TEST
  rm -r "$test_dir"
}

if [ "${1:-}" = --self-test ]; then
  self_test
  echo "synthetic-user runner self-test: passed"
  exit 0
fi

case "$RUN_ID" in
  ''|*[!A-Za-z0-9._-]*)
    echo "synthetic-user run ID must contain only letters, numbers, dot, underscore, or hyphen" >&2
    exit 2
    ;;
esac

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
# Do not let Podman or its monitor inherit the runner's advisory-lock file
# descriptor. A deliberately preserved failed container must not block the
# next diagnostic run after this runner exits.
podman() {
  command podman "$@" 9>&-
}
ensure_private_directory "$EVIDENCE_ROOT"
ensure_private_directory "$EVIDENCE_ROOT/runs"
exec 9>"$EVIDENCE_ROOT/runner.lock"
ensure_private_file "$EVIDENCE_ROOT/runner.lock"
if ! flock -n 9; then
  echo "another synthetic-user run is active in this worktree" >&2
  exit 2
fi

CATALOG=(SU-01 SU-02 SU-03 SU-04 SU-05 SU-06 SU-07 SU-08 SU-09 SU-10 SU-11
  SU-12-service SU-12-cloudstack SU-12-kubernetes SU-12-helm SU-12-ansible
  SU-12-workload-maintenance SU-12-api SU-13 SU-14 SU-15 SU-16 SU-17 SU-18
  SU-19 SU-20 SU-21 SU-22)
if [ "$#" -eq 0 ]; then
  set -- "${CATALOG[@]}"
fi
TOTAL="$#"
SELECTED=("$@")
declare -A SELECTED_SEEN=()
for scenario in "${SELECTED[@]}"; do
  case "$scenario" in
    ''|*[!A-Za-z0-9-]*)
      echo "synthetic-user scenario name is invalid: $scenario" >&2
      exit 2
      ;;
  esac
  if [ -n "${SELECTED_SEEN[$scenario]:-}" ]; then
    echo "synthetic-user scenario selected more than once: $scenario" >&2
    exit 2
  fi
  SELECTED_SEEN[$scenario]=1
done
FULL_CATALOG=false
if [ "${SELECTED[*]}" = "${CATALOG[*]}" ]; then
  FULL_CATALOG=true
fi
RUN_DIR="$EVIDENCE_ROOT/runs/$RUN_ID"
RESULTS_DIR="$RUN_DIR/scenarios"
MANIFEST="$RUN_DIR/manifest.md"
CLEANUP_MANIFEST="$RUN_DIR/cleanup.manifest"
ensure_private_directory "$RUN_DIR"
ensure_private_directory "$RESULTS_DIR"
if ! recover_interrupted_run; then
  echo "synthetic-user could not recover interrupted resources for run $RUN_ID" >&2
  exit 1
fi
touch "$CLEANUP_MANIFEST"
ensure_private_file "$CLEANUP_MANIFEST"
SOURCE_MANIFEST="$RUN_DIR/source-files.sha256"
(
  cd "$REPO_ROOT"
  find Cargo.toml Cargo.lock build.rs deny.toml src config tests examples \
    ctf/gating/README.md ctf/gating/Containerfile ctf/gating/run.sh \
    ctf/gating/verbs.yaml ctf/gating/attack.sh \
    ctf/gating/synthetic-user-runner.sh ctf/gating/synthetic-user.sh \
    ctf/gating/fake-llm.rs -type f -print0 |
    LC_ALL=C sort -z |
    xargs -0 sha256sum
) > "$SOURCE_MANIFEST"
ensure_private_file "$SOURCE_MANIFEST"
SOURCE_DIGEST="$(sha256sum "$SOURCE_MANIFEST" | cut -d ' ' -f 1)"
printf '%s\n' "runs/$RUN_ID" > "$EVIDENCE_ROOT/latest-run"
ensure_private_file "$EVIDENCE_ROOT/latest-run"
{
  echo "# Synthetic-user run manifest"
  echo
  echo "- Run: \`$RUN_ID\`"
  echo "- Commit: \`$(git -C "$REPO_ROOT" rev-parse HEAD)\`"
  echo "- Source manifest: \`source-files.sha256\`"
  echo "- Cleanup manifest: \`cleanup.manifest\`"
  echo "- Source digest: \`$SOURCE_DIGEST\`"
  echo "- Image: \`$(podman image inspect "$IMAGE" --format '{{.Id}}')\`"
  echo "- Complete catalog: \`$FULL_CATALOG\`"
  echo "- Selected scenarios: \`${SELECTED[*]}\`"
  echo "- Status: running"
} > "$MANIFEST"
ensure_private_file "$MANIFEST"

# This callback is invoked indirectly by the EXIT trap below.
# shellcheck disable=SC2317
cleanup_active() {
  if [ -n "$ACTIVE_SCENARIO" ]; then
    if ! cleanup_scenario "$ACTIVE_SCENARIO"; then
      echo "synthetic-user cleanup failed; retaining $CLEANUP_MANIFEST for recovery" >&2
    fi
  fi
  if [ -n "$OUTCOMES_FILE" ] && [ -f "$OUTCOMES_FILE" ]; then
    rm -- "$OUTCOMES_FILE"
  fi
}

trap cleanup_active EXIT
trap 'exit 130' INT TERM

run_one() {
  local scenario="$1"
  local slug container init_container volume authority_volume result exec_status daemon_user
  local volume_source authority_source catalog_directory_source catalog_lock_source
  local -a scenario_environment=(--env GUARD_SWEEPER_GRACE_SECS=1) daemon_groups=()
  HOST_FAILURE_PHASE=""
  HOST_FAILURE_CATEGORY=""
  HOST_FAILURE_EXEC_STATUS=""
  HOST_FAILURE_EVIDENCE=""
  if [ -f "$RESULTS_DIR/$scenario.host-failure.md" ]; then
    rm -- "$RESULTS_DIR/$scenario.host-failure.md"
  fi
  slug="$(printf '%s' "$scenario" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-')"
  container="$PREFIX-$slug-$RUN_ID"
  init_container="$container-init"
  volume="$PREFIX-$slug-$RUN_ID-data"
  authority_volume="$PREFIX-$slug-$RUN_ID-authority"
  ACTIVE_SCENARIO="$scenario"
  result="blocked"
  trap 'cleanup_scenario "$scenario"; trap - RETURN' RETURN

  write_status "$scenario" "$container" "$volume,$authority_volume" "starting" "none established" "create the isolated fixture"
  register_pending_resource volume "$volume" "$scenario"
  if ! podman volume create \
    --label "guard.synthetic-user.run=$RUN_ID" \
    --label "guard.synthetic-user.scenario=$scenario" \
    "$volume" >/dev/null; then
    record_host_failure "$scenario" volume-create volume-create 1
    return 1
  fi
  if ! register_resource volume "$volume" "$scenario"; then
    record_host_failure "$scenario" volume-manifest volume-create 1
    return 1
  fi
  register_pending_resource volume "$authority_volume" "$scenario"
  if ! podman volume create \
    --label "guard.synthetic-user.run=$RUN_ID" \
    --label "guard.synthetic-user.scenario=$scenario" \
    "$authority_volume" >/dev/null; then
    record_host_failure "$scenario" authority-volume-create volume-create 1
    return 1
  fi
  if ! register_resource volume "$authority_volume" "$scenario"; then
    record_host_failure "$scenario" authority-volume-manifest volume-create 1
    return 1
  fi

  if [ "$scenario" = SU-18 ]; then
    scenario_environment+=(--env GUARD_ACCESS_TTL_SECS=3)
  fi
  daemon_user="$(daemon_container_user "$scenario")"
  mapfile -t daemon_groups < <(daemon_group_arguments "$scenario")
  register_pending_resource container "$init_container" "$scenario"
  if ! podman create \
    --name "$init_container" \
    --label "guard.synthetic-user.run=$RUN_ID" \
    --label "guard.synthetic-user.scenario=$scenario" \
    --user 0:0 \
    --network none \
    --read-only \
    --cap-drop ALL \
    --cap-add CHOWN \
    --security-opt no-new-privileges \
    --memory "$MEMORY" \
    --memory-swap "$MEMORY" \
    --cpus "$CPUS" \
    --pids-limit "$PIDS" \
    --tmpfs /tmp:rw,nosuid,nodev,size=256m,mode=1777 \
    --volume "$volume:/scenario:rw" \
    --volume "$authority_volume:/authority:rw" \
    --entrypoint /synthetic-user.sh \
    "$IMAGE" prepare-principals "$scenario" >/dev/null; then
    record_host_failure "$scenario" principal-output-create container-create 1
    return 1
  fi
  if ! register_resource container "$init_container" "$scenario"; then
    record_host_failure "$scenario" principal-output-manifest container-create 1
    return 1
  fi
  if ! podman start --attach "$init_container"; then
    record_host_failure "$scenario" principal-output-setup container-start 1
    return 1
  fi
  if ! cleanup_registered_resource container "$init_container" "$scenario"; then
    record_host_failure "$scenario" principal-output-cleanup cleanup 1
    return 1
  fi
  volume_source="$(podman volume inspect --format '{{.Mountpoint}}' "$volume")"
  volume_source="$(readlink -f "$volume_source")"
  authority_source="$(podman volume inspect --format '{{.Mountpoint}}' "$authority_volume")"
  catalog_directory_source="$(readlink -f "$authority_source")"
  catalog_lock_source="$catalog_directory_source/.verbs.yaml.learning-lock"
  if [ ! -d "$catalog_directory_source" ] \
    || [ ! -f "$catalog_directory_source/verbs.yaml" ] \
    || [ ! -f "$catalog_lock_source" ] \
    || [ "$(sha256sum "$catalog_directory_source/verbs.yaml" | awk '{print $1}')" != \
      "$(sha256sum "$CATALOG_SOURCE" | awk '{print $1}')" ]; then
    record_host_failure "$scenario" protected-catalog-source fixture-setup 1
    return 1
  fi
  register_pending_resource container "$container" "$scenario"
  if podman create \
    --name "$container" \
    --label "guard.synthetic-user.run=$RUN_ID" \
    --label "guard.synthetic-user.scenario=$scenario" \
    --user "$daemon_user" \
    --network none \
    --read-only \
    --cap-drop ALL \
    --cap-add SETUID \
    --cap-add SETGID \
    "${daemon_groups[@]}" \
    --security-opt no-new-privileges \
    --memory "$MEMORY" \
    --memory-swap "$MEMORY" \
    --cpus "$CPUS" \
    --pids-limit "$PIDS" \
    --tmpfs /tmp:rw,nosuid,nodev,size=256m,mode=1777 \
    --tmpfs /var/log:rw,nosuid,nodev,size=32m,mode=0700 \
    --volume "$volume:/scenario:rw" \
    --volume "$catalog_directory_source:$CATALOG_DIRECTORY_DESTINATION:ro" \
    --volume "$catalog_lock_source:$CATALOG_LOCK_DESTINATION:rw" \
    "${scenario_environment[@]}" \
    --entrypoint /synthetic-user.sh \
    "$IMAGE" daemon "$scenario" >/dev/null; then
    :
  else
    exec_status=$?
    record_host_failure "$scenario" container-create container-create "$exec_status"
    return 1
  fi
  if ! register_resource container "$container" "$scenario"; then
    record_host_failure "$scenario" container-manifest container-create 1
    return 1
  fi

  if assert_isolated_container "$container" "$scenario" \
    "$volume_source" "$catalog_directory_source" "$catalog_lock_source"; then
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
    collect_startup_diagnostics "$container" "$scenario"
    record_host_failure "$scenario" daemon-readiness container-readiness 1
    echo "$scenario: isolated Guard daemon did not become ready" >&2
    return 1
  fi
  if ! assert_daemon_runtime_boundary "$container" "$scenario"; then
    record_host_failure "$scenario" daemon-socket-permissions container-setup 1
    return 1
  fi
  case "$scenario" in
    SU-12-api|SU-16)
      if ! podman exec --user 0:0 "$container" /synthetic-user.sh provision-api-secret; then
        record_host_failure "$scenario" api-secret-provision fixture-setup 1
        return 1
      fi
      ;;
  esac

  write_status "$scenario" "$container" "$volume" "running" "under evaluation" "run the deterministic contract"
  if run_scenario "$container" "$scenario"; then
    result="passed"
  else
    result="failed"
    podman exec --user 1000:1000 "$container" /synthetic-user.sh failure "$scenario" || true
  fi
  if [ "$result" = passed ] && [ "$scenario" = SU-12-api ]; then
    if ! podman exec --user 0:0 "$container" /synthetic-user.sh postcheck "$scenario"; then
      result="failed"
    fi
  fi

  if ! podman exec --user 0:0 "$container" \
    /synthetic-user.sh collect-result "$scenario" "$result"; then
    record_host_failure "$scenario" result-finalization evidence-collection 1
    result="failed"
  elif ! podman exec --user 0:0 "$container" \
    grep -Fqx -- "- Result: $result" "/scenario/collector/results/$scenario.md"; then
    record_host_failure "$scenario" result-verification evidence-collection 1
    result="failed"
    if ! podman exec --user 0:0 "$container" \
      /synthetic-user.sh collect-result "$scenario" "$result"; then
      record_host_failure "$scenario" result-finalization evidence-collection 1
    fi
  fi
  if ! copy_scenario_result "$container" "$scenario"; then
    record_host_failure "$scenario" result-copy evidence-copy 1
    write_missing_result_evidence "$scenario"
    result="failed"
  fi
  if [ "$result" = failed ] && [ "${GUARD_SU_KEEP_FAILED:-0}" = 1 ]; then
    echo "$scenario: preserving failed fixture container=$container volumes=$volume,$authority_volume" >&2
    mark_preserved "$scenario"
    ACTIVE_SCENARIO=""
    trap - RETURN
    return 1
  fi
  if ! cleanup_scenario "$scenario"; then
    record_host_failure "$scenario" fixture-cleanup cleanup 1
    return 1
  fi
  ACTIVE_SCENARIO=""
  trap - RETURN
  write_status "$scenario" "none" "none" "$result" "see scenarios/$scenario.md" "continue with the next isolated scenario"
  [ "$result" = passed ]
}

run_phase() {
  local container="$1" scenario="$2" uid="$3" phase="$4" command_category exec_status principal
  command_category="$(command_category_for_phase "$phase")"
  principal="$(principal_name_for_uid "$uid")"
  if podman exec \
    --user "$principal" \
    --env HOME="/tmp/synthetic-home-$uid" \
    --env XDG_CONFIG_HOME="/tmp/synthetic-config-$uid" \
    --env XDG_DATA_HOME="/tmp/synthetic-data-$uid" \
    --env GUARD_ADMIN_TOKEN_FILE=/scenario/run/admin.token \
    "$container" timeout 120 /synthetic-user.sh phase "$scenario" "$phase"
  then
    exec_status=0
  else
    exec_status=$?
  fi
  if ! podman exec --user 0:0 "$container" \
    /synthetic-user.sh collect-phase "$scenario" "$uid" "$phase" "$exec_status"; then
    record_host_failure "$scenario" "$phase" evidence-collection 1
    return 1
  fi
  if [ "$exec_status" -ne 0 ]; then
    record_host_failure "$scenario" "$phase" "$command_category" "$exec_status"
    return "$exec_status"
  fi
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
    collect_startup_diagnostics "$container" "$scenario"
    record_host_failure "$scenario" restart-readiness container-readiness 1
    return 1
  fi
  if ! assert_daemon_runtime_boundary "$container" "$scenario"; then
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
      run_phase "$container" "$scenario" 1001 resume-execution || return
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
      run_phase "$container" "$scenario" 1000 approve-held || return
      run_phase "$container" "$scenario" 1001 resume-held || return
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
    SU-19)
      run_phase "$container" "$scenario" 1001 request-primary || return
      run_phase "$container" "$scenario" 1002 request-secondary || return
      run_phase "$container" "$scenario" 1000 decide || return
      run_phase "$container" "$scenario" 1001 use-primary || return
      run_phase "$container" "$scenario" 1002 use-secondary || return
      run_phase "$container" "$scenario" 1000 verify || return
      ;;
    SU-20)
      run_phase "$container" "$scenario" 1001 request || return
      run_phase "$container" "$scenario" 1002 request-secondary || return
      run_phase "$container" "$scenario" 1000 approve || return
      run_phase "$container" "$scenario" 1001 consume-first || return
      run_phase "$container" "$scenario" 1002 consume-secondary-first || return
      restart_daemon "$container" "$scenario" || return
      run_phase "$container" "$scenario" 1000 revoke-after-restart || return
      run_phase "$container" "$scenario" 1001 post-revoke-primary || return
      run_phase "$container" "$scenario" 1002 post-revoke-secondary || return
      restart_daemon "$container" "$scenario" || return
      run_phase "$container" "$scenario" 1001 after-second-restart-primary || return
      run_phase "$container" "$scenario" 1002 after-second-restart-secondary || return
      run_phase "$container" "$scenario" 1000 verify || return
      ;;
    SU-21)
      run_phase "$container" "$scenario" 1001 discover-and-request || return
      run_phase "$container" "$scenario" 1000 decide || return
      run_phase "$container" "$scenario" 1001 retry-and-use || return
      run_phase "$container" "$scenario" 1000 stale-and-verify || return
      ;;
    SU-22)
      run_phase "$container" "$scenario" 1000 install || return
      run_phase "$container" "$scenario" 1001 request || return
      run_phase "$container" "$scenario" 1000 approve-and-use || return
      run_phase "$container" "$scenario" 1001 consume-before-upgrade || return
      run_phase "$container" "$scenario" 1000 fail-and-rollback || return
      run_phase "$container" "$scenario" 1001 retry-after-rollback || return
      run_phase "$container" "$scenario" 1000 promote-upgrade || return
      run_phase "$container" "$scenario" 1001 verify-client || return
      run_phase "$container" "$scenario" 1000 cleanup || return
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

if ! assert_cleanup_invariants; then
  echo "synthetic-user cleanup invariant failed" >&2
  exit 1
fi

if [ "$failures" -eq 0 ]; then
  manifest_status=complete
else
  manifest_status=failed
fi
OUTCOMES_FILE="${MANIFEST}.outcomes"
{
  echo
  echo "## Outcomes"
  # Early host-side failures can skip result finalization entirely; every
  # selected scenario must still contribute exactly one evidence row.
  for scenario in "${SELECTED[@]}"; do
    if [ ! -f "$RESULTS_DIR/$scenario.md" ]; then
      write_missing_result_evidence "$scenario"
    fi
  done
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
} > "$OUTCOMES_FILE"
ensure_private_file "$OUTCOMES_FILE"
finalize_manifest_status "$manifest_status" "$OUTCOMES_FILE"
cat "$OUTCOMES_FILE"
if [ "$failures" -ne 0 ]; then
  for scenario in "${SELECTED[@]}"; do
    evidence="$RESULTS_DIR/$scenario.md"
    if grep -Fqx -- '- Result: failed' "$evidence"; then
      echo
      echo "## Failure evidence: $scenario"
      # Print only collector-authored summary fields. Raw transcripts and
      # principal phase output remain inside the ephemeral scenario volume.
      sed -n \
        -e '/^- Result: /p' \
        -e '/^- Classification: /p' \
        -e '/^- Evidence: /p' \
        -e '/^- Failure signal: /p' \
        "$evidence"
      if [ -f "$RESULTS_DIR/$scenario.host-failure.md" ]; then
        sed -n \
          -e '/^- Phase: /p' \
          -e '/^- Command category: /p' \
          -e '/^- Podman exec status: /p' \
          "$RESULTS_DIR/$scenario.host-failure.md"
      fi
    fi
  done
fi
rm -- "$OUTCOMES_FILE"
OUTCOMES_FILE=""
write_status "complete" "none" "none" "$((TOTAL - failures)) passed, $failures failed" \
  "see per-scenario evidence" "review the report and integrated diff"
exit "$failures"
