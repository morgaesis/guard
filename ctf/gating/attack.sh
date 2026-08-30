#!/bin/bash
# Adversarial harness for consequence gating. Runs inside the container.
#
# Deployment: the daemon drops approved commands to uid 1003 and the agent is
# uid 1001. The operator gate is bypass-resistant because operator authority is
# the admin bearer token: it lives in a daemon-owned mode-0400 file, the daemon
# receives it through stdin at startup, and the child identity cannot read
# daemon state or operator configuration.
set -u

SOCK=/run/guard/guard.sock
ADMIN_TOKEN_FILE=/run/guard/admin.token
UPSTREAM_KUBECONFIG=/run/guard/upstream.kubeconfig
BROKERED_KUBECONFIG=/run/guard/brokered.kubeconfig
KUBE_PROXY=127.0.0.1:18443
PASS=0
FAIL=0

ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

generate_fixture_value() {
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
}

# Run a guard command as the unprivileged agent (uid 1001) or the operator (1000).
agent()    { runuser -u agent       -- "$@"; }
agent_shim() { runuser -u agent -- env PATH="/shim:/fakebin:/usr/local/bin:/usr/bin:/bin" "$@"; }
operator() { runuser -u guarddaemon -- env GUARD_ADMIN_TOKEN_FILE="$ADMIN_TOKEN_FILE" "$@"; }

handle_of() { grep -oE 'handle:[[:space:]]*[0-9a-f]+' "$1" | awk '{print $2}' | head -1; }

capability_mask() {
  awk '/^CapEff:/ { value = tolower($2); sub(/^0+/, "", value); print value == "" ? "0" : value }' "/proc/$1/status"
}

assert_daemon_boundary() {
  local socket_mode_group
  if [ "$(capability_mask "$DAEMON_PID")" = c0 ]; then
    ok "daemon retained exactly CAP_SETGID and CAP_SETUID"
  else
    bad "daemon capability set differs from CAP_SETGID and CAP_SETUID"
  fi
  socket_mode_group="$(stat -c '%a:%G' "$SOCK")"
  if [ "$socket_mode_group" = 660:guard-clients ]; then
    ok "daemon published the production guard-clients socket boundary"
  else
    bad "daemon socket boundary is $socket_mode_group instead of 660:guard-clients"
  fi
}

start_daemon() {
  setpriv \
    --reuid=guarddaemon \
    --regid=guarddaemon \
    --init-groups \
    --bounding-set=-all,+setgid,+setuid \
    --inh-caps=+setgid,+setuid \
    --ambient-caps=+setgid,+setuid \
    --no-new-privs \
    env HOME=/home/guarddaemon \
      PATH="/fakebin:/usr/local/bin:/usr/bin:/bin" \
      KUBECONFIG="$BROKERED_KUBECONFIG" \
      GUARD_SWEEPER_GRACE_SECS=2 \
      guard server start \
      --no-llm \
      --gate consequence \
      --socket "$SOCK" \
      --socket-group guard-clients \
      --verbs /run/guard/verbs.yaml \
      --state-db /var/lib/guard/state.db \
      --shim-dir /shim \
      --users 1001 \
      --exec-user guardexec \
      --child-env KUBECONFIG \
      --kube-proxy "$KUBE_PROXY" \
      --kubeconfig "$UPSTREAM_KUBECONFIG" \
      --brokered-kubeconfig-out "$BROKERED_KUBECONFIG" \
      --admin-token-stdin \
      < "$ADMIN_TOKEN_FILE" >>/var/log/guard.log 2>&1 &
  DAEMON_PID=$!
}

echo "=== Setup ==="
mkdir -p /work /run/guard /var/lib/guard
mkdir -p /fakebin /shim
install -m 0600 /etc/guard/verbs.yaml /run/guard/verbs.yaml
generate_fixture_value > "$ADMIN_TOKEN_FILE"
printf '\n' >> "$ADMIN_TOKEN_FILE"
chmod 0400 "$ADMIN_TOKEN_FILE"
cat >"$UPSTREAM_KUBECONFIG" <<'EOF'
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
install -o guarddaemon -g guardexec -m 0640 /dev/null "$BROKERED_KUBECONFIG"
echo "hello" > /work/seed.txt
printf '%s\n' '---' '- hosts: web' '  gather_facts: false' '  tasks: []' > /work/site.yml
mkdir -p /work/ansible-project
printf '[defaults]\ninventory = inventory\n' > /work/ansible-project/ansible.cfg
printf 'all\n' > /work/ansible-project/inventory
mkdir -p /work/secret && echo "data" > /work/secret/file
cat >/fakebin/ssh <<'EOF'
#!/bin/sh
case "${SSH_AUTH_SOCK:-}" in
  /run/guard/broker-agent.sock)
    printf 'guarded-ssh:%s:%s:broker-owned\n' "$1" "$(pwd)"
    ;;
  /tmp/direct-agent.sock|/tmp/agent.sock)
  echo "caller ssh agent visible" >&2
  exit 42
    ;;
  "")
    echo "broker ssh agent missing" >&2
    exit 47
    ;;
  *)
    echo "unexpected ssh agent: $SSH_AUTH_SOCK" >&2
    exit 48
    ;;
esac
EOF
cat >/fakebin/kubectl <<'EOF'
#!/bin/sh
[ "${KUBECONFIG:-}" = /run/guard/brokered.kubeconfig ] || exit 49
[ -r "$KUBECONFIG" ] || exit 50
grep -q 'guard-proxy' "$KUBECONFIG" || exit 51
case "$*" in
  "scale deployment/provisional --replicas=2 -n fixture")
    : > /work/provisional.scaled
    ;;
  "scale deployment/provisional --replicas=1 -n fixture")
    unlink /work/provisional.scaled
    ;;
  "scale deployment/kept --replicas=2 -n fixture")
    : > /work/kept.scaled
    ;;
  "scale deployment/kept --replicas=1 -n fixture")
    unlink /work/kept.scaled
    ;;
  "scale deployment/restart --replicas=2 -n fixture")
    : > /work/restart.scaled
    ;;
  "scale deployment/restart --replicas=1 -n fixture")
    unlink /work/restart.scaled
    ;;
  "delete namespace secret")
    unlink /work/secret/file
    rmdir /work/secret
    ;;
esac
printf 'guarded-kubectl:%s:%s:%s\n' "$*" "$(pwd)" "${SSH_AUTH_SOCK:-none}"
EOF
cat >/fakebin/helm <<'EOF'
#!/bin/sh
printf 'guarded-helm:%s:%s\n' "$*" "$(pwd)"
EOF
cat >/fakebin/ansible <<'EOF'
#!/bin/sh
if [ "$*" = "-m ping all" ]; then
  if [ -z "${GUARD_DEPTH:-}" ]; then
    echo "direct remote access unavailable" >&2
    exit 43
  fi
  if [ -n "${ANSIBLE_CONFIG:-}" ]; then
    echo "caller ANSIBLE_CONFIG leaked" >&2
    exit 44
  fi
  if [ ! -f ansible.cfg ] || [ ! -f inventory ]; then
    echo "[WARNING]: No inventory was parsed, only implicit localhost is available" >&2
    echo "[WARNING]: provided hosts list is empty" >&2
    exit 45
  fi
  grep -q '^inventory *= *inventory$' ansible.cfg && grep -q '^all$' inventory || exit 46
  printf 'guarded-ansible-cwd:%s:%s\n' "$*" "$(pwd)"
  exit 0
fi
printf 'guarded-ansible:%s:%s\n' "$*" "$(pwd)"
EOF
cat >/fakebin/ansible-playbook <<'EOF'
#!/bin/sh
printf 'guarded-ansible-playbook:%s:%s\n' "$*" "$(pwd)"
EOF
cat >/fakebin/whoami <<'EOF'
#!/bin/sh
[ "$#" -eq 1 ] && [ "$1" = child-contract ] || exit 51
cap_eff="$(awk '/^CapEff:/ { print $2 }' "/proc/$$/status")"
case "$cap_eff" in
  ''|*[1-9a-fA-F]*) exit 52 ;;
esac
printf 'uid=%s\ncap_eff=%s\n' "$(id -u)" "$cap_eff"
EOF
chmod 0755 /fakebin/ssh /fakebin/kubectl /fakebin/helm /fakebin/ansible /fakebin/ansible-playbook /fakebin/whoami
# The child owns only its fixture work tree. Daemon state and operator
# configuration remain under identities the child cannot mutate.
chmod 0755 /run/guard /fakebin /shim
chmod 0400 "$UPSTREAM_KUBECONFIG"
chown -R guardexec:guardexec /work
chown guarddaemon:guarddaemon \
  /run/guard /var/lib/guard "$UPSTREAM_KUBECONFIG" \
  /run/guard/verbs.yaml
chown -R guarddaemon:guarddaemon /shim
chown guarddaemon:guarddaemon /home/guarddaemon
chown agent:agent /home/agent
runuser -u agent       -- guard config set-server "$SOCK" >/dev/null 2>&1 || true
runuser -u guarddaemon -- guard config set-server "$SOCK" >/dev/null 2>&1 || true
runuser -u guarddaemon -- guard shim kubectl,helm,ansible,ansible-playbook --path /shim >/tmp/shim-install.out 2>&1 \
  || { bad "guarddaemon could not install generic shims"; cat /tmp/shim-install.out; exit 1; }
runuser -u guarddaemon -- guard shim ssh --path /shim --env SSH_AUTH_SOCK=/run/guard/broker-agent.sock >/tmp/ssh-shim-install.out 2>&1 \
  || { bad "guarddaemon could not install broker-owned ssh shim config"; cat /tmp/ssh-shim-install.out; exit 1; }
for shim in ssh kubectl helm ansible ansible-playbook; do
  [ -x "/shim/$shim" ] || { bad "expected shim missing or not executable: $shim"; exit 1; }
done

echo "=== Direct ssh has no usable caller credential ==="
if agent env PATH="/fakebin:/usr/local/bin:/usr/bin:/bin" SSH_AUTH_SOCK=/tmp/direct-agent.sock ssh safe-host >/tmp/direct-ssh.out 2>&1; then
  bad "direct ssh unexpectedly found a usable caller credential"
else
  if grep -q "caller ssh agent visible" /tmp/direct-ssh.out; then
    ok "direct ssh exposes only the caller's unusable fake credential"
  else
    bad "direct ssh failure was not the expected credential failure"
    cat /tmp/direct-ssh.out
  fi
fi
if cd /work/ansible-project && agent env PATH="/fakebin:/usr/local/bin:/usr/bin:/bin" ANSIBLE_CONFIG=/tmp/caller-ansible.cfg ansible -m ping all >/tmp/direct-ansible.out 2>&1; then
  bad "direct ansible unexpectedly had remote access"
else
  if grep -q "direct remote access unavailable" /tmp/direct-ansible.out; then
    ok "direct ansible has no usable remote access"
  else
    bad "direct ansible failure was not the expected credential failure"
    cat /tmp/direct-ansible.out
  fi
fi

echo "=== Start daemon with distinct child identity (gate=consequence, no LLM) ==="
: > /var/log/guard.log
start_daemon
chown guarddaemon:guarddaemon "$ADMIN_TOKEN_FILE"

for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.2; done
if [ -S "$SOCK" ]; then
  ok "daemon listening on $SOCK"
else
  bad "daemon did not start"
  cat /var/log/guard.log
  exit 1
fi
assert_daemon_boundary

echo
echo "=== 1. transparent shims broker through Guard ==="
if cd /work && agent_shim env SSH_AUTH_SOCK=/tmp/agent.sock ssh safe-host >/tmp/ssh-shim.out 2>/tmp/ssh-shim.err; then
  bad "opaque ssh execution bypassed the closed executable profile registry"
else
  if grep -q "guarded-ssh" /tmp/ssh-shim.out; then
    bad "rejected ssh execution still started the child process"
  else
    ok "opaque ssh execution was rejected before process start"
  fi
fi
OUT=$(cd /work && agent_shim kubectl version --client 2>/tmp/kubectl-shim.err)
case "$OUT" in
  guarded-kubectl:version\ --client:/work:none) ok "kubectl shim reached Guard with argv/cwd preserved" ;;
  *) bad "kubectl shim output mismatch: '$OUT'"; cat /tmp/kubectl-shim.err ;;
esac
if cd /work && agent_shim helm upgrade --install demo ./chart --namespace staging --dry-run --diff >/tmp/helm-shim.out 2>/tmp/helm-shim.err; then
  bad "fixed identity executed Helm with mutable profile authority"
elif grep -Eq 'fixed-identity|shared child UID' /tmp/helm-shim.err \
  && ! grep -q 'guarded-helm' /tmp/helm-shim.out; then
  ok "fixed identity denied Helm before process start"
else
  bad "fixed-identity Helm denial did not report the profile boundary"; cat /tmp/helm-shim.err
fi
if cd /work && agent_shim ansible web -m ping --check >/tmp/ansible-shim.out 2>/tmp/ansible-shim.err; then
  bad "fixed identity executed Ansible with mutable profile authority"
elif grep -Eq 'fixed-identity|shared child UID' /tmp/ansible-shim.err \
  && ! grep -q 'guarded-ansible' /tmp/ansible-shim.out; then
  ok "fixed identity denied Ansible before process start"
else
  bad "fixed-identity Ansible denial did not report the profile boundary"; cat /tmp/ansible-shim.err
fi
if cd /work && agent_shim ansible-playbook /work/site.yml --check --diff --limit web >/tmp/playbook-shim.out 2>/tmp/playbook-shim.err; then
  bad "fixed identity executed ansible-playbook with mutable profile authority"
elif grep -Eq 'fixed-identity|shared child UID' /tmp/playbook-shim.err \
  && ! grep -q 'guarded-ansible-playbook' /tmp/playbook-shim.out; then
  ok "fixed identity denied ansible-playbook before process start"
else
  bad "fixed-identity ansible-playbook denial did not report the profile boundary"; cat /tmp/playbook-shim.err
fi

echo
echo "=== 2. reversible verb executes immediately ==="
OUT=$(agent guard verb run read-file --socket "$SOCK" 2>/tmp/read.err)
if [ "$OUT" = "hello" ]; then
  ok "reversible read returned content"
else
  bad "reversible read (got: '$OUT')"
  cat /tmp/read.err
fi

OUT=$(agent guard verb run child-capability-contract --socket "$SOCK" 2>/tmp/child-contract.err)
if printf '%s\n' "$OUT" | grep -qx 'uid=1003' \
  && printf '%s\n' "$OUT" | grep -Eq '^cap_eff=0+$'; then
  ok "fixed child ran as guardexec with zero effective capabilities"
else
  bad "fixed child identity or capability contract failed: '$OUT'"
  cat /tmp/child-contract.err
fi
if agent guard run --socket "$SOCK" \
  --secret-file CHILD_FILE_PATH=CHILD_FILE_FIXTURE \
  true >/tmp/child-secret.out 2>/tmp/child-secret.err; then
  bad "fixed child identity accepted per-run credential delivery"
elif grep -q 'shared child UID' /tmp/child-secret.err \
  && [ -z "$(find /run/guard/secret-files -mindepth 1 -print -quit)" ]; then
  ok "fixed child identity rejected per-run credentials before lease creation"
else
  bad "fixed child credential rejection did not fail closed"
  cat /tmp/child-secret.err
fi

echo
echo "=== 2. recoverable verb runs behind an auto-revert envelope ==="
agent guard verb run scale-workload --param name=provisional --confirm-within 2 --socket "$SOCK" >/tmp/prov.out 2>&1
if [ -f /work/provisional.scaled ]; then
  ok "recoverable change applied (workload scaled)"
else
  bad "recoverable change did not apply"; cat /tmp/prov.out
fi
echo "    waiting for auto-revert (grace 2s + window 2s)..."
sleep 6
if [ ! -f /work/provisional.scaled ]; then ok "auto-revert restored the unconfirmed workload"; else bad "auto-revert did NOT fire"; fi

echo
echo "=== 3. operator confirm cancels the auto-revert; agent cannot confirm ==="
agent guard verb run scale-workload --param name=kept --confirm-within 30 --socket "$SOCK" >/tmp/keep.out 2>&1
HANDLE=$(handle_of /tmp/keep.out)
if [ -n "$HANDLE" ]; then
  if agent guard confirm "$HANDLE" --socket "$SOCK" >/tmp/agentconfirm.out 2>&1; then
    bad "agent confirmed its own provisional (admin-token only)"
  else
    ok "agent cannot confirm a provisional without the admin token"
  fi
  operator guard confirm "$HANDLE" --socket "$SOCK" >/dev/null 2>&1
  sleep 3
  if [ -f /work/kept.scaled ]; then
    ok "confirmed change kept (no revert)"
  else
    bad "confirmed change was reverted"
  fi
else
  bad "could not parse provisional handle"; cat /tmp/keep.out
fi

echo
echo "=== 4. irreversible verb is HELD, not executed ==="
agent guard verb run delete-fixture-namespace --socket "$SOCK" >/tmp/held.out 2>&1
HHANDLE=$(handle_of /tmp/held.out)
if grep -qi "HELD" /tmp/held.out && [ -d /work/secret ]; then
  ok "irreversible action held (not executed; target intact)"
else
  bad "irreversible action was not held"; cat /tmp/held.out
fi

echo
echo "=== 5. agent CANNOT self-approve its held command (bypass-resistance) ==="
if [ -n "$HHANDLE" ]; then
  if agent guard access approve "$HHANDLE" --once --socket "$SOCK" >/tmp/selfapprove.out 2>&1; then
    bad "agent self-approved an irreversible hold (CRITICAL bypass)"
  else
    ok "agent self-approve refused (no admin token)"
  fi
  if [ -d /work/secret ]; then
    ok "target still intact after self-approve attempt"
  else
    bad "target destroyed by agent self-approve"
  fi
fi

echo
echo "=== 6. operator approval arms the bound snapshot; requester resumes it ==="
if [ -n "$HHANDLE" ]; then
  if operator guard access approve "$HHANDLE" --once --socket "$SOCK" >/tmp/opapprove.out 2>&1; then
    if [ -d /work/secret ]; then
      ok "operator approval armed the hold without executing it"
    else
      bad "operator approval executed as the operator"
    fi
  else
    bad "operator approval did not arm the hold"; cat /tmp/opapprove.out
  fi
  if agent guard resume "$HHANDLE" --socket "$SOCK" >/tmp/resume.out 2>&1; then
    if [ ! -d /work/secret ]; then
      ok "requester resumed the approved snapshot"
    else
      bad "requester resume did not execute"
    fi
  else
    bad "requester could not resume the approved snapshot"; cat /tmp/resume.out
  fi
fi

echo
echo "=== 7. parameter injection is structurally rejected ==="
if agent guard verb run scale-workload --param name=-rf --socket "$SOCK" >/tmp/flag.out 2>&1; then
  bad "flag-injection value '-rf' accepted"
else
  ok "flag-injection value rejected"
fi
if agent guard verb run scale-workload --param 'name=web;invalid' --socket "$SOCK" >/tmp/shell.out 2>&1; then
  bad "shell-metachar value accepted"
else
  ok "shell-metachar value rejected"
fi

echo
echo "=== 8. raw irreversible command stays gated (no verb escape) ==="
echo "marker" > /work/marker.txt
agent guard run rm -rf /work/marker.txt --socket "$SOCK" >/tmp/raw.out 2>&1 || true
if [ -f /work/marker.txt ]; then
  ok "raw destructive command did not execute"
else
  bad "raw rm executed despite gating"
fi

echo
echo "=== 9. restart mid-window: future deadline is re-armed ==="
agent guard verb run scale-workload --param name=restart --confirm-within 600 --socket "$SOCK" >/tmp/restart.out 2>&1
RHANDLE=$(handle_of /tmp/restart.out)
kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null
start_daemon
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.2; done
assert_daemon_boundary
sleep 5
PROVISIONALS=$(operator guard provisionals --socket "$SOCK" 2>/dev/null || true)
if [ -f /work/restart.scaled ] \
  && printf '%s\n' "$PROVISIONALS" | grep -Fq "$RHANDLE" \
  && printf '%s\n' "$PROVISIONALS" | grep -q '^\[armed\]'; then
  ok "restart left the change in place and re-armed its future deadline"
else
  bad "restart recovery did not behave (workload marker present? $( [ -f /work/restart.scaled ] && echo yes || echo no ))"
  printf '%s\n' "$PROVISIONALS" | head
fi

echo
echo "=== Audit log shows the gate decisions ==="
if grep -qE '\[AUDIT\] (HELD|PROVISIONAL|REVERT|APPROVED|CONFIRM|STARTUP_RECOVERY)' /var/log/guard.log; then
  ok "audit trail present"
else
  bad "audit trail missing"
fi

kill "$DAEMON_PID" 2>/dev/null || true
echo
echo "=== RESULT: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] || { echo "--- daemon log tail ---"; tail -50 /var/log/guard.log; }
exit "$FAIL"
