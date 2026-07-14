#!/bin/bash
# Adversarial harness for consequence gating. Runs inside the container.
#
# Deployment: an UNPRIVILEGED daemon runs as uid 1000 (also the operator); the
# agent is uid 1001. The operator gate is bypass-resistant precisely because the
# daemon UID (1000) differs from the agent's (1001): only uid 1000 can approve,
# confirm, deny, or revert. Approved commands execute as the daemon identity
# (this is the policy-gate deployment; the root-broker --exec-as-caller variant
# is exercised in the WSL deployment, where setuid privilege drop is available).
set -u

SOCK=/run/guard/guard.sock
PASS=0
FAIL=0

ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

# Run a guard command as the unprivileged agent (uid 1001) or the operator (1000).
agent()    { runuser -u agent       -- "$@"; }
agent_shim() { runuser -u agent -- env PATH="/shim:/fakebin:/usr/local/bin:/usr/bin:/bin" "$@"; }
operator() { runuser -u guarddaemon -- "$@"; }

handle_of() { grep -oE 'handle:[[:space:]]*[0-9a-f]+' "$1" | awk '{print $2}' | head -1; }

echo "=== Setup ==="
mkdir -p /work /run/guard /var/lib/guard
mkdir -p /fakebin /shim
echo "hello" > /work/seed.txt
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
chmod 0755 /fakebin/ssh /fakebin/kubectl /fakebin/helm /fakebin/ansible /fakebin/ansible-playbook
# The daemon (uid 1000) owns its socket dir, state dir, and the work tree.
chown -R guarddaemon:guarddaemon /work /run/guard /var/lib/guard /shim
chmod 0755 /fakebin /shim
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
  grep -q "caller ssh agent visible" /tmp/direct-ssh.out \
    && ok "direct ssh exposes only the caller's unusable fake credential" \
    || { bad "direct ssh failure was not the expected credential failure"; cat /tmp/direct-ssh.out; }
fi
if cd /work/ansible-project && agent env PATH="/fakebin:/usr/local/bin:/usr/bin:/bin" ANSIBLE_CONFIG=/tmp/caller-ansible.cfg ansible -m ping all >/tmp/direct-ansible.out 2>&1; then
  bad "direct ansible unexpectedly had remote access"
else
  grep -q "direct remote access unavailable" /tmp/direct-ansible.out \
    && ok "direct ansible has no usable remote access" \
    || { bad "direct ansible failure was not the expected credential failure"; cat /tmp/direct-ansible.out; }
fi

echo "=== Start unprivileged daemon (uid 1000, gate=consequence, no LLM) ==="
runuser -u guarddaemon -- env PATH="/fakebin:/usr/local/bin:/usr/bin:/bin" GUARD_SWEEPER_GRACE_SECS=2 guard server start \
  --no-llm \
  --gate consequence \
  --socket "$SOCK" \
  --verbs /etc/guard/verbs.yaml \
  --state-db /var/lib/guard/state.db \
  --shim-dir /shim \
  --users 1001 \
  >/var/log/guard.log 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.2; done
chmod 666 "$SOCK" 2>/dev/null || true
[ -S "$SOCK" ] && ok "daemon listening on $SOCK" || { bad "daemon did not start"; cat /var/log/guard.log; exit 1; }

echo
echo "=== 1. transparent shims broker through Guard ==="
SESSION_TOKEN=0123456789abcdef0123456789abcdef
operator guard session grant "$SESSION_TOKEN" --ttl 60 --socket "$SOCK" >/tmp/session-grant.out 2>&1 \
  || { bad "operator could not install live-equivalent session"; cat /tmp/session-grant.out; }
OUT=$(cd /work && agent_shim env SSH_AUTH_SOCK=/tmp/agent.sock ssh safe-host 2>/tmp/ssh-shim.err)
case "$OUT" in
  guarded-ssh:safe-host:/work:broker-owned) ok "ssh shim reached guarded primary with cwd and broker-owned SSH_AUTH_SOCK" ;;
  *) bad "ssh shim output mismatch: '$OUT'"; cat /tmp/ssh-shim.err ;;
esac
OUT=$(cd /work && agent_shim kubectl version --client 2>/tmp/kubectl-shim.err)
case "$OUT" in
  guarded-kubectl:version\ --client:/work:none) ok "kubectl shim reached Guard with argv/cwd preserved" ;;
  *) bad "kubectl shim output mismatch: '$OUT'"; cat /tmp/kubectl-shim.err ;;
esac
OUT=$(cd /work && agent_shim helm upgrade --install demo ./chart --namespace staging --dry-run --diff 2>/tmp/helm-shim.err)
case "$OUT" in
  guarded-helm:upgrade\ --install\ demo\ ./chart\ --namespace\ staging\ --dry-run\ --diff:/work) ok "helm shim honored typed dry-run/diff/target shape" ;;
  *) bad "helm shim output mismatch: '$OUT'"; cat /tmp/helm-shim.err ;;
esac
OUT=$(cd /work && agent_shim ansible web -m ping --check 2>/tmp/ansible-shim.err)
case "$OUT" in
  guarded-ansible:web\ -m\ ping\ --check:/work) ok "ansible shim honored typed check-mode shape" ;;
  *) bad "ansible shim output mismatch: '$OUT'"; cat /tmp/ansible-shim.err ;;
esac
OUT=$(cd /work/ansible-project && agent_shim env GUARD_SESSION="$SESSION_TOKEN" ANSIBLE_CONFIG=/tmp/caller-ansible.cfg ansible -m ping all 2>/tmp/ansible-cwd.err)
case "$OUT" in
  guarded-ansible-cwd:-m\ ping\ all:/work/ansible-project) ok "ansible shim discovered cwd inventory/config without caller ANSIBLE_CONFIG" ;;
  *) bad "ansible cwd discovery output mismatch: '$OUT'"; cat /tmp/ansible-cwd.err ;;
esac
OUT=$(cd /work && agent_shim ansible-playbook site.yml --check --diff --limit web 2>/tmp/playbook-shim.err)
case "$OUT" in
  guarded-ansible-playbook:site.yml\ --check\ --diff\ --limit\ web:/work) ok "ansible-playbook shim honored typed check/diff/limit shape" ;;
  *) bad "ansible-playbook shim output mismatch: '$OUT'"; cat /tmp/playbook-shim.err ;;
esac
if cd /work && agent_shim ansible-playbook site.yml >/tmp/playbook-deny.out 2>&1; then
  bad "opaque file-driven ansible-playbook ran without typed controls"
else
  ok "opaque file-driven ansible-playbook without controls was denied"
fi
if cd /work && agent_shim helm upgrade --install demo ./chart --namespace staging --dry-run=false --dry-run --diff >/tmp/helm-dup.out 2>&1; then
  bad "duplicate/equivalent helm option bypass was accepted"
else
  ok "duplicate/equivalent helm option bypass failed"
fi

echo
echo "=== 2. reversible verb executes immediately ==="
OUT=$(agent guard verb run read-file --param path=/work/seed.txt --socket "$SOCK" 2>/tmp/read.err)
[ "$OUT" = "hello" ] && ok "reversible read returned content" || { bad "reversible read (got: '$OUT')"; cat /tmp/read.err; }

echo
echo "=== 2. recoverable verb runs behind an auto-revert envelope ==="
agent guard verb run stage-file --param path=/work/prov.txt --confirm-within 2 --socket "$SOCK" >/tmp/prov.out 2>&1
if [ -f /work/prov.txt ]; then
  ok "recoverable change applied (file created)"
else
  bad "recoverable change did not apply"; cat /tmp/prov.out
fi
echo "    waiting for auto-revert (grace 2s + window 2s)..."
sleep 6
if [ ! -f /work/prov.txt ]; then ok "auto-revert removed the unconfirmed change"; else bad "auto-revert did NOT fire"; fi

echo
echo "=== 3. operator confirm cancels the auto-revert; agent cannot confirm ==="
agent guard verb run stage-file --param path=/work/keep.txt --confirm-within 30 --socket "$SOCK" >/tmp/keep.out 2>&1
HANDLE=$(handle_of /tmp/keep.out)
if [ -n "$HANDLE" ]; then
  if agent guard confirm "$HANDLE" --socket "$SOCK" >/tmp/agentconfirm.out 2>&1; then
    bad "agent confirmed its own provisional (should be daemon-UID only)"
  else
    ok "agent cannot confirm a provisional (daemon-UID only)"
  fi
  operator guard confirm "$HANDLE" --socket "$SOCK" >/dev/null 2>&1
  sleep 3
  [ -f /work/keep.txt ] && ok "confirmed change kept (no revert)" || bad "confirmed change was reverted"
else
  bad "could not parse provisional handle"; cat /tmp/keep.out
fi

echo
echo "=== 4. irreversible verb is HELD, not executed ==="
agent guard verb run wipe --param path=/work/secret --socket "$SOCK" >/tmp/held.out 2>&1
HHANDLE=$(handle_of /tmp/held.out)
if grep -qi "HELD" /tmp/held.out && [ -d /work/secret ]; then
  ok "irreversible action held (not executed; target intact)"
else
  bad "irreversible action was not held"; cat /tmp/held.out
fi

echo
echo "=== 5. agent CANNOT self-approve its held command (bypass-resistance) ==="
if [ -n "$HHANDLE" ]; then
  if agent guard approve "$HHANDLE" --socket "$SOCK" >/tmp/selfapprove.out 2>&1; then
    bad "agent self-approved an irreversible hold (CRITICAL bypass)"
  else
    ok "agent self-approve refused (not daemon UID)"
  fi
  [ -d /work/secret ] && ok "target still intact after self-approve attempt" || bad "target destroyed by agent self-approve"
fi

echo
echo "=== 6. operator approve executes from the bound snapshot ==="
if [ -n "$HHANDLE" ]; then
  operator guard approve "$HHANDLE" --socket "$SOCK" >/tmp/opapprove.out 2>&1
  sleep 1
  [ ! -d /work/secret ] && ok "operator approval executed the held action" || { bad "operator approval did not execute"; cat /tmp/opapprove.out; }
fi

echo
echo "=== 7. parameter injection is structurally rejected ==="
agent guard verb run stage-file --param path=-rf --socket "$SOCK" >/tmp/flag.out 2>&1 \
  && bad "flag-injection value '-rf' accepted" || ok "flag-injection value rejected"
agent guard verb run stage-file --param 'path=/work/x;rm -rf /work' --socket "$SOCK" >/tmp/shell.out 2>&1 \
  && bad "shell-metachar value accepted" || ok "shell-metachar value rejected"

echo
echo "=== 8. raw irreversible command stays gated (no verb escape) ==="
echo "marker" > /work/marker.txt
agent guard run rm -rf /work/marker.txt --socket "$SOCK" >/tmp/raw.out 2>&1 || true
[ -f /work/marker.txt ] && ok "raw destructive command did not execute" || bad "raw rm executed despite gating"

echo
echo "=== 9. restart mid-window: no unattended revert at boot ==="
agent guard verb run stage-file --param path=/work/restart.txt --confirm-within 600 --socket "$SOCK" >/tmp/restart.out 2>&1
RHANDLE=$(handle_of /tmp/restart.out)
kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null
runuser -u guarddaemon -- env PATH="/fakebin:/usr/local/bin:/usr/bin:/bin" GUARD_SWEEPER_GRACE_SECS=2 guard server start \
  --no-llm --gate consequence --socket "$SOCK" --verbs /etc/guard/verbs.yaml \
  --state-db /var/lib/guard/state.db --shim-dir /shim --users 1001 >>/var/log/guard.log 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.2; done
chmod 666 "$SOCK" 2>/dev/null || true
sleep 5
if [ -f /work/restart.txt ] && operator guard provisionals --socket "$SOCK" 2>/dev/null | grep -q needs_operator_decision; then
  ok "restart left the change in place as needs_operator_decision (no unattended revert)"
else
  bad "restart recovery did not behave (file present? $( [ -f /work/restart.txt ] && echo yes || echo no ))"
  operator guard provisionals --socket "$SOCK" 2>/dev/null | head
fi

echo
echo "=== Audit log shows the gate decisions ==="
grep -qE '\[AUDIT\] (HELD|PROVISIONAL|REVERT|APPROVED|CONFIRM|STARTUP_RECOVERY)' /var/log/guard.log \
  && ok "audit trail present" || bad "audit trail missing"

kill "$DAEMON_PID" 2>/dev/null || true
echo
echo "=== RESULT: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] || { echo "--- daemon log tail ---"; tail -50 /var/log/guard.log; }
exit "$FAIL"
