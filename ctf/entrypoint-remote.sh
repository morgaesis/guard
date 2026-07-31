#!/bin/bash
set -euo pipefail

# sshd reads the mounted public key directly (StrictModes accepts it: the
# single-file mount is owned by the agent user and is not group/world
# writable). No runtime copy, chown, or chmod is needed, so the entrypoint
# works with CAP_FOWNER dropped.
if [ ! -r /run/ctf/agent_key.pub ]; then
    echo "Remote CTF authorized key is unavailable." >&2
    exit 1
fi

mkdir -p /run/sshd

# nginx and sshd are both supervised by the container runtime; PID 1 execs
# sshd, and a container stop terminates every process in the namespace.
nginx &

exec /usr/sbin/sshd -D -e
