#!/usr/bin/env python3
"""Exercise the installed launcher and real client in a disposable Linux container.

Requires Python 3, coreutils, util-linux, and Guard binaries built for the container.
OLD_GUARD_BINARY points to a verified stable release older than 0.8.8.
Mount this repository read-only and run with an explicit disposable container root:
  podman run --rm --network none --entrypoint python3 \
    -e GUARD_OPERATOR_TEST_CONTAINER=1 -v "$PWD:/source:ro" \
    -v "$OLD_GUARD_BINARY:/old-guard:ro" IMAGE \
    /source/deployment/systemd/test-guard-operator.py \
    /source/deployment/systemd/guard-operator /source/target/debug/guard /old-guard
The standard library provides Unix sockets and subprocess isolation without packages.
"""

import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest


if (os.geteuid() != 0 or os.environ.get("GUARD_OPERATOR_TEST_CONTAINER") != "1"
        or not (Path("/run/.containerenv").exists() or Path("/.dockerenv").exists())):
    sys.exit("requires an explicitly selected disposable root container; no host changes allowed")
if len(sys.argv) != 4:
    sys.exit("usage: test-guard-operator.py LAUNCHER GUARD_BINARY OLD_GUARD_BINARY")
LAUNCHER_SOURCE, BINARY_SOURCE, OLD_BINARY_SOURCE = map(Path, sys.argv[1:])
sys.argv[1:] = []
LAUNCHER = Path("/usr/local/sbin/guard-operator")
BINARY = Path("/usr/local/bin/guard")
TOKEN = Path("/etc/guard/admin.token")
SOCKET = "/run/guard/guard.sock"


def write(path, text, mode=0o644):
    path = Path(path)
    path.write_text(text)
    path.chmod(mode)


class OperatorLauncher(unittest.TestCase):
    def setUp(self):
        for path in [Path("/etc/guard"), Path("/run/guard")]:
            if path.exists():
                shutil.rmtree(path)
            path.mkdir(mode=0o700)
        for path in [LAUNCHER.parent, BINARY.parent]:
            path.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(LAUNCHER_SOURCE, LAUNCHER)
        LAUNCHER.chmod(0o700)
        shutil.copyfile(BINARY_SOURCE, BINARY)
        BINARY.chmod(0o755)
        self.token = secrets.token_hex(32)
        write(TOKEN, self.token + "\n", 0o400)
        write("/service-mode", "guard.service")
        write("/usr/bin/systemctl", '''#!/bin/sh
set -eu
[ "$#" = 2 ] && [ "$1" = is-active ]
[ "${SYSTEMD_BUS_ADDRESS+x}" != x ]
mode=$(cat /service-mode)
if [ "$mode" = both ] || [ "$mode" = "$2" ]; then
    printf 'active\\n'
else
    printf 'inactive\\n'
    exit 3
fi
''', 0o755)
        self.directory = tempfile.TemporaryDirectory(prefix="operator fixture ")
        self.addCleanup(self.directory.cleanup)
        self.cwd = Path(self.directory.name)
        write(self.cwd / ".env", "GUARD_SOCKET=/wrong.sock\nGUARD_ADMIN_TOKEN=wrong\n"
              "GUARD_NO_AUTO_CONFIG=0\nGUARD_TCP_PORT=1\n")
        write(self.cwd / "startup.sh", "touch /unexpected-startup\n")
        (self.cwd / "config/guard").mkdir(parents=True)
        write(self.cwd / "config/guard/client.yaml", "admin_token: wrong\nserver_socket: /wrong.sock\n")
        # Even a protected HOME's existing configuration must not override the launcher.
        Path("/etc/guard/guard").mkdir()
        write("/etc/guard/guard/client.yaml", "admin_token: wrong\nserver_tcp_port: 1\n")
        self.environment = dict(os.environ, HOME=str(self.cwd), XDG_CONFIG_HOME=str(self.cwd / "config"),
                                GUARD_ADMIN_TOKEN="wrong", GUARD_ADMIN_TOKEN_FILE="/wrong",
                                GUARD_SOCKET="/wrong.sock", GUARD_TCP_PORT="1", GUARD_NO_AUTO_CONFIG="0",
                                ENV=str(self.cwd / "startup.sh"), BASH_ENV=str(self.cwd / "startup.sh"),
                                SYSTEMD_BUS_ADDRESS="unix:path=/wrong-bus")

    def invoke(self, *arguments, stdin="", executable=None):
        result = subprocess.run([str(executable or LAUNCHER), *arguments], cwd=self.cwd,
                                env=self.environment, input=stdin, text=True,
                                capture_output=True, timeout=10)
        self.assertTrue(self.token not in result.stdout + result.stderr, "credential appeared in client output")
        self.assertFalse(Path("/unexpected-startup").exists(), "interpreter sourced caller startup file")
        return result

    def expect_failure(self, code, *arguments):
        result = self.invoke(*arguments)
        self.assertEqual(result.returncode, code, "unexpected launcher status")
        self.assertTrue(result.stderr.startswith("guard-operator:"))

    def rpc(self, arguments, handlers, stdin=""):
        errors = []
        requests = []
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(SOCKET)
            listener.listen()
            listener.settimeout(8)

            def serve():
                try:
                    for handler in handlers:
                        with listener.accept()[0] as connection:
                            connection.settimeout(5)
                            request = json.loads(connection.makefile("rb").readline())
                            if request.get("admin_token") != self.token:
                                raise AssertionError("operator credential did not reach the fixed socket")
                            requests.append(request["admin"])
                            response = handler(request["admin"])
                            connection.sendall(json.dumps(response).encode() + b"\n")
                except Exception as error:
                    errors.append(type(error).__name__)

            worker = threading.Thread(target=serve)
            worker.start()
            result = self.invoke(*arguments, stdin=stdin)
            worker.join(timeout=9)
            self.assertFalse(worker.is_alive(), "RPC fixture did not finish")
        Path(SOCKET).unlink()
        self.assertFalse(errors, "RPC fixture failed to receive the expected authenticated request")
        self.assertEqual(result.returncode, 0, "real operator client failed")
        return requests, result

    def test_relative_spaced_verb_add_and_amend_from_hostile_cwd(self):
        definition = "name: fixture\nbinary: /bin/true\nconsequence: reversible\n"
        # The serialized definition returned by the real client supplies all default fields.
        write(self.cwd / "verb definition.yaml", definition)
        stored = []

        def added(request):
            self.assertEqual(request["op"], "verb_add")
            stored.append(request["verb"])
            return dict(result="verb_created", verb=request["verb"], persisted=True)

        self.rpc(["verb", "add", "--file", "verb definition.yaml", "--json"], [added])

        def shown(request):
            self.assertEqual(request["op"], "verb_show")
            return dict(result="verb_created", verb=stored[0], persisted=True)

        def amended(request):
            self.assertEqual(request["op"], "verb_amend")
            self.assertEqual(request["replacement"]["name"], "fixture")
            self.assertTrue(bool(request["expected_digest"]))
            return dict(result="verb_amended", verb=request["replacement"], previous_digest=request["expected_digest"], digest="fixture-digest")

        self.rpc(["verb", "amend", "fixture", "--file=verb definition.yaml", "--json"], [shown, amended])

    def test_secret_stdin_and_alias_keep_fixed_endpoint(self):
        def exists(request):
            self.assertEqual(request["op"], "secret_exists")
            return dict(result="secret_exists", exists=False)

        def stored(request):
            self.assertEqual(request["op"], "secret_set")
            self.assertTrue(request["value"] == "fixture-input", "stdin changed")
            return dict(result="ok")

        self.rpc(["secret", "add", "fixture"], [exists, stored], stdin="fixture-input\n")

    def test_delimiter_is_forwarded_to_clap_without_an_appended_socket_flag(self):
        def deleted(request):
            self.assertEqual(request["op"], "verb_delete")
            self.assertEqual(request["name"], "-fixture")
            return dict(result="ok")

        self.rpc(["verb", "delete", "--", "-fixture"], [deleted])

    def test_old_client_and_unknown_versions_fail_before_authenticated_rpc(self):
        shutil.copyfile(OLD_BINARY_SOURCE, BINARY)
        BINARY.chmod(0o755)
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(SOCKET)
            listener.listen()
            listener.settimeout(0.1)
            self.expect_failure(125, "secrets", "list")
            with self.assertRaises(TimeoutError):
                listener.accept()
        Path(SOCKET).unlink()
        for version in ["guard v0.8.7 (abcdef0)", "guard v0.8.8-rc.1 (abcdef0)",
                        "guard v0.8.8+custom (abcdef0)", "guard unknown", "guard v00.8.8 (abcdef0)"]:
            write(BINARY, "#!/bin/sh\nprintf '%s\\n' '" + version + "'\n", 0o755)
            self.expect_failure(125, "secrets", "list")

    def test_forwarding_preserves_argv_stdin_cwd_and_excludes_token_value(self):
        write(BINARY, '''#!/usr/bin/python3
import json, os, sys
if sys.argv[1:] == ["--version"]:
    assert os.getcwd() == "/"
    assert "GUARD_ADMIN_TOKEN" not in os.environ
    assert "GUARD_ADMIN_TOKEN_FILE" not in os.environ
    assert sys.stdin.read() == ""
    print("guard v0.8.8 (abcdef0)")
    sys.exit(0)
assert "GUARD_ADMIN_TOKEN" not in os.environ
assert "GUARD_TCP_PORT" not in os.environ
assert "ENV" not in os.environ and "BASH_ENV" not in os.environ
assert os.environ["GUARD_NO_AUTO_CONFIG"] == "1"
assert os.environ["GUARD_SOCKET"] == "/run/guard/guard.sock"
assert os.environ["GUARD_ADMIN_TOKEN_FILE"] == "/etc/guard/admin.token"
assert os.environ["HOME"] == os.environ["XDG_CONFIG_HOME"] == "/etc/guard"
assert sys.stdin.read() == "fixture-input"
print(json.dumps({"arguments": sys.argv[1:], "cwd": os.getcwd()}))
''', 0o755)
        args = ["approval", "note", "fixture", "--", "--file=literal message"]
        result = self.invoke(*args, stdin="fixture-input")
        self.assertEqual(result.returncode, 0)
        observed = json.loads(result.stdout)
        self.assertEqual(observed["arguments"], args)
        self.assertEqual(observed["cwd"], str(self.cwd))

    def test_each_allowed_leaf_is_a_real_clap_command(self):
        leaves = ["status", "confirm", "revert", "provisionals", "provisionals show"]
        leaves += ["access " + leaf for leaf in ["approve", "deny", "extend", "revoke", "list", "show", "status"]]
        leaves += ["approval " + leaf for leaf in ["list", "show", "note"]]
        leaves += ["audit " + leaf for leaf in ["verify", "tail"]]
        leaves += ["verb " + leaf for leaf in ["list", "show", "add", "amend", "delete", "create", "coverage list", "coverage clear"]]
        leaves += ["secrets " + leaf for leaf in ["add", "list", "remove"]]
        for leaf in leaves:
            with self.subTest(leaf=leaf):
                self.assertEqual(self.invoke(*leaf.split(), "--help").returncode, 0)

    def test_requester_local_and_daemon_commands_are_rejected(self):
        for args in [["run", "/bin/true"], ["exec", "/bin/true"], ["verb", "run", "fixture"],
                     ["verb", "lint", "--fix"], ["approval", "resume", "fixture"],
                     ["approval", "withdraw", "fixture"], ["access", "request", "fixture"],
                     ["access", "whoami"], ["provisionals", "--json", "unsupported"],
                     ["server", "start"], ["server", "connect"],
                     ["config", "set-admin-token"], ["shim"], ["mcp", "serve"]]:
            with self.subTest(arguments=args):
                self.expect_failure(2, *args)
        for args in [["access", "list", "--socket", "/wrong"], ["status", "--socket=/wrong"],
                     ["verb", "show", "--", "--socket=/wrong"]]:
            self.expect_failure(2, *args)
        self.assertEqual(self.invoke("verb", "show", "--unknown-option").returncode, 2)
        self.assertEqual(self.invoke("status", "--tcp-port=1").returncode, 2)
        self.assertEqual(self.invoke("status", "--config=/wrong").returncode, 2)

    def test_service_selection_fails_closed(self):
        for mode in ["both", "neither"]:
            write("/service-mode", mode)
            self.expect_failure(125, "access", "list")
        write("/service-mode", "guard-exec-as-caller.service")
        self.assertEqual(self.invoke("access", "list", "--help").returncode, 0)

    def test_real_uid_gate_and_installation_permissions(self):
        result = subprocess.run(["setpriv", "--reuid=1000", "--regid=1000", "--clear-groups",
                                 str(LAUNCHER), "status"], capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        shutil.copyfile(LAUNCHER_SOURCE, "/readable-launcher")
        Path("/readable-launcher").chmod(0o755)
        result = subprocess.run(["setpriv", "--reuid=1000", "--regid=1000", "--clear-groups",
                                 "/bin/sh", "/readable-launcher", "status"], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 125)
        self.assertIn(b"sudo guard-operator", result.stderr)
        LAUNCHER.chmod(0o755)
        self.expect_failure(125, "status")
        LAUNCHER.chmod(0o700)
        BINARY.chmod(0o777)
        self.expect_failure(125, "status")

    def test_token_metadata_and_protected_ancestor_failures(self):
        for mode in [0o600, 0o444]:
            TOKEN.chmod(mode)
            self.expect_failure(125, "status")
        TOKEN.chmod(0o400)
        os.chown(TOKEN, 1000, 1000)
        self.expect_failure(125, "status")
        os.chown(TOKEN, 0, 0)
        link = TOKEN.with_name("link")
        os.link(TOKEN, link)
        self.expect_failure(125, "status")
        link.unlink()
        TOKEN.rename(link)
        TOKEN.symlink_to(link)
        self.expect_failure(125, "status")
        TOKEN.unlink()
        os.mkfifo(TOKEN, 0o400)
        self.expect_failure(125, "status")
        TOKEN.unlink()
        self.expect_failure(125, "status")
        write(TOKEN, "", 0o400)
        self.expect_failure(125, "status")
        write(TOKEN, self.token, 0o400)
        Path("/etc/guard").chmod(0o777)
        self.expect_failure(125, "status")
        Path("/etc/guard").chmod(0o700)
        Path("/etc/guard").rename("/etc/guard-fixture-link-target")
        Path("/etc/guard").symlink_to("/etc/guard-fixture-link-target")
        try:
            self.expect_failure(125, "status")
        finally:
            Path("/etc/guard").unlink()
            Path("/etc/guard-fixture-link-target").rename("/etc/guard")


unittest.main(verbosity=2)
