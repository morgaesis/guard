# Development

## Building

```bash
cargo build --quiet --release
cargo test --quiet
cargo clippy -- -D warnings
cargo fmt --all -- --check
```

## Pre-commit hooks

A `.pre-commit-config.yaml` is included. Install with:

```bash
pip install pre-commit
pre-commit install
pre-commit install --hook-type commit-msg
```

This runs `cargo fmt`, `cargo clippy`, `cargo test`, `cargo audit`, and validates commit messages against Conventional Commits format.

## Conventional commits

Commit messages must follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <subject>
```

Allowed types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.

Examples:

```
feat(server): add additive prompt support
fix(evaluate): handle empty policy engine
docs(readme): update pricing for Gemini 3 Flash
chore(deps): bump tokio to 1.40
```

### Installing the commit-msg hook (without pre-commit framework)

If you don't want to install the Python `pre-commit` framework, a standalone shell script is available at `scripts/git-hooks/commit-msg`. Install it locally with:

```bash
ln -sf ../../scripts/git-hooks/commit-msg .git/hooks/commit-msg
```

The symlink picks up changes to the tracked script automatically. The standalone hook has no dependencies beyond `sh` and `grep`.

## Recording a demo

A terminal recording can be generated using [VHS](https://github.com/charmbracelet/vhs) inside a fresh podman container to avoid exposing local environment details.

### Setup

```bash
# Build the guard binary
cargo build --quiet --release

# Create a demo container with VHS and guard installed
podman run -it --rm \
  --name guard-demo \
  -v ./target/release/guard:/usr/local/bin/guard:ro \
  -v ./demo.tape:/demo.tape:ro \
  -e GUARD_LLM_API_KEY="$GUARD_LLM_API_KEY" \
  ubuntu:24.04 bash
```

Inside the container:

```bash
# Install VHS (see https://github.com/charmbracelet/vhs for latest)
apt-get update && apt-get install -y curl
curl -fsSL https://github.com/charmbracelet/vhs/releases/download/v0.8.0/vhs_0.8.0_amd64.deb -o vhs.deb
dpkg -i vhs.deb

# Run the recording
vhs /demo.tape
```

### The tape file

The tracked `demo.tape` in the repo root drives the recording; edit it to
change the demo. Its structure:

```tape
Output docs/demo.svg
Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 500
Set Padding 20

Type "guard run hostname"
Enter
Sleep 2s

Type "guard run ps aux"
Enter
Sleep 2s

Type "guard run cat /etc/hosts"
Enter
Sleep 2s

Type "guard run rm -rf /"
Enter
Sleep 3s

Type "guard run sudo su"
Enter
Sleep 3s
```

The tape file should only use generic commands and hostnames. Do not include real API keys, usernames, hostnames, or paths specific to your local environment.

### Alternative: record without VHS

```bash
podman run -it --rm \
  -v ./target/release/guard:/usr/local/bin/guard:ro \
  -e GUARD_LLM_API_KEY="$GUARD_LLM_API_KEY" \
  ubuntu:24.04 bash -c '
    guard server start --socket /tmp/guard.sock &
    sleep 2
    guard config set-server /tmp/guard.sock
    echo "=== Allowed ==="
    guard run hostname
    guard run id
    guard run ps aux
    echo "=== Denied ==="
    guard run rm -rf /
    guard run sudo su
    guard run "bash -c eval \$(echo cm0gLXJmIC8= | base64 -d)"
  '
```

## Running CTF adversarial tests

See [ctf/DESIGN.md](ctf/DESIGN.md) for the full CTF test harness setup. Three
tracked entry points cover the harness:

```bash
export GUARD_LLM_API_KEY=sk-or-...

# Two-container harness (guard daemon + shimmed tools vs. target host).
./ctf/run.sh                                   # build and start containers
podman exec -it guard-local run-claude-attack  # drive the agent CTF
./ctf/teardown.sh                              # clean up containers and state

# Single hardened container running an adversarial Claude campaign against
# the daemon; results land in ctf/runs/<timestamp>/.
./ctf/run-adversary.sh

# Consequence-gating harness (Docker or Podman).
./ctf/gating/run.sh          # adversarial gating attack
./ctf/gating/run.sh test     # full cargo test suite in a Linux container
```

`run.sh` and `run-adversary.sh` need `GUARD_LLM_API_KEY` or
`OPENROUTER_API_KEY` for the daemon's evaluator, plus a `claude` CLI and its
OAuth credentials for the attacking agent.

## Test integrity

- A test gated on a secret (for example the evaluator API key) may skip when
  the secret is absent locally. When its matching `GUARD_*_REQUIRED`
  environment variable is set, the test must fail instead of skipping. A CI
  leg that provides the secret sets the variable so a missing or broken secret
  cannot silently erase coverage.
- Parse-only assertions are not behavioral coverage. Every YAML test corpus
  under `tests/` must be evaluated against the policy engine or evaluator;
  a test that only deserializes and counts entries does not count as coverage
  for the behaviors the corpus describes.

## Dependency auditing

```bash
cargo audit              # CVE scan
cargo deny check         # license + dependency policy
cargo outdated           # check for updates
cargo machete            # unused dependencies
```
