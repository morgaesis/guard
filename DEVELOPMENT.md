# Development

## Contributing

Bug reports and enhancement requests use the repository's GitHub issue
tracker. Security reports follow [SECURITY.md](SECURITY.md) and do not belong in
public issues.

Contributions use GitHub pull requests against `main`. Keep each pull request
focused on one coherent change, add behavioral tests for changed behavior, and
update the existing documentation when a public contract changes. Run the
pre-commit gate below over the complete diff before requesting review. A
maintainer review and passing required checks are required before merge.
Routine Dependabot updates are the exception described under
[Dependency updates](#dependency-updates).

Contributions are accepted under the repository's MIT license. By submitting a
contribution, the contributor confirms they have the right to provide it under
that license.

## Dependency updates

`scripts/dependabot-automerge.sh` holds the policy for Dependabot pull requests,
and the scheduled `Dependabot reconcile` workflow applies it from `main`. It
never checks out or runs pull request content with a repository token.

- A Cargo patch or minor update, or a GitHub Actions update pinned to a full
  commit SHA, merges without a maintainer review once every required check
  succeeded for its exact head commit and every review thread is resolved.
- A major Cargo update, an unclassified update, or any other ecosystem fails
  the required `Classify dependency update` check until a repository owner,
  member, or collaborator approves the exact head commit.
- An update merges only when its head commit contains the current `main`
  commit, so its checks ran on the tree that the merge produces. One update
  merges per run, and one branch that lacks the `main` commit is refreshed per
  run by merging `main` into it. A conflicting workflow update waits for the
  rebase that Dependabot performs on a conflict.
- A workflow run that was cancelled, or that failed once, is rerun. A failure
  counts as a defect of the update once a rerun reproduced it.

A Cargo update whose required checks fail, or whose branch conflicts with
`main`, is repaired by `scripts/dependency-repair.sh`. A language model reads
the failure logs and edits files without the ability to run commands; Cargo
then applies the requested lockfile updates in a job that holds neither the
model credential nor a repository token. A separate job commits the result to
the pull request branch as a signed commit, limited to the Cargo manifests,
lockfiles, and Rust source of that update. The repaired update merges under
the same conditions as any other: a patch or minor update stays routine, and a
major update still needs its approving review. The model runs once for a given
Dependabot commit, `main` commit, and set of failing checks. Workflow updates
are not repaired.

The same repair runs locally against the current checkout, including a linked
worktree, and leaves its result uncommitted. The context file holds the
failing check output:

```bash
scripts/dependency-repair.sh candidate context.md
```

The model credential is read from `OPENROUTER_API_KEY`, removed from the
script's environment, and handed to the model process alone. The model and
the OpenCode release are fixed in the script, and `opencode` on `PATH` must be
that release.

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
  -e GUARD_LLM_API_KEY \
  ubuntu:26.04@sha256:3131b4cc82a783df6c9df078f86e01819a13594b865c2cad47bd1bca2b7063bb bash
```

Inside the container:

```bash
# Install VHS
apt-get update && apt-get install -y curl
curl -fsSL https://github.com/charmbracelet/vhs/releases/download/v0.11.0/vhs_0.11.0_amd64.deb -o vhs.deb
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
  -e GUARD_LLM_API_KEY \
  ubuntu:26.04@sha256:3131b4cc82a783df6c9df078f86e01819a13594b865c2cad47bd1bca2b7063bb bash -c '
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
export CLAUDE_CREDS=/path/to/dedicated-test-credentials.json

# Two-container harness (guard daemon + shimmed tools vs. target host).
bash ./ctf/run.sh    # build and start the per-run labeled containers
podman exec -it --user "$(id -u)" <local-container> \
  env -i HOME=/home/agent PATH=/home/agent/.guard/shims:/usr/local/bin:/usr/bin:/bin \
  run-claude-attack  # drive the agent CTF
bash ./ctf/teardown.sh <run-manifest>  # remove the exact run's resources

# One isolated container per credentialed adversary scenario; bounded,
# redacted results land in ctf/runs/<timestamp>-<scenario>/.
bash ./ctf/run-adversary.sh

# Consequence-gating harness (Docker or Podman).
./ctf/gating/run.sh          # adversarial gating attack
./ctf/gating/run.sh test     # full cargo test suite in a Linux container
```

`run.sh` and `run-adversary.sh` need `GUARD_LLM_API_KEY` or
`OPENROUTER_API_KEY` for the daemon's evaluator, plus a `claude` CLI.
`CLAUDE_CREDS` is required and must name a dedicated, short-lived test
identity credential, never a personal OAuth session.

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
