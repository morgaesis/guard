# Install

Guard is a single binary with no runtime dependencies beyond an LLM API key.

## Options

Install from source:

```bash
cargo install --path .
```

Build locally without installing:

```bash
cargo build --quiet --release
./target/release/guard --version
```

Install from a GitHub release artifact:

```bash
# Example for Linux x86_64
curl -fsSLO https://github.com/morgaesis/guard/releases/download/v0.1.0/guard-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
tar -xzf guard-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
install -m 0755 guard ~/.local/bin/guard
```

Choose the release asset that matches the target platform:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`

## Basic setup

Set an API key before use:

```bash
export GUARD_LLM_API_KEY="..."
```

Or:

```bash
export OPENROUTER_API_KEY="..."
```

Verify the binary:

```bash
guard --version
guard server start &
guard run uptime
```

On Windows, guard's native local transport is a named pipe with SID-based peer
authentication, selected with `--socket` (the name maps to `\\.\pipe\<name>`):

```powershell
guard server start --socket guard
guard config set-server guard
guard run whoami
```

The named-pipe SID is the caller's principal, with full parity to a Unix peer
uid, so consequence gating (`--gate consequence`), per-principal `--secret` /
`--env` injection, and daemon-principal admin all work over the pipe. The
operator is whoever runs as the daemon's own principal (its SID on Windows).
`--exec-as-caller` is Unix-only; on Windows the daemon executes approved commands
as its own service account. For the bypass-resistant gating deployment — guard as
a Windows service under a dedicated service account with an ACL'd state and
credential directory — use
[`deployment/windows/install-guard.ps1`](deployment/windows/install-guard.ps1).
See [DEPLOYMENT.md](DEPLOYMENT.md).

A TCP loopback transport is also available. It carries only a bearer token and no
local principal, so consequence gating and secret/`--env` injection are refused
over TCP, and admin RPCs require a separate admin token:

```powershell
guard server start --tcp-port 8123
guard config set-port 8123
guard config set-admin-token <admin-token>
guard run whoami
```

## Configuration

Configuration is environment-driven. See [`.env.example`](.env.example) for all available variables.

Key variables:

- `GUARD_LLM_API_KEY` / `OPENROUTER_API_KEY` -- LLM API key (required)
- `GUARD_LLM_API_URL` / `GUARD_API_URL` -- LLM endpoint (default: OpenRouter)
- `GUARD_LLM_MODEL` -- Primary model (default: `openai/gpt-5.4-nano`). For a fallback chain, use `GUARD_LLM_MODELS` with a comma-separated list; the chain takes precedence over this single-model value when set.
- `GUARD_MODE` -- Evaluation mode (default: `readonly`)
- `GUARD_LLM_TIMEOUT` / `GUARD_TIMEOUT` -- LLM call timeout in seconds (default: `30`)
- `GUARD_AUTH_TOKEN` -- Shared token for TCP clients
- `GUARD_ADMIN_TOKEN` -- Separate token for TCP admin RPCs such as `guard grant`
- `GUARD_LEARN_RULES` -- Learn static allows from repeated low-risk approvals
- `GUARD_LEARN_SHIMS` -- `off`, `suggest`, or `create` shorter service shims for promoted rules

For long-running service deployment, see [DEPLOYMENT.md](DEPLOYMENT.md).
