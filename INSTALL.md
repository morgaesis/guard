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
export SSH_GUARD_LLM_API_KEY="..."
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

On Windows, use the loopback TCP transport:

```powershell
guard server start --tcp-port 8123
guard config set-port 8123
guard config set-admin-token <admin-token>
guard run whoami
```

## Configuration

Configuration is environment-driven. See [`.env.example`](.env.example) for all available variables.

Key variables:

- `SSH_GUARD_LLM_API_KEY` / `OPENROUTER_API_KEY` -- LLM API key (required)
- `SSH_GUARD_LLM_API_URL` / `SSH_GUARD_API_URL` -- LLM endpoint (default: OpenRouter)
- `SSH_GUARD_LLM_MODEL` -- Primary model (default: `openai/gpt-5.4-nano`). For a fallback chain, use `SSH_GUARD_LLM_MODELS` with a comma-separated list; the chain takes precedence over this single-model value when set.
- `SSH_GUARD_MODE` -- Evaluation mode (default: `readonly`)
- `SSH_GUARD_LLM_TIMEOUT` / `SSH_GUARD_TIMEOUT` -- LLM call timeout in seconds (default: `30`)
- `SSH_GUARD_AUTH_TOKEN` -- Shared token for TCP clients
- `SSH_GUARD_ADMIN_TOKEN` -- Separate token for TCP admin RPCs such as `guard grant`
- `SSH_GUARD_LEARN_RULES` -- Learn static allows from repeated low-risk approvals
- `SSH_GUARD_LEARN_SHIMS` -- `off`, `suggest`, or `create` shorter service shims for promoted rules

For long-running service deployment, see [DEPLOYMENT.md](DEPLOYMENT.md).
