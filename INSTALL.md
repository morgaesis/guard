# Install

Guard is a single binary. LLM evaluation requires an API key or a configured
daemon-side secret backend.

## From source

```bash
cargo install --path .
guard --version
```

Build without installing:

```bash
cargo build --quiet --release
./target/release/guard --version
```

## Release archive

```bash
GUARD_VERSION=v0.5.0
curl -fsSLO "https://github.com/morgaesis/guard/releases/download/${GUARD_VERSION}/guard-${GUARD_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
curl -fsSLO "https://github.com/morgaesis/guard/releases/download/${GUARD_VERSION}/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf "guard-${GUARD_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
install -m 0755 guard ~/.local/bin/guard
```

Published targets are:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-pc-windows-msvc`

Build from source on macOS. The release workflow does not publish macOS assets.

Releases also ship per-target CycloneDX SBOMs and signed build provenance
attestations. See [Release verification](docs/release-verification.md) for
checking them.

## Local endpoint

Set the evaluator key where the daemon starts:

```bash
export GUARD_LLM_API_KEY="..."
guard server start &
guard status
guard run uptime
```

`OPENROUTER_API_KEY` is also accepted. A durable service should load the key
from its protected environment or from Guard's secret backend.

On Windows, `--socket` selects a named pipe:

```powershell
guard server start --socket guard
guard config set-server guard
guard run whoami
```

The named-pipe peer SID supplies caller identity. The dedicated service installer
creates the bypass-resistant account and ACL layout:

```powershell
deployment\windows\install-guard.ps1
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for Unix and Windows principal separation.

## TCP endpoint

Loopback TCP uses bearer identity rather than a kernel-authenticated local
principal. It requires an execution token and a separate admin token for admin
RPCs. Consequence gating and per-principal secret injection are unavailable.

```bash
export GUARD_AUTH_TOKEN="..."
export GUARD_ADMIN_TOKEN="..."
guard server start --tcp-port 8123
```

Configure the port with `guard config set-port 8123`. The client commands
`guard config set-token <token>` and `guard config set-admin-token <token>`
store the corresponding bearer in the restricted client configuration, but
their required value argument can enter process listings and shell history.
Prefer the local socket or named pipe for a single-host deployment.

## Next steps

Use [`.env.example`](.env.example) and [Configuration](docs/configuration.md)
for daemon settings. Use [DEPLOYMENT.md](DEPLOYMENT.md) before granting the
daemon remote credentials or privileged local authority; its Upgrades section
covers replacing the binary of a deployed service and the state-database
schema behavior across versions.
