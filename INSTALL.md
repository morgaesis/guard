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
GUARD_VERSION=v0.9.0
curl -fsSLO "https://github.com/morgaesis/guard/releases/download/${GUARD_VERSION}/guard-${GUARD_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
curl -fsSLO "https://github.com/morgaesis/guard/releases/download/${GUARD_VERSION}/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf "guard-${GUARD_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
archive_root="guard-${GUARD_VERSION}-x86_64-unknown-linux-gnu"
install -d ~/.local/bin
install -m 0755 "$archive_root/guard" ~/.local/bin/guard
```

Each archive expands beneath its release-and-target directory. Linux archives
include the binary, systemd units, operator wrapper, hardening examples, and
generic verb examples. The Windows archive includes `guard.exe`, the PowerShell
installer and tests, an inner binary digest manifest, and the same examples.
Every archive includes the platform-marked examples. Guard rejects one at lint
or startup when its declared platform does not match the binary.
Installation uses files from the expanded archive rather than a source checkout.
The packaged execution-capable systemd services share the host `/tmp` namespace
with brokered children, so their temporary files remain visible to the caller
subject to normal file permissions.

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
sudo --preserve-env=GUARD_LLM_API_KEY guard server start \
  --exec-as-caller \
  --socket /run/guard/guard.sock \
  --socket-group "$(id -gn)" &
guard config set-server /run/guard/guard.sock
guard status
guard run uptime
```

`OPENROUTER_API_KEY` is also accepted. A durable service should load the key
from its protected environment or from Guard's secret backend.

On Windows, `--socket` selects a named pipe. Windows provides policy, access
administration, and inspection only; local process execution and API proxying
are unavailable because the platform has no distinct worker identity or secure
client-authority handoff:

```powershell
guard server start --socket guard
guard config set-server guard
guard status
```

The named-pipe peer SID supplies caller identity. The dedicated service installer
creates the service-account and protected state layout. Its stock pipe accepts
authenticated local users as distinct principals, so use it on a single-tenant
host or isolate the agent in its own host or VM:

Verify the downloaded archive against the release `SHA256SUMS` file. In an
elevated shell, extract that verified archive into an Administrators-and-SYSTEM
only directory. Read the binary digest from the archive's `BINARY-SHA256` file
and pass it explicitly. The installer copies the candidate into its protected
maintenance tree, verifies that digest, and only then executes the staged copy:

```powershell
$archive = Resolve-Path '.\guard-v0.9.0-x86_64-pc-windows-msvc.tar.gz'
$archiveHash = '<digest from the verified release SHA256SUMS>'
$protectedRoot = 'C:\ProgramData\GuardInstall'
New-Item -ItemType Directory -Force -Path $protectedRoot | Out-Null
& icacls.exe $protectedRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null
$protectedArchive = Join-Path $protectedRoot (Split-Path -Leaf $archive)
Copy-Item -LiteralPath $archive -Destination $protectedArchive
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $protectedArchive).Hash -ne $archiveHash) { throw 'Archive digest mismatch.' }
& tar.exe -C $protectedRoot -xzf $protectedArchive
$archiveRoot = 'C:\ProgramData\GuardInstall\guard-v0.9.0-x86_64-pc-windows-msvc'
$binaryHash = ((Get-Content -LiteralPath "$archiveRoot\BINARY-SHA256" -Raw).Trim() -split '\s+')[0]
& "$archiveRoot\deployment\windows\install-guard.ps1" `
  -Action install `
  -CandidateExe "$archiveRoot\guard.exe" `
  -ExpectedSha256 $binaryHash
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for Unix and Windows principal separation.

## TCP endpoint

Loopback TCP uses bearer identity rather than a kernel-authenticated local
principal. It requires an execution token and a separate admin token for admin
RPCs. Consequence gating and per-principal secret injection are unavailable.
On Unix, execution through `--exec-user` requires root or `CAP_SETUID` and
`CAP_SETGID`; the packaged systemd service configures this identity boundary.
The command below assumes those privileges are present.

```bash
export GUARD_AUTH_TOKEN="..."
export GUARD_ADMIN_TOKEN="..."
guard server start --tcp-port 8123 --exec-user guard-exec
```

Configure the port with `guard config set-port 8123`. Pipe each bearer to
`guard config set-token` or `guard config set-admin-token`, or run either
command at a terminal for a hidden prompt. The commands store the bearer in the
restricted client configuration without accepting it in process arguments.
Prefer the local socket or named pipe for a single-host deployment.

## Next steps

Use [`.env.example`](.env.example) and [Configuration](docs/configuration.md)
for daemon settings. Use [DEPLOYMENT.md](DEPLOYMENT.md) before granting the
daemon remote credentials or privileged local authority; its Upgrades section
covers replacing the binary of a deployed service and the state-database
schema behavior across versions.
