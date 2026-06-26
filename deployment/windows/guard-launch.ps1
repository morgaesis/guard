param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$EnvFile = $env:SSH_GUARD_WINDOWS_ENV_FILE,
    [int]$Port = 8123,
    [ValidateSet("off", "suggest", "create")]
    [string]$LearnShims = "create",
    [switch]$NoLearnRules,
    [switch]$NoCopyKubeconfig
)

$ErrorActionPreference = "Stop"

function New-GuardToken {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    return [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function Get-GuardListenerProcess {
    param([int]$ListenPort)

    $listeners = Get-NetTCPConnection -LocalPort $ListenPort -State Listen -ErrorAction SilentlyContinue
    foreach ($listener in $listeners) {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId = $($listener.OwningProcess)" -ErrorAction SilentlyContinue
        if ($process -and $process.CommandLine -match "guard\.exe" -and $process.CommandLine -match "server start") {
            return $process
        }
    }
    return $null
}

function Copy-KubeConfigFromWslIfMissing {
    if ($NoCopyKubeconfig) {
        return
    }
    $target = if ($env:KUBECONFIG) {
        ($env:KUBECONFIG -split [IO.Path]::PathSeparator)[0]
    }
    else {
        Join-Path $env:USERPROFILE ".kube\config"
    }
    if (-not $target) {
        return
    }
    if (Test-Path -LiteralPath $target) {
        return
    }
    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
        return
    }

    $script = 'p="${KUBECONFIG:-$HOME/.kube/config}"; p="${p%%:*}"; if [ -r "$p" ]; then cat "$p"; fi'
    $content = $null
    try {
        $content = & wsl.exe -d Ubuntu sh -lc $script 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $content) {
            $content = & wsl.exe sh -lc $script 2>$null
        }
    }
    catch {
        return
    }
    if (-not $content) {
        return
    }

    $targetDir = Split-Path -Parent $target
    if ($targetDir) {
        New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
    }
    Set-Content -LiteralPath $target -Value ($content -join "`n") -Encoding utf8
}

$guard = Join-Path $RepoRoot "target\release\guard.exe"
if (-not (Test-Path -LiteralPath $guard)) {
    $guard = "guard.exe"
}

if (-not $EnvFile) {
    $candidate = Join-Path $RepoRoot ".env"
    if (Test-Path -LiteralPath $candidate) {
        $EnvFile = $candidate
    }
}

$wanted = @(
    "OPENROUTER_API_KEY",
    "SSH_GUARD_LLM_API_KEY",
    "SSH_GUARD_LLM_MODEL",
    "SSH_GUARD_LLM_MODELS",
    "SSH_GUARD_LLM_API_URL",
    "SSH_GUARD_LLM_TIMEOUT",
    "SSH_GUARD_ADMIN_TOKEN"
)

if ($EnvFile -and (Test-Path -LiteralPath $EnvFile)) {
    foreach ($line in Get-Content -LiteralPath $EnvFile) {
        $trim = $line.Trim()
        if ($trim.Length -eq 0 -or $trim.StartsWith("#")) {
            continue
        }
        if ($trim -match "^export\s+") {
            $trim = $trim -replace "^export\s+", ""
        }
        $idx = $trim.IndexOf("=")
        if ($idx -lt 1) {
            continue
        }
        $name = $trim.Substring(0, $idx).Trim()
        if ($wanted -notcontains $name) {
            continue
        }
        $value = $trim.Substring($idx + 1).Trim()
        if (($value.StartsWith('"') -and $value.EndsWith('"')) -or
            ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        [Environment]::SetEnvironmentVariable($name, $value, "Process")
    }
}

if (-not $env:SSH_GUARD_AUTH_TOKEN) {
    $clientConfig = Join-Path $env:APPDATA "guard\client.yaml"
    if (Test-Path -LiteralPath $clientConfig) {
        $tokenLine = Get-Content -LiteralPath $clientConfig |
            Where-Object { $_ -match "^auth_token:" } |
            Select-Object -First 1
        if ($tokenLine) {
            $token = ($tokenLine -replace "^auth_token:\s*", "").Trim().Trim('"').Trim("'")
            if ($token) {
                $env:SSH_GUARD_AUTH_TOKEN = $token
            }
        }
    }
}

if (-not $env:SSH_GUARD_ADMIN_TOKEN) {
    $clientConfig = Join-Path $env:APPDATA "guard\client.yaml"
    if (Test-Path -LiteralPath $clientConfig) {
        $tokenLine = Get-Content -LiteralPath $clientConfig |
            Where-Object { $_ -match "^admin_token:" } |
            Select-Object -First 1
        if ($tokenLine) {
            $token = ($tokenLine -replace "^admin_token:\s*", "").Trim().Trim('"').Trim("'")
            if ($token) {
                $env:SSH_GUARD_ADMIN_TOKEN = $token
            }
        }
    }
}

if (-not $env:SSH_GUARD_AUTH_TOKEN) {
    $env:SSH_GUARD_AUTH_TOKEN = New-GuardToken
    & $guard config set-token $env:SSH_GUARD_AUTH_TOKEN | Out-Null
}

if (-not $env:SSH_GUARD_ADMIN_TOKEN) {
    $env:SSH_GUARD_ADMIN_TOKEN = New-GuardToken
    & $guard config set-admin-token $env:SSH_GUARD_ADMIN_TOKEN | Out-Null
}

Copy-KubeConfigFromWslIfMissing

& $guard config set-port $Port | Out-Null

$guardListener = Get-GuardListenerProcess -ListenPort $Port
if ($guardListener) {
    & $guard status *> $null
    if ($LASTEXITCODE -eq 0) {
        exit 0
    }
    throw "guard.exe is listening on port $Port, but the configured client cannot authenticate"
}

$otherListener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($otherListener) {
    throw "port $Port is already in use by a non-guard process"
}

$logDir = Join-Path $env:LOCALAPPDATA "guard"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$outLog = Join-Path $logDir "guard-daemon.out.log"
$errLog = Join-Path $logDir "guard-daemon.err.log"

$arguments = @("server", "start", "--tcp-port", "$Port")
if (-not $NoLearnRules) {
    $arguments += @("--learn-rules", "--learn-shims", $LearnShims)
}

$env:RUST_LOG = if ($env:RUST_LOG) { $env:RUST_LOG } else { "info" }

Start-Process `
    -FilePath $guard `
    -ArgumentList $arguments `
    -WorkingDirectory $RepoRoot `
    -WindowStyle Hidden `
    -RedirectStandardOutput $outLog `
    -RedirectStandardError $errLog
