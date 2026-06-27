<#
.SYNOPSIS
    Deploy the `guard` consequence-gating daemon on Windows as a bypass-resistant
    Windows service.

.DESCRIPTION
    Installs guard as a Windows service that runs under the virtual service
    account `NT SERVICE\guard`. That account is the operator/daemon principal:
    it owns the named-pipe transport, the SQLite state database, the verb
    catalog, and the brokered kubeconfig. The interactive logged-in user (who
    runs AI agents) is a different, non-admin Windows principal and is therefore
    structurally unable to:

      1. Approve / deny / confirm / revert its own gated commands. The daemon's
         `validate_admin` (src/server.rs) only accepts an admin RPC when the
         connecting peer's SID equals the daemon's own SID. The agent connects
         to the pipe as its own SID, which is NOT the guard SID, so every
         `guard approve|deny|confirm|revert` it issues is refused. Only a caller
         running AS `NT SERVICE\guard` is accepted as the operator.

      2. Read the brokered credentials (the guard-only kubeconfig) or read/forge
         the daemon state (state.db). The data directory ACL grants FULL only to
         the guard SID, SYSTEM, and Administrators, and explicitly removes Users,
         Authenticated Users, and Everyone. A non-admin agent opening state.db or
         the kubeconfig gets ACCESS_DENIED from the kernel — it cannot read a
         brokered secret and cannot write a forged "approved" row to flip a held
         command into an executed one.

    The single trust boundary is Windows account isolation enforced by:
      * the named-pipe SID check in the daemon (operator identity), and
      * the NTFS DACL on C:\ProgramData\guard (state + credential confidentiality).

    Because creating or running a scheduled task AS a service account requires
    Administrator rights, the non-admin agent cannot fabricate the operator path
    either: the only way to act as `NT SERVICE\guard` from a console is through an
    elevated (UAC) action, which the agent cannot self-grant.

.NOTES
    Run from an elevated PowerShell for any action that changes system state
    (install, uninstall, approve, deny, confirm, revert). `status`,
    `provisionals`, and `approvals` are read-only and run as the current user.

    Guard CLI flags used here are the only ones that exist (verified against
    src/main.rs clap definitions):
      server start --socket <name> --gate consequence --state-db <path>
                   --verbs <path> [--no-llm]
      approve|deny|confirm|revert <handle> --socket <name>
      provisionals --socket <name>
      approvals [<handle>] --socket <name>
      config set-server <name>
#>

[CmdletBinding()]
param(
    # Subcommand. Defaults to a full install.
    [ValidateSet('install', 'uninstall', 'status', 'approve', 'deny', 'confirm', 'revert', 'provisionals', 'approvals')]
    [string]$Action = 'install',

    # Handle for approve/deny/confirm/revert (the value printed by `guard run`
    # when a command is HELD or PROVISIONAL).
    [string]$Handle,

    # Repo root, used to locate guard.exe and the bundled verb catalog.
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,

    # Optional .env file supplying an LLM API key. When omitted (and no key is
    # found), the service runs with --no-llm (static/verb policy only). The
    # legacy SSH_GUARD_WINDOWS_ENV_FILE name is still honored as a fallback.
    [string]$EnvFile = ($(if ($env:GUARD_WINDOWS_ENV_FILE) { $env:GUARD_WINDOWS_ENV_FILE } else { $env:SSH_GUARD_WINDOWS_ENV_FILE })),

    # uninstall only: also delete the data directory (state.db + brokered creds).
    [switch]$Purge
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Constants. These are the bypass boundary; keep them in one place.
# ---------------------------------------------------------------------------

# Windows service name. `NT SERVICE\<name>` is the virtual service account.
$ServiceName = 'guard'

# Virtual service account the daemon runs as. No password, isolated profile,
# deterministic SID derivable from the service name via `sc.exe showsid`.
$ServiceAccount = 'NT SERVICE\guard'

# Named pipe transport name. The daemon maps `--socket guard` to
# \\.\pipe\guard (winplat::pipe_name). Clients reach it with
# `guard config set-server guard`.
$SocketName = 'guard'
$PipePath = '\\.\pipe\guard'

# State + credential directory. This is the confidentiality boundary.
$DataDir = 'C:\ProgramData\guard'
$StateDb = Join-Path $DataDir 'state.db'
$VerbsPath = Join-Path $DataDir 'verbs.yaml'
# Guard-only kubeconfig: brokered kubectl reads it, the agent cannot.
$KubeDir = Join-Path $DataDir 'kube'
$KubeConfig = Join-Path $KubeDir 'config'
# Scratch dir for transient-task output capture (inside the ACL'd boundary so
# only the operator/admin can read a captured operator action's output).
$TaskOutDir = Join-Path $DataDir 'taskout'
# Deployed daemon binary: a copy of guard.exe INSIDE the ACL'd data dir. The
# service account runs this copy (it can read+execute it once the dir ACL grants
# the guard SID FULL; the agent cannot read it). The agent runs its own
# (worktree/PATH) copy as a client, so the two never need to share a binary path.
$DeployedExe = Join-Path $DataDir 'guard.exe'

# Well-known SIDs used in ACLs. Using SIDs (not localized names) keeps the
# script correct on non-English Windows.
$SidSystem = 'S-1-5-18'         # NT AUTHORITY\SYSTEM
$SidAdmins = 'S-1-5-32-544'     # BUILTIN\Administrators
$SidUsers = 'S-1-5-32-545'      # BUILTIN\Users
$SidAuthUsers = 'S-1-5-11'      # NT AUTHORITY\Authenticated Users
$SidEveryone = 'S-1-1-0'        # Everyone

# Service env vars guard reads for the LLM (resolved by guard_env in main.rs:
# GUARD_* then SSH_GUARD_*). Only the API key is sensitive; the rest are config.
# The legacy SSH_GUARD_* names are kept here so an operator whose env file still
# uses the old prefix continues to work.
$LlmEnvKeys = @(
    'GUARD_LLM_API_KEY',
    'SSH_GUARD_LLM_API_KEY',
    'OPENROUTER_API_KEY',
    'GUARD_LLM_MODEL',
    'SSH_GUARD_LLM_MODEL',
    'GUARD_LLM_MODELS',
    'SSH_GUARD_LLM_MODELS',
    'GUARD_LLM_API_URL',
    'SSH_GUARD_LLM_API_URL',
    'GUARD_LLM_TIMEOUT',
    'SSH_GUARD_LLM_TIMEOUT'
)

# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------

function Test-Admin {
    # Elevation check exactly as specified: a non-admin agent must fail this for
    # every state-changing action, which is what forces operator actions through
    # a UAC prompt the agent cannot satisfy.
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$id
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Assert-Admin {
    param([string]$ForAction)
    if (-not (Test-Admin)) {
        throw "Action '$ForAction' requires Administrator. Right-click PowerShell and 'Run as administrator', then re-run. This elevation gate is part of the security model: a non-admin agent cannot run operator actions."
    }
}

function Resolve-GuardExe {
    # Locate guard.exe: prefer the release build, then debug, then PATH. The
    # service binPath needs a fixed absolute path, so PATH-only is only used as a
    # last resort (and resolved to a full path).
    $candidates = @(
        (Join-Path $RepoRoot 'target\release\guard.exe'),
        (Join-Path $RepoRoot 'target\debug\guard.exe')
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { return (Resolve-Path -LiteralPath $c).Path }
    }
    $cmd = Get-Command 'guard.exe' -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw "guard.exe not found. Build it first (cargo build --release) or place it on PATH. Looked in: $($candidates -join ', ')"
}

function Get-GuardSid {
    # Deterministic NT SERVICE\guard SID. `sc.exe showsid <name>` derives the SID
    # purely from the service name and works BEFORE the service exists, so we can
    # display it any time. NOTE: although the SID value is deterministic, icacls
    # cannot RESOLVE it (neither the `*S-1-5-80-...` SID form nor the
    # `NT SERVICE\guard` name form) until the service has actually been created —
    # both fail with "No mapping between account names and security IDs" (error
    # 1332) on a non-existent service. The install therefore creates the service
    # FIRST, then applies the guard-SID grant. Output looks like:
    #     NAME: guard
    #     SERVICE SID: S-1-5-80-...
    $out = & sc.exe showsid $ServiceName 2>&1
    $line = $out | Where-Object { $_ -match 'SERVICE SID\s*:\s*(S-1-5-80-\S+)' } | Select-Object -First 1
    if (-not $line) {
        throw "Could not derive the guard service SID from 'sc.exe showsid $ServiceName'. Output: $($out -join '; ')"
    }
    [void]($line -match '(S-1-5-80-\S+)')
    return $Matches[1]
}

function Set-DataDirAcl {
    <#
        Apply the bypass-boundary DACL to a directory: break inheritance, then
        grant FULL only to the guard SID, SYSTEM, and Administrators, and remove
        every broad principal (Users, Authenticated Users, Everyone). With
        inheritance broken and no broad ACE, a non-admin agent gets ACCESS_DENIED
        opening anything under this directory — it cannot read brokered secrets or
        the daemon state, and cannot write a forged approval row.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$GuardSid
    )

    # IMPORTANT ORDERING: the guard service SID only resolves in icacls after the
    # service exists, so callers MUST create the service before calling this. We
    # grant SYSTEM + Administrators first (always resolvable), then the guard SID.

    # /inheritance:r removes inherited ACEs and stops inheritance. Without an
    # explicit grant afterward the dir would have NO access at all, so we grant
    # the trusted principals immediately after.
    & icacls $Path /inheritance:r | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls /inheritance:r failed on $Path (exit $LASTEXITCODE)" }

    # Grant FULL (F) to SYSTEM and Administrators by well-known SID (`*S-...`) so
    # this is locale-independent. (OI)(CI) makes the grant inherit to files and
    # subdirs so state.db, verbs.yaml, and the kube/ + taskout/ subtrees pick it up.
    foreach ($sid in @($SidSystem, $SidAdmins)) {
        & icacls $Path /grant:r "*${sid}:(OI)(CI)F" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "icacls grant failed for $sid on $Path (exit $LASTEXITCODE)" }
    }

    # Grant FULL to the guard service SID. This is the operator/daemon principal
    # and the only non-admin account allowed into the boundary. It resolves only
    # because the service already exists (see ordering note above).
    & icacls $Path /grant:r "*${GuardSid}:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls grant failed for the guard SID $GuardSid on $Path (exit $LASTEXITCODE). The service must be created before the ACL is applied so the SID resolves."
    }

    # Belt-and-suspenders: explicitly remove the broad principals. After
    # /inheritance:r they should already be gone, but a re-run on a dir that was
    # previously created with defaults (or hand-edited) must converge to the
    # locked state. /remove is idempotent (no error if the ACE is absent).
    foreach ($sid in @($SidUsers, $SidAuthUsers, $SidEveryone)) {
        & icacls $Path /remove:g "*${sid}" | Out-Null
        # Do not hard-fail: removing an absent trustee is a no-op we tolerate.
    }
}

function Import-LlmKeyFromEnvFile {
    <#
        Parse an .env file for an LLM API key (and related config) and return a
        hashtable of env-var name => value. Tolerates `export `, quotes, and
        comments. Never logs values. Only the small allow-list of LLM-related
        keys is read.
    #>
    param([string]$Path)
    $result = @{}
    if (-not $Path) { return $result }
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Warning "EnvFile '$Path' not found; service will start with --no-llm unless a key is already in the service env."
        return $result
    }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trim = $line.Trim()
        if ($trim.Length -eq 0 -or $trim.StartsWith('#')) { continue }
        if ($trim -match '^export\s+') { $trim = $trim -replace '^export\s+', '' }
        $idx = $trim.IndexOf('=')
        if ($idx -lt 1) { continue }
        $name = $trim.Substring(0, $idx).Trim()
        if ($LlmEnvKeys -notcontains $name) { continue }
        $value = $trim.Substring($idx + 1).Trim()
        if (($value.StartsWith('"') -and $value.EndsWith('"')) -or
            ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        if ($value) { $result[$name] = $value }
    }
    return $result
}

function Invoke-GuardAsOperator {
    <#
        Run a guard action AS the operator (NT SERVICE\guard) via a transient
        scheduled task, and return its captured stdout/stderr.

        WHY a scheduled task: the daemon accepts an admin RPC only from a peer
        whose SID equals the guard SID. The operator therefore has to RUN the
        guard client process under the guard account. Windows lets you run a
        process as a virtual service account only through the Task Scheduler (or
        a service), and CREATING/RUNNING such a task requires Administrator. That
        is the whole point: the non-admin agent cannot create or run this task,
        so it cannot reach the operator gate. The human operator triggers this
        from an elevated console (a UAC prompt), which the agent cannot self-grant.

        Output capture: schtasks does not return a task's stdout. We wrap the
        guard invocation in a cmd.exe redirect to a file UNDER the ACL'd data
        directory (so only operator/admin can read it), run the task, wait for it
        to finish, read the file back, then delete both the file and the task.

        UNVERIFIED ON A LIVE HOST: running a task whose principal is a virtual
        service account, and the exact RunLevel/working-dir behavior of the
        redirect, need elevated testing. See the report.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('approve', 'deny', 'confirm', 'revert', 'provisionals', 'approvals')]
        [string]$GuardAction,
        [string]$ActionHandle,
        [Parameter(Mandatory)][string]$GuardExe
    )

    $taskName = "guard-op-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Force -Path $TaskOutDir | Out-Null
    $outFile = Join-Path $TaskOutDir "$taskName.out"

    # Build the guard argument list. `provisionals`/`approvals` take no handle.
    $guardArgs = @($GuardAction)
    if ($GuardAction -in @('approve', 'deny', 'confirm', 'revert')) {
        if (-not $ActionHandle) { throw "Action '$GuardAction' requires -Handle <handle>." }
        $guardArgs += $ActionHandle
    }
    $guardArgs += @('--socket', $SocketName)

    # The task runs cmd.exe so we can redirect combined stdout+stderr to the
    # capture file. Quote the exe and any path-bearing args. The guard handle and
    # socket name are constrained tokens, but quote defensively anyway.
    $quotedGuard = '"' + $GuardExe + '"'
    $quotedArgs = ($guardArgs | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $quotedOut = '"' + $outFile + '"'
    # /c runs then exits. 1> file 2>&1 captures both streams.
    $cmdLine = "$quotedGuard $quotedArgs 1>$quotedOut 2>&1"

    # Create the task:
    #   /RU "NT SERVICE\guard"  -> run as the operator principal (no password)
    #   /RL LIMITED             -> RunLevel Limited (the daemon does not need
    #                              elevation; the operator identity is what matters)
    #   /SC ONCE /ST 00:00      -> a one-shot schedule we will trigger manually
    #   /F                      -> overwrite if a stale task with this name exists
    # The action is `cmd /c "<cmdline>"`. schtasks wants the whole thing as /TR.
    & schtasks.exe /Create /TN $taskName /TR "cmd.exe /c $cmdLine" /SC ONCE /ST 00:00 /RU $ServiceAccount /RL LIMITED /F | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "schtasks /Create failed for operator action '$GuardAction' (exit $LASTEXITCODE). Are you elevated?"
    }

    try {
        # Trigger it now.
        & schtasks.exe /Run /TN $taskName | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "schtasks /Run failed for '$taskName' (exit $LASTEXITCODE)." }

        # Poll until the task's last run completes. A running task reports
        # Status 'Running'; once done it goes back to 'Ready'. We bound the wait.
        $deadline = (Get-Date).AddSeconds(60)
        do {
            Start-Sleep -Milliseconds 400
            $query = & schtasks.exe /Query /TN $taskName /FO LIST /V 2>$null
            $statusLine = $query | Where-Object { $_ -match '^\s*Status:\s*(.+)$' } | Select-Object -First 1
            $running = $statusLine -and ($statusLine -match 'Running')
        } while ($running -and (Get-Date) -lt $deadline)

        # Read captured output (file lives under the ACL'd dir).
        if (Test-Path -LiteralPath $outFile) {
            return (Get-Content -LiteralPath $outFile -Raw)
        }
        return "(no output captured; the operator task produced none or did not run)"
    }
    finally {
        # Clean up the transient task and its capture file regardless of outcome.
        & schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null
        if (Test-Path -LiteralPath $outFile) {
            Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
        }
    }
}

# ---------------------------------------------------------------------------
# Actions.
# ---------------------------------------------------------------------------

function Invoke-Install {
    Assert-Admin -ForAction 'install'

    $guardExe = Resolve-GuardExe
    $guardSid = Get-GuardSid
    Write-Host "guard.exe:   $guardExe"
    Write-Host "guard SID:   $guardSid  ($ServiceAccount)"

    # 1. Create the data + subdirectories. They are NOT yet ACL'd: the guard
    #    service SID does not resolve in icacls until the service exists (step 5),
    #    so the lockdown happens in step 6, before the daemon is ever started
    #    (step 9). The daemon writes nothing until then, so the first state.db /
    #    kubeconfig bytes are still born inside the locked boundary.
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    New-Item -ItemType Directory -Force -Path $KubeDir | Out-Null
    New-Item -ItemType Directory -Force -Path $TaskOutDir | Out-Null

    # 1b. Deploy the daemon binary into the boundary (copied BEFORE the ACL is
    #     applied in step 6, so the guard SID's later FULL grant covers it). The
    #     service account runs this copy; the source under the user profile is not
    #     readable by the guard SID.
    Copy-Item -LiteralPath $guardExe -Destination $DeployedExe -Force
    Write-Host "Deployed daemon binary -> $DeployedExe"

    # 2. Install the verb catalog if absent. The catalog is the typed, least-
    #    expressive interface; only the operator edits it. Placing it under the
    #    soon-to-be-ACL'd dir means the agent can run verbs but cannot rewrite them.
    if (-not (Test-Path -LiteralPath $VerbsPath)) {
        $srcVerbs = Join-Path $RepoRoot 'examples\verbs-kubectl.yaml'
        if (Test-Path -LiteralPath $srcVerbs) {
            Copy-Item -LiteralPath $srcVerbs -Destination $VerbsPath -Force
            Write-Host "Installed verb catalog -> $VerbsPath"
        }
        else {
            Write-Warning "Bundled verb catalog not found at $srcVerbs; the service will start without --verbs unless you place one at $VerbsPath."
        }
    }
    else {
        Write-Host "Verb catalog already present at $VerbsPath (left as-is)."
    }

    # 3. Resolve LLM config. If we have an API key, the daemon can do LLM
    #    evaluation; otherwise it runs --no-llm (static policy + verb catalog).
    $llmEnv = Import-LlmKeyFromEnvFile -Path $EnvFile
    $haveKey = $llmEnv.ContainsKey('GUARD_LLM_API_KEY') -or
               $llmEnv.ContainsKey('SSH_GUARD_LLM_API_KEY') -or
               $llmEnv.ContainsKey('OPENROUTER_API_KEY')

    # 4. Build the service binPath. Only flags that exist in src/main.rs.
    #    --socket guard            -> named pipe \\.\pipe\guard with SID auth
    #    --gate consequence        -> reversibility routing + operator approval
    #    --state-db / --verbs      -> both inside the ACL'd boundary
    #    --no-llm                  -> only when no key is configured
    $binArgs = @(
        'server', 'start',
        '--socket', $SocketName,
        '--gate', 'consequence',
        '--state-db', $StateDb,
        '--verbs', $VerbsPath
    )
    if (-not $haveKey) { $binArgs += '--no-llm' }

    # sc.exe binPath is a single string; quote the exe (it can contain spaces)
    # and the path-bearing args.
    $binPathParts = @('"' + $DeployedExe + '"')
    foreach ($a in $binArgs) {
        if ($a -match '[\s\\:]') { $binPathParts += '"' + $a + '"' } else { $binPathParts += $a }
    }
    $binPath = $binPathParts -join ' '

    # 5. Create or update the service. This must precede the ACL: the guard
    #    service SID is unresolvable to icacls until the service exists. sc.exe
    #    create fails if the service already exists, so check first and use
    #    `config` to update for idempotency.
    $exists = (& sc.exe query $ServiceName 2>$null | Select-String -SimpleMatch 'SERVICE_NAME').Count -gt 0
    if ($exists) {
        Write-Host "Service '$ServiceName' exists; updating binPath/start/account."
        # Stop before reconfiguring so a running daemon picks up new args on start.
        & sc.exe stop $ServiceName 2>$null | Out-Null
        # Note the required `key= value` spacing sc.exe demands (space AFTER =).
        & sc.exe config $ServiceName binPath= "$binPath" start= auto obj= "$ServiceAccount" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe config failed (exit $LASTEXITCODE)" }
    }
    else {
        Write-Host "Creating service '$ServiceName' as $ServiceAccount."
        # obj= "NT SERVICE\guard" with NO password= : virtual service accounts
        # have no password and an isolated profile. This is what gives the daemon
        # a distinct SID (the bypass boundary) without managing a credential.
        & sc.exe create $ServiceName binPath= "$binPath" start= auto obj= "$ServiceAccount" DisplayName= "guard consequence gate" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed (exit $LASTEXITCODE)" }
    }

    # 6. Lock down the data directory now that the guard SID resolves. This is
    #    the confidentiality boundary: FULL to guard SID / SYSTEM / Administrators,
    #    every broad principal removed. Applied before the daemon starts (step 9).
    Set-DataDirAcl -Path $DataDir -GuardSid $guardSid
    Write-Host "ACL applied to $DataDir (FULL: guard SID, SYSTEM, Administrators; Users/AuthUsers/Everyone removed)."

    # 7. Failure recovery: restart on crash so the gate stays up. reset= 86400
    #    resets the failure counter daily; three restart actions with backoff.
    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning "sc.exe failure config returned exit $LASTEXITCODE (non-fatal)." }

    # 8. Service environment. KUBECONFIG points the brokered kubectl at the
    #    guard-only kubeconfig that lives inside the ACL'd dir, so brokered
    #    kubectl reads a config the agent cannot see. Plus any LLM env.
    #    Service env lives in the service's registry key
    #    (HKLM\SYSTEM\CurrentControlSet\Services\<name>\Environment) as a
    #    REG_MULTI_SZ. It is readable by admins (trusted) but NOT by the non-admin
    #    agent, which cannot read other accounts' service config.
    $serviceEnv = @("KUBECONFIG=$KubeConfig")
    foreach ($k in $llmEnv.Keys) { $serviceEnv += "$k=$($llmEnv[$k])" }
    Set-ServiceEnvironment -Name $ServiceName -Pairs $serviceEnv
    if ($haveKey) {
        Write-Host "Service env: KUBECONFIG + LLM key(s) set (values not logged)."
    }
    else {
        Write-Host "Service env: KUBECONFIG set; no LLM key found, daemon runs --no-llm."
    }

    # 9. Start the service.
    & sc.exe start $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "sc.exe start returned exit $LASTEXITCODE. Check 'sc.exe query $ServiceName' and the Windows Event Log (Application)."
    }

    Write-Host ''
    Write-Host 'Install complete. Next steps:'
    Write-Host "  1. As an admin, drop a NON-PRODUCTION kubeconfig at:"
    Write-Host "       $KubeConfig"
    Write-Host "     (it inherits the locked ACL; the agent cannot read it)."
    Write-Host "  2. Point the client/agent at the daemon:"
    Write-Host "       guard config set-server $SocketName"
    Write-Host "  3. Agents call gated kubectl via verbs, e.g.:"
    Write-Host "       guard verb run k-get --param context=morgaesis --param resource=pods --param namespace=default"
    Write-Host "  4. Approve a HELD command (operator, elevated console):"
    Write-Host "       .\install-guard.ps1 -Action approve -Handle <handle>"
}

function Set-ServiceEnvironment {
    # Write the service's Environment value (REG_MULTI_SZ). Requires admin (we
    # are already elevated in install). Each entry is NAME=VALUE.
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Pairs
    )
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if (-not (Test-Path $key)) { throw "Service registry key not found: $key (was the service created?)" }
    # REG_MULTI_SZ is represented as a string array in PowerShell.
    New-ItemProperty -Path $key -Name 'Environment' -PropertyType MultiString -Value $Pairs -Force | Out-Null
}

function Invoke-Uninstall {
    Assert-Admin -ForAction 'uninstall'
    & sc.exe stop $ServiceName 2>$null | Out-Null
    # Give the SCM a moment; deletion of a STOP_PENDING service can fail.
    Start-Sleep -Milliseconds 800
    & sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "sc.exe delete returned exit $LASTEXITCODE (service may not have existed)."
    }
    else {
        Write-Host "Service '$ServiceName' deleted."
    }
    if ($Purge) {
        if (Test-Path -LiteralPath $DataDir) {
            Remove-Item -LiteralPath $DataDir -Recurse -Force
            Write-Host "Purged data directory $DataDir (state.db + brokered creds removed)."
        }
    }
    else {
        Write-Host "Data directory $DataDir left in place (pass -Purge to remove it)."
    }
}

function Invoke-Status {
    # Read-only: safe to run as the current (possibly non-admin) user.
    Write-Host "Service:"
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "  name     $($svc.Name)"
        Write-Host "  status   $($svc.Status)"
        $wmi = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
        if ($wmi) {
            Write-Host "  account  $($wmi.StartName)"
            Write-Host "  start    $($wmi.StartMode)"
        }
    }
    else {
        Write-Host "  (not installed)"
    }

    Write-Host ""
    Write-Host "Pipe:"
    # A connected named pipe shows up as a file under \\.\pipe\. Listing the pipe
    # filesystem and matching the name is the simplest existence probe.
    $pipeUp = $false
    try {
        $pipeUp = [bool]([System.IO.Directory]::GetFiles('\\.\pipe\') | Where-Object { $_ -match '\\guard$' })
    }
    catch { $pipeUp = $false }
    Write-Host "  $PipePath  ->  $(if ($pipeUp) { 'present' } else { 'absent' })"

    Write-Host ""
    Write-Host "Operator principal:"
    try { Write-Host "  guard SID  $(Get-GuardSid)  ($ServiceAccount)" }
    catch { Write-Host "  (could not derive SID: $_)" }

    Write-Host ""
    Write-Host "Data dir ACL ($DataDir):"
    if (Test-Path -LiteralPath $DataDir) {
        & icacls $DataDir | ForEach-Object { Write-Host "  $_" }
    }
    else {
        Write-Host "  (data directory does not exist)"
    }
}

function Invoke-OperatorAction {
    param([string]$GuardAction)
    Assert-Admin -ForAction $GuardAction
    $out = Invoke-GuardAsOperator -GuardAction $GuardAction -ActionHandle $Handle -GuardExe $DeployedExe
    Write-Host $out
}

function Invoke-ReadOnlyView {
    # provisionals / approvals listing. These are principal-scoped: run as the
    # current user, they show only that principal's items. To see ALL items as
    # the operator (every agent's held/provisional commands), we route through
    # the transient-task helper so the listing runs AS the guard SID. That
    # requires elevation, so non-admins fall back to the principal-scoped view.
    param([string]$GuardAction)
    if (Test-Admin) {
        Write-Host "(operator view: listing as $ServiceAccount)"
        $out = Invoke-GuardAsOperator -GuardAction $GuardAction -GuardExe $DeployedExe
        Write-Host $out
    }
    else {
        Write-Host "(current-user view: not elevated, showing only your own items)"
        $guardExe = Resolve-GuardExe
        $callerArgs = @($GuardAction, '--socket', $SocketName)
        & $guardExe @callerArgs
    }
}

# ---------------------------------------------------------------------------
# Dispatch.
# ---------------------------------------------------------------------------

switch ($Action) {
    'install'      { Invoke-Install }
    'uninstall'    { Invoke-Uninstall }
    'status'       { Invoke-Status }
    'approve'      { Invoke-OperatorAction -GuardAction 'approve' }
    'deny'         { Invoke-OperatorAction -GuardAction 'deny' }
    'confirm'      { Invoke-OperatorAction -GuardAction 'confirm' }
    'revert'       { Invoke-OperatorAction -GuardAction 'revert' }
    'provisionals' { Invoke-ReadOnlyView -GuardAction 'provisionals' }
    'approvals'    { Invoke-ReadOnlyView -GuardAction 'approvals' }
}
