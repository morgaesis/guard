<#
.SYNOPSIS
    Install, operate, and roll back the Guard Windows service.

.DESCRIPTION
    Guard runs as NT SERVICE\guard. Program files and the operator-maintenance
    tree are owned by Administrators and SYSTEM. The service can read and
    execute the installed binary and read the operator catalog, but it cannot
    modify either location or read installer backups. The state and credential
    tree is writable by the service.

    Administrative RPCs run in a transient scheduled task as the supported
    local SYSTEM identity. Guard authorizes only the kernel-authenticated SYSTEM
    SID as this additional Windows operator. Task operands are validated and
    base64 encoded as data before PowerShell task syntax is constructed.

    The named pipe authenticates each local caller SID but does not restrict
    connections to one agent SID. Place mutually untrusted local accounts on
    separate hosts or virtual machines.

.EXAMPLE
    .\install-guard.ps1 -Action install -CandidateExe .\guard.exe -ExpectedSha256 <manifest-sha256>

.EXAMPLE
    .\install-guard.ps1 -Action access-approve -Reference gr-<32-hex>

.EXAMPLE
    .\install-guard.ps1 -Action access-approve -Reference <request-1>,<request-2> -ApprovalMode uses -Uses 3 -Json

.EXAMPLE
    .\install-guard.ps1 -Action rollback -Backup <backup-name>
#>

[CmdletBinding()]
param(
    [ValidateSet(
        'install', 'uninstall', 'status', 'rollback',
        'access-approve', 'access-deny', 'access-extend', 'access-revoke',
        'access-list', 'access-show', 'confirm', 'revert', 'provisionals'
    )]
    [string]$Action = 'install',

    [string[]]$Reference = @(),

    [ValidateSet('ordinary', 'once', 'uses')]
    [string]$ApprovalMode = 'ordinary',

    [long]$Uses = 0,
    [string]$Intent,
    [string]$Reason,
    [switch]$Json,
    # Retains bounded sanitized output only. Executable tasks are always removed.
    [switch]$PreserveDiagnostics,

    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$CandidateExe,
    [string]$ExpectedSha256,
    [string]$Backup,

    # Values from this allowlisted file merge into the protected service
    # environment. Omitting the file preserves all existing values.
    [string]$EnvFile = $env:GUARD_WINDOWS_ENV_FILE,

    # Uninstall only. This removes retained state, credentials, and backups.
    [switch]$Purge
)

$ErrorActionPreference = 'Stop'

$ServiceName = 'guard'
$ServiceAccount = 'NT SERVICE\guard'
$OperatorAccount = 'SYSTEM'
$SocketName = 'guard'
$PipePath = '\\.\pipe\guard'

$InstallRoot = 'C:\Program Files\Guard'
$DeployedExe = Join-Path $InstallRoot 'guard.exe'
$ConfigRoot = 'C:\ProgramData\GuardConfig'
$VerbsPath = Join-Path $ConfigRoot 'verbs.yaml'
$DataDir = 'C:\ProgramData\Guard'
$StateDb = Join-Path $DataDir 'state.db'
$KubeDir = Join-Path $DataDir 'kube'
$KubeConfig = Join-Path $KubeDir 'config'
$MaintenanceRoot = 'C:\ProgramData\GuardMaintenance'
$StagingDir = Join-Path $MaintenanceRoot 'staging'
$BackupRoot = Join-Path $MaintenanceRoot 'backups'
$TaskOutDir = Join-Path $MaintenanceRoot 'task-output'

$ServiceReadinessTimeoutSeconds = 30
$OperatorTaskTimeoutSeconds = 60
$BackupMetadataSchema = 2

$SidSystem = 'S-1-5-18'
$SidAdmins = 'S-1-5-32-544'
$SidUsers = 'S-1-5-32-545'
$SidAuthUsers = 'S-1-5-11'
$SidEveryone = 'S-1-1-0'

$LlmEnvKeys = @(
    'GUARD_LLM_API_KEY',
    'OPENROUTER_API_KEY',
    'GUARD_LLM_MODEL',
    'GUARD_LLM_MODELS',
    'GUARD_LLM_API_URL',
    'GUARD_LLM_TIMEOUT'
)

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Assert-Admin {
    param([Parameter(Mandatory)][string]$ForAction)
    if (-not (Test-Admin)) {
        throw "Action '$ForAction' requires an elevated PowerShell."
    }
}

function Assert-NoReparsePoint {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing reparse point '$Path'."
    }
}

function Resolve-GuardExe {
    if ($CandidateExe) {
        if (-not (Test-Path -LiteralPath $CandidateExe -PathType Leaf)) {
            throw "CandidateExe does not exist: '$CandidateExe'."
        }
        Assert-NoReparsePoint -Path $CandidateExe
        return (Resolve-Path -LiteralPath $CandidateExe).Path
    }
    $candidates = @(
        (Join-Path $RepoRoot 'guard.exe'),
        (Join-Path $RepoRoot 'target\release\guard.exe'),
        (Join-Path $RepoRoot 'target\debug\guard.exe')
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            Assert-NoReparsePoint -Path $candidate
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    $command = Get-Command 'guard.exe' -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    throw 'guard.exe not found in the release archive, build output, or PATH.'
}

function Assert-ExpectedCandidateHash {
    if ($ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'Action install requires -ExpectedSha256 from the verified release manifest.'
    }
    return $ExpectedSha256.ToLowerInvariant()
}

function ConvertFrom-GuardVersionOutput {
    param(
        [Parameter(Mandatory)][string[]]$Text,
        [Parameter(Mandatory)][int]$NativeStatus
    )
    if ($NativeStatus -ne 0 -or ($Text -join ' ') -notmatch '^guard\s+v([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)') {
        throw 'Guard binary did not report a valid version.'
    }
    return $Matches[1]
}

function Get-GuardVersion {
    param([Parameter(Mandatory)][string]$GuardExe)
    $text = & $GuardExe --version 2>&1
    try {
        return ConvertFrom-GuardVersionOutput -Text $text -NativeStatus $LASTEXITCODE
    }
    catch {
        throw "Guard binary '$GuardExe' did not report a valid version."
    }
}

function Stage-VerifiedGuardCandidate {
    param(
        [Parameter(Mandatory)][string]$SourceExe,
        [Parameter(Mandatory)][string]$ExpectedHash
    )
    $maintenanceRootExisted = Test-Path -LiteralPath $MaintenanceRoot
    $stagedExe = Join-Path $StagingDir "guard-$([guid]::NewGuid().ToString('N')).exe"
    try {
        Set-MaintenanceAcl
        Copy-Item -LiteralPath $SourceExe -Destination $stagedExe
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $stagedExe).Hash.ToLowerInvariant() -ne $ExpectedHash.ToLowerInvariant()) {
            throw 'Staged Guard binary hash differs from the verified release manifest.'
        }
        $version = Get-GuardVersion -GuardExe $stagedExe
        return [pscustomobject]@{ Path = $stagedExe; Version = $version; Hash = $ExpectedHash.ToLowerInvariant() }
    }
    catch {
        if (Test-Path -LiteralPath $stagedExe) { Remove-Item -LiteralPath $stagedExe -Force }
        if (-not $maintenanceRootExisted -and (Test-Path -LiteralPath $MaintenanceRoot)) {
            Remove-GuardOwnedTree -Path $MaintenanceRoot
        }
        throw
    }
}

function Get-GuardSid {
    $output = & sc.exe showsid $ServiceName 2>&1
    $line = $output | Where-Object { $_ -match 'SERVICE SID\s*:\s*(S-1-5-80-\S+)' } | Select-Object -First 1
    if (-not $line) {
        throw "Could not derive the Guard service SID with 'sc.exe showsid $ServiceName'."
    }
    [void]($line -match '(S-1-5-80-\S+)')
    return $Matches[1]
}

function New-AclEntry {
    param(
        [Parameter(Mandatory)][string]$Sid,
        [Parameter(Mandatory)][Security.AccessControl.FileSystemRights]$Rights,
        [bool]$Inherit = $true
    )
    # .NET adds Synchronize to allow rules. Store that normalized value so
    # exact verification compares the ACL that Windows actually persists.
    $normalized = $Rights -bor [Security.AccessControl.FileSystemRights]::Synchronize
    return [pscustomobject]@{ Sid = $Sid; Rights = $normalized; Inherit = $Inherit }
}

function New-ExactFileSystemAcl {
    param(
        [Parameter(Mandatory)][bool]$Directory,
        [Parameter(Mandatory)][string]$OwnerSid,
        [Parameter(Mandatory)][object[]]$Entries
    )
    $acl = if ($Directory) {
        New-Object Security.AccessControl.DirectorySecurity
    }
    else {
        New-Object Security.AccessControl.FileSecurity
    }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new($OwnerSid))
    foreach ($entry in $Entries) {
        $inheritance = if ($Directory -and $entry.Inherit) {
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit
        }
        else {
            [Security.AccessControl.InheritanceFlags]::None
        }
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new([string]$entry.Sid),
            [Security.AccessControl.FileSystemRights]$entry.Rights,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    return ,$acl
}

function Assert-ExactFileSystemAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$OwnerSid,
        [Parameter(Mandatory)][object[]]$Entries
    )
    Assert-NoReparsePoint -Path $Path
    $item = Get-Item -LiteralPath $Path -Force
    $acl = Get-Acl -LiteralPath $Path
    $actualOwner = $acl.Owner
    try {
        $actualOwner = ([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        $actualOwner = ([Security.Principal.SecurityIdentifier]$acl.Owner).Value
    }
    if ($actualOwner -ne $OwnerSid) { throw "ACL owner mismatch on '$Path'." }
    if (-not $acl.AreAccessRulesProtected) { throw "ACL inheritance is enabled on '$Path'." }

    $rules = @($acl.Access)
    if ($rules.Count -ne $Entries.Count) {
        throw "ACL trustee count mismatch on '$Path'."
    }
    foreach ($entry in $Entries) {
        $matching = @($rules | Where-Object {
            $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $entry.Sid
        })
        if ($matching.Count -ne 1) { throw "ACL trustee mismatch on '$Path'." }
        $rule = $matching[0]
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            ([int64]$rule.FileSystemRights) -ne ([int64]$entry.Rights)) {
            throw "ACL rights mismatch for '$($entry.Sid)' on '$Path'."
        }
        $expectedInheritance = if ($item.PSIsContainer -and $entry.Inherit) {
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit
        }
        else {
            [Security.AccessControl.InheritanceFlags]::None
        }
        if ($rule.IsInherited -or $rule.InheritanceFlags -ne $expectedInheritance -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
            throw "ACL inheritance flags mismatch for '$($entry.Sid)' on '$Path'."
        }
    }
}

function Set-ExactFileSystemAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$OwnerSid,
        [Parameter(Mandatory)][object[]]$Entries
    )
    Assert-NoReparsePoint -Path $Path
    $directory = Test-Path -LiteralPath $Path -PathType Container
    $acl = New-ExactFileSystemAcl -Directory $directory -OwnerSid $OwnerSid -Entries $Entries
    Set-Acl -LiteralPath $Path -AclObject $acl
    Assert-ExactFileSystemAcl -Path $Path -OwnerSid $OwnerSid -Entries $Entries
}

function Test-PathWithin {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Parent
    )
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $fullParent = [IO.Path]::GetFullPath($Parent).TrimEnd('\')
    return $fullPath.Equals($fullParent, [StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith("$fullParent\", [StringComparison]::OrdinalIgnoreCase)
}

function Test-PathExcluded {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$Exclude = @()
    )
    foreach ($excludedRoot in $Exclude) {
        if (Test-PathWithin -Path $Path -Parent $excludedRoot) { return $true }
    }
    return $false
}

function Get-PrunedTreeItems {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$Exclude = @()
    )
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($Path)
    while ($pending.Count -gt 0) {
        $parent = $pending.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $parent -Force)) {
            if (Test-PathExcluded -Path $item.FullName -Exclude $Exclude) { continue }
            Assert-NoReparsePoint -Path $item.FullName
            Write-Output $item
            if ($item.PSIsContainer) { $pending.Push($item.FullName) }
        }
    }
}

function Set-ExactAclTree {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$OwnerSid,
        [Parameter(Mandatory)][object[]]$Entries,
        [string[]]$Exclude = @()
    )
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Set-ExactFileSystemAcl -Path $Path -OwnerSid $OwnerSid -Entries $Entries
    foreach ($item in Get-PrunedTreeItems -Path $Path -Exclude $Exclude) {
        Set-ExactFileSystemAcl -Path $item.FullName -OwnerSid $OwnerSid -Entries $Entries
    }
}

function Assert-ExactAclTree {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$OwnerSid,
        [Parameter(Mandatory)][object[]]$Entries,
        [string[]]$Exclude = @()
    )
    Assert-ExactFileSystemAcl -Path $Path -OwnerSid $OwnerSid -Entries $Entries
    foreach ($item in Get-PrunedTreeItems -Path $Path -Exclude $Exclude) {
        Assert-ExactFileSystemAcl -Path $item.FullName -OwnerSid $OwnerSid -Entries $Entries
    }
}

function Reset-TreeForAdministrativeMaintenance {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    if (-not ((Test-PathWithin -Path $Path -Parent $DataDir) -or
        (Test-PathWithin -Path $Path -Parent $ConfigRoot) -or
        (Test-PathWithin -Path $Path -Parent $MaintenanceRoot))) {
        throw "Refusing to reset ACLs outside a Guard-owned tree: '$Path'."
    }
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push([IO.Path]::GetFullPath($Path))
    while ($pending.Count -gt 0) {
        $current = $pending.Pop()
        Assert-NoReparsePoint -Path $current
        $item = Get-Item -LiteralPath $current -Force
        & takeown.exe /F $current /A | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not take ownership of '$current'." }
        # Non-inheriting rules avoid changing an unchecked child or junction.
        & icacls.exe $current /inheritance:r /grant:r "*${SidSystem}:(F)" "*${SidAdmins}:(F)" /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not grant administrative maintenance access to '$current'." }
        if ($item.PSIsContainer) {
            $children = @(Get-ChildItem -LiteralPath $current -Force)
            foreach ($child in $children) { Assert-NoReparsePoint -Path $child.FullName }
            for ($index = $children.Count - 1; $index -ge 0; $index--) {
                $pending.Push($children[$index].FullName)
            }
        }
    }
}

function Get-AdministrativeAclEntries {
    return @(
        (New-AclEntry -Sid $SidSystem -Rights ([Security.AccessControl.FileSystemRights]::FullControl)),
        (New-AclEntry -Sid $SidAdmins -Rights ([Security.AccessControl.FileSystemRights]::FullControl))
    )
}

function Get-ServiceReadAclEntries {
    param([Parameter(Mandatory)][string]$GuardSid)
    return @(
        (New-AclEntry -Sid $SidSystem -Rights ([Security.AccessControl.FileSystemRights]::FullControl)),
        (New-AclEntry -Sid $SidAdmins -Rights ([Security.AccessControl.FileSystemRights]::FullControl)),
        (New-AclEntry -Sid $GuardSid -Rights ([Security.AccessControl.FileSystemRights]::ReadAndExecute))
    )
}

function Get-ServiceWriteAclEntries {
    param([Parameter(Mandatory)][string]$GuardSid)
    return @(
        (New-AclEntry -Sid $SidSystem -Rights ([Security.AccessControl.FileSystemRights]::FullControl)),
        (New-AclEntry -Sid $SidAdmins -Rights ([Security.AccessControl.FileSystemRights]::FullControl)),
        (New-AclEntry -Sid $GuardSid -Rights ([Security.AccessControl.FileSystemRights]::FullControl))
    )
}

function Set-MaintenanceAcl {
    New-Item -ItemType Directory -Force -Path $MaintenanceRoot, $StagingDir, $BackupRoot, $TaskOutDir | Out-Null
    $entries = Get-AdministrativeAclEntries
    Set-ExactAclTree -Path $MaintenanceRoot -OwnerSid $SidAdmins -Entries $entries
}

function Set-DeploymentAcls {
    param([Parameter(Mandatory)][string]$GuardSid)
    New-Item -ItemType Directory -Force -Path $InstallRoot, $ConfigRoot, $DataDir, $KubeDir | Out-Null
    Set-ExactAclTree -Path $InstallRoot -OwnerSid $SidAdmins -Entries (Get-ServiceReadAclEntries -GuardSid $GuardSid)
    Set-ExactAclTree -Path $ConfigRoot -OwnerSid $SidAdmins -Entries (Get-ServiceReadAclEntries -GuardSid $GuardSid)

    $privateRoots = @(
        (Join-Path $DataDir 'secret-files'),
        (Join-Path $DataDir 'api-proxy-reverts')
    )
    Set-ExactAclTree -Path $DataDir -OwnerSid $SidAdmins -Entries (Get-ServiceWriteAclEntries -GuardSid $GuardSid) -Exclude $privateRoots
    Set-MaintenanceAcl
}

function Assert-DeploymentAcls {
    param([Parameter(Mandatory)][string]$GuardSid)
    $readEntries = Get-ServiceReadAclEntries -GuardSid $GuardSid
    $writeEntries = Get-ServiceWriteAclEntries -GuardSid $GuardSid
    $administrativeEntries = Get-AdministrativeAclEntries
    Assert-ExactAclTree -Path $InstallRoot -OwnerSid $SidAdmins -Entries $readEntries
    Assert-ExactAclTree -Path $ConfigRoot -OwnerSid $SidAdmins -Entries $readEntries
    $privateRoots = @(
        (Join-Path $DataDir 'secret-files'),
        (Join-Path $DataDir 'api-proxy-reverts')
    )
    Assert-ExactFileSystemAcl -Path $DataDir -OwnerSid $SidAdmins -Entries $writeEntries
    Assert-ExactFileSystemAcl -Path $KubeDir -OwnerSid $SidAdmins -Entries $writeEntries
    Assert-ExactAclTree -Path $MaintenanceRoot -OwnerSid $SidAdmins -Entries $administrativeEntries
    # Guard creates and validates the daemon-only private subtrees itself.
    # Administrators deliberately cannot reopen them without a maintenance
    # ownership reset, so deployment verification prunes them above.
}

function Get-ServiceRegistryPath {
    return "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
}

function Get-ServiceRegistryAclObject {
    param([Parameter(Mandatory)][string]$Path)
    $lastError = 'service registry key is not visible'
    for ($attempt = 1; $attempt -le 20; $attempt++) {
        try {
            if (Test-Path -LiteralPath $Path) { return Get-Acl -LiteralPath $Path }
        }
        catch { $lastError = $_.Exception.Message }
        if ($attempt -lt 20) { Start-Sleep -Milliseconds 100 }
    }
    throw "Service registry ACL could not be read after 20 attempts: $lastError"
}

function Set-ServiceRegistryAclObject {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$AclObject
    )
    $lastError = 'service registry ACL was not written'
    for ($attempt = 1; $attempt -le 20; $attempt++) {
        try {
            Set-Acl -LiteralPath $Path -AclObject $AclObject
            return
        }
        catch { $lastError = $_.Exception.Message }
        if ($attempt -lt 20) { Start-Sleep -Milliseconds 100 }
    }
    throw "Service registry ACL could not be written after 20 attempts: $lastError"
}

function Set-ServiceRegistryAcl {
    param([Parameter(Mandatory)][string]$GuardSid)
    $path = Get-ServiceRegistryPath
    $acl = Get-ServiceRegistryAclObject -Path $path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new($SidAdmins))
    foreach ($entry in @(
        @($SidSystem, [Security.AccessControl.RegistryRights]::FullControl),
        @($SidAdmins, [Security.AccessControl.RegistryRights]::FullControl),
        @($GuardSid, [Security.AccessControl.RegistryRights]::ReadKey)
    )) {
        $rule = [Security.AccessControl.RegistryAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new([string]$entry[0]),
            $entry[1],
            [Security.AccessControl.InheritanceFlags]::ContainerInherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    Set-ServiceRegistryAclObject -Path $path -AclObject $acl

    $verified = Get-ServiceRegistryAclObject -Path $path
    $ownerSid = try {
        ([Security.Principal.NTAccount]$verified.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        ([Security.Principal.SecurityIdentifier]$verified.Owner).Value
    }
    $rules = @($verified.Access)
    if ($ownerSid -ne $SidAdmins -or -not $verified.AreAccessRulesProtected -or $rules.Count -ne 3) {
        throw 'Service registry ACL does not have the exact protected trustee set.'
    }
    $expectedRights = @{
        $SidSystem = [Security.AccessControl.RegistryRights]::FullControl
        $SidAdmins = [Security.AccessControl.RegistryRights]::FullControl
        $GuardSid = [Security.AccessControl.RegistryRights]::ReadKey
    }
    foreach ($required in $expectedRights.Keys) {
        $matching = @($rules | Where-Object {
            $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $required -and
            $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow
        })
        if ($matching.Count -ne 1 -or
            ([int64]$matching[0].RegistryRights) -ne ([int64]$expectedRights[$required]) -or
            $matching[0].IsInherited -or
            $matching[0].InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::ContainerInherit -or
            $matching[0].PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
            throw "Service registry ACL is incorrect for trustee '$required'."
        }
    }
}

function Import-LlmEnvironment {
    param([string]$Path)
    $result = @{}
    if (-not $Path) { return $result }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-Warning "EnvFile '$Path' does not exist. Existing service values remain unchanged."
        return $result
    }
    Assert-NoReparsePoint -Path $Path
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
        if ($trimmed -match '^export\s+') { $trimmed = $trimmed -replace '^export\s+', '' }
        $separator = $trimmed.IndexOf('=')
        if ($separator -lt 1) { continue }
        $name = $trimmed.Substring(0, $separator).Trim()
        if ($LlmEnvKeys -notcontains $name) { continue }
        $value = $trimmed.Substring($separator + 1).Trim()
        if (($value.StartsWith('"') -and $value.EndsWith('"')) -or
            ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        if ($value) { $result[$name] = $value }
    }
    return $result
}

function Convert-EnvironmentObjectToMap {
    param([AllowNull()]$InputObject)
    $result = @{}
    if ($null -eq $InputObject) { return $result }
    foreach ($property in $InputObject.PSObject.Properties) {
        if ($property.Name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$' -or $result.ContainsKey($property.Name)) {
            throw 'The protected environment backup contains an invalid or duplicate name.'
        }
        $result[$property.Name] = [string]$property.Value
    }
    return $result
}

function Get-ServiceEnvironmentMap {
    $result = @{}
    $path = Get-ServiceRegistryPath
    if (-not (Test-Path -LiteralPath $path)) { return $result }
    $property = Get-ItemProperty -LiteralPath $path -Name Environment -ErrorAction SilentlyContinue
    if ($null -eq $property -or $null -eq $property.Environment) { return $result }
    foreach ($pair in [string[]]$property.Environment) {
        $separator = $pair.IndexOf('=')
        if ($separator -lt 1) { throw 'The existing service Environment value contains a malformed entry.' }
        $name = $pair.Substring(0, $separator)
        if ($name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$' -or $result.ContainsKey($name)) {
            throw 'The existing service Environment value contains an invalid or duplicate name.'
        }
        $result[$name] = $pair.Substring($separator + 1)
    }
    return $result
}

function Merge-ServiceEnvironment {
    param(
        [Parameter(Mandatory)][hashtable]$Existing,
        [Parameter(Mandatory)][hashtable]$Imported
    )
    $result = @{}
    foreach ($name in $Existing.Keys) { $result[$name] = $Existing[$name] }
    foreach ($name in $Imported.Keys) { $result[$name] = $Imported[$name] }
    $result['KUBECONFIG'] = $KubeConfig
    $childNames = @()
    if ($result.ContainsKey('GUARD_CHILD_ENV')) {
        $childNames += @(([string]$result['GUARD_CHILD_ENV'] -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    if ($childNames -notcontains 'KUBECONFIG') { $childNames += 'KUBECONFIG' }
    $result['GUARD_CHILD_ENV'] = ($childNames | Select-Object -Unique) -join ','
    return $result
}

function Set-ServiceEnvironment {
    param(
        [Parameter(Mandatory)][hashtable]$Environment,
        [Parameter(Mandatory)][string]$GuardSid
    )
    Set-ServiceRegistryAcl -GuardSid $GuardSid
    $pairs = @($Environment.Keys | Sort-Object | ForEach-Object { "$_=$($Environment[$_])" })
    New-ItemProperty -LiteralPath (Get-ServiceRegistryPath) -Name Environment -PropertyType MultiString -Value $pairs -Force | Out-Null
    Set-ServiceRegistryAcl -GuardSid $GuardSid
}

function Assert-TextArgument {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 4096 -or $Value -match '[\x00-\x1f\x7f]') {
        throw "$Name must be 1 to 4096 printable characters."
    }
}

function Assert-RequestReference {
    param([Parameter(Mandatory)][string]$Value)
    if ($Value -notmatch '^[0-9a-fA-F]{32}$') { throw "Invalid request reference '$Value'." }
}

function Assert-AccessDecisionReference {
    param([Parameter(Mandatory)][string]$Value)
    if ($Value -match '^gr-[0-9a-fA-F]{32}$') { return }
    if ($Value -match '^[0-9a-fA-F]{32}$') { return }
    throw "Invalid access decision reference '$Value'."
}

function Assert-AccessTargetReference {
    param([Parameter(Mandatory)][string]$Value)
    if ($Value -notmatch '^(?:session:[0-9a-fA-F]{16}|agent:S-1-[0-9-]{3,180})$') {
        throw "Invalid access reference '$Value'."
    }
}

function Assert-AccessInspectableReference {
    param([Parameter(Mandatory)][string]$Value)
    if ($Value -match '^(?:gr-)?[0-9a-fA-F]{32}$') { return }
    Assert-AccessTargetReference -Value $Value
}

function Assert-ReferenceCount {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Minimum,
        [Parameter(Mandatory)][int]$Maximum
    )
    if ($Reference.Count -lt $Minimum -or $Reference.Count -gt $Maximum) {
        throw "Action '$Name' accepts $Minimum to $Maximum reference values."
    }
}

function Get-GuardActionArguments {
    $arguments = [Collections.Generic.List[string]]::new()
    switch ($Action) {
        'access-approve' {
            Assert-ReferenceCount -Name $Action -Minimum 1 -Maximum 64
            foreach ($value in $Reference) { Assert-AccessDecisionReference -Value $value }
            [void]$arguments.Add('access'); [void]$arguments.Add('approve')
            foreach ($value in $Reference) { [void]$arguments.Add($value) }
            if ($ApprovalMode -eq 'once') { [void]$arguments.Add('--once') }
            elseif ($ApprovalMode -eq 'uses') {
                if ($Uses -lt 1 -or $Uses -gt 1000000) { throw 'Uses must be between 1 and 1000000.' }
                [void]$arguments.Add('--uses'); [void]$arguments.Add([string]$Uses)
            }
            elseif ($Uses -ne 0) { throw 'Uses requires ApprovalMode uses.' }
        }
        'access-deny' {
            Assert-ReferenceCount -Name $Action -Minimum 1 -Maximum 64
            foreach ($value in $Reference) { Assert-AccessDecisionReference -Value $value }
            [void]$arguments.Add('access'); [void]$arguments.Add('deny')
            foreach ($value in $Reference) { [void]$arguments.Add($value) }
            if ($Reason) { Assert-TextArgument -Name Reason -Value $Reason; [void]$arguments.Add('--reason'); [void]$arguments.Add($Reason) }
        }
        'access-extend' {
            Assert-ReferenceCount -Name $Action -Minimum 1 -Maximum 1
            Assert-AccessTargetReference -Value $Reference[0]
            Assert-TextArgument -Name Intent -Value $Intent
            [void]$arguments.Add('access'); [void]$arguments.Add('extend'); [void]$arguments.Add($Reference[0]); [void]$arguments.Add($Intent)
            if ($ApprovalMode -eq 'once') { [void]$arguments.Add('--once') }
            elseif ($ApprovalMode -eq 'uses') {
                if ($Uses -lt 1 -or $Uses -gt 1000000) { throw 'Uses must be between 1 and 1000000.' }
                [void]$arguments.Add('--uses'); [void]$arguments.Add([string]$Uses)
            }
            elseif ($Uses -ne 0) { throw 'Uses requires ApprovalMode uses.' }
        }
        'access-revoke' {
            Assert-ReferenceCount -Name $Action -Minimum 1 -Maximum 1
            foreach ($value in $Reference) { Assert-AccessTargetReference -Value $value }
            [void]$arguments.Add('access'); [void]$arguments.Add('revoke')
            foreach ($value in $Reference) { [void]$arguments.Add($value) }
        }
        'access-list' {
            Assert-ReferenceCount -Name $Action -Minimum 0 -Maximum 0
            [void]$arguments.Add('access'); [void]$arguments.Add('list')
        }
        'access-show' {
            Assert-ReferenceCount -Name $Action -Minimum 1 -Maximum 1
            Assert-AccessInspectableReference -Value $Reference[0]
            [void]$arguments.Add('access'); [void]$arguments.Add('show'); [void]$arguments.Add($Reference[0])
        }
        'confirm' {
            Assert-ReferenceCount -Name $Action -Minimum 1 -Maximum 1
            Assert-RequestReference -Value $Reference[0]
            [void]$arguments.Add('confirm'); [void]$arguments.Add($Reference[0])
        }
        'revert' {
            Assert-ReferenceCount -Name $Action -Minimum 1 -Maximum 1
            Assert-RequestReference -Value $Reference[0]
            [void]$arguments.Add('revert'); [void]$arguments.Add($Reference[0])
        }
        'provisionals' {
            Assert-ReferenceCount -Name $Action -Minimum 0 -Maximum 0
            [void]$arguments.Add('provisionals')
        }
        default { throw "Action '$Action' is not an operator RPC action." }
    }
    if ($Json -and $Action -notin @('confirm', 'revert')) { [void]$arguments.Add('--json') }
    [void]$arguments.Add('--socket'); [void]$arguments.Add($SocketName)
    return [string[]]$arguments
}

function ConvertTo-Base64Utf8 {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Value))
}

function Assert-GuardOperatorInvocation {
    param(
        [Parameter(Mandatory)][string]$GuardExe,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$OutputFile
    )
    if (-not ([IO.Path]::GetFullPath($GuardExe).Equals([IO.Path]::GetFullPath($DeployedExe), [StringComparison]::OrdinalIgnoreCase))) {
        throw 'Operator task executable must be the installed Guard binary.'
    }
    if (-not (Test-PathWithin -Path $OutputFile -Parent $TaskOutDir) -or
        [IO.Path]::GetFileName($OutputFile) -notmatch '^guard-op-[a-f0-9]{32}\.out$') {
        throw 'Operator output path is outside the protected task-output directory.'
    }
    if ($Arguments.Count -lt 3 -or $Arguments.Count -gt 140) { throw 'Operator argument count is invalid.' }
    foreach ($argument in $Arguments) {
        if ($null -eq $argument -or $argument.Length -gt 4096 -or $argument -match '[\x00-\x1f\x7f]') {
            throw 'Operator arguments contain an invalid value.'
        }
    }
}

function New-GuardOperatorPayload {
    param(
        [Parameter(Mandatory)][string]$GuardExe,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$OutputFile
    )
    Assert-GuardOperatorInvocation -GuardExe $GuardExe -Arguments $Arguments -OutputFile $OutputFile
    $encodedExe = ConvertTo-Base64Utf8 $GuardExe
    $encodedOutput = ConvertTo-Base64Utf8 $OutputFile
    $encodedArguments = @($Arguments | ForEach-Object { "'$(ConvertTo-Base64Utf8 $_)'" }) -join ','
    $script = @"
`$ErrorActionPreference = 'Stop'
function Decode([string]`$value) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(`$value)) }
`$guardExe = Decode '$encodedExe'
`$outputFile = Decode '$encodedOutput'
`$guardArguments = @($encodedArguments) | ForEach-Object { Decode `$_ }
& `$guardExe @guardArguments *> `$outputFile
exit `$LASTEXITCODE
"@
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
}

function Invoke-GuardAsOperator {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$GuardExe
    )
    Assert-Admin -ForAction $Action
    if (-not (Test-Path -LiteralPath $GuardExe -PathType Leaf)) { throw "Installed Guard binary not found at '$GuardExe'." }
    $taskName = "guard-op-$([guid]::NewGuid().ToString('N'))"
    $outputFile = Join-Path $TaskOutDir "$taskName.out"
    $payload = New-GuardOperatorPayload -GuardExe $GuardExe -Arguments $Arguments -OutputFile $outputFile
    $powerShellExe = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $taskAction = New-ScheduledTaskAction -Execute $powerShellExe -Argument "-NoLogo -NoProfile -NonInteractive -EncodedCommand $payload"
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $OperatorAccount -LogonType ServiceAccount -RunLevel Highest
    $taskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds $OperatorTaskTimeoutSeconds)
    $registered = $false
    $nativeStatus = $null
    $output = $null
    try {
        Register-ScheduledTask -TaskName $taskName -Action $taskAction -Principal $taskPrincipal -Settings $taskSettings | Out-Null
        $registered = $true
        $before = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\'
        Start-ScheduledTask -TaskName $taskName -TaskPath '\'
        $deadline = (Get-Date).AddSeconds($OperatorTaskTimeoutSeconds)
        do {
            Start-Sleep -Milliseconds 400
            $task = Get-ScheduledTask -TaskName $taskName -TaskPath '\'
            $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\'
            $triggered = $taskInfo.LastRunTime -gt $before.LastRunTime
            $active = $task.State -in @('Running', 'Queued')
        } while ((-not $triggered -or $active) -and (Get-Date) -lt $deadline)
        $nativeStatus = $taskInfo.LastTaskResult
        if (Test-Path -LiteralPath $outputFile) {
            $output = Get-Content -LiteralPath $outputFile -Raw
        }
        if (-not $triggered -or $active) {
            $diagnostic = if ($null -eq $output) { '' } else { ConvertTo-SanitizedDiagnosticOutput -Value $output }
            throw "Guard operator task timed out; native_status=$nativeStatus; output=$diagnostic"
        }
        return Resolve-GuardOperatorResult -RawOutput $output -NativeStatus $nativeStatus -JsonOutput:$Json
    }
    finally {
        $diagnostic = if ($null -eq $output) { $null } else { ConvertTo-SanitizedDiagnosticOutput -Value $output }
        Remove-GuardOperatorArtifacts -TaskName $taskName -OutputFile $outputFile -PreserveOutput:$PreserveDiagnostics -DiagnosticOutput $diagnostic
        if ($PreserveDiagnostics -and $null -ne $output) {
            Write-Warning "Preserved sanitized diagnostic output '$outputFile'; the SYSTEM task was removed."
        }
    }
}

function Resolve-GuardOperatorResult {
    param(
        [AllowNull()][string]$RawOutput,
        [Parameter(Mandatory)][int64]$NativeStatus,
        [switch]$JsonOutput
    )
    if ($null -eq $RawOutput) {
        throw "Guard operator task produced no output; native_status=$NativeStatus"
    }
    if ($JsonOutput) {
        try { $null = $RawOutput | ConvertFrom-Json -ErrorAction Stop }
        catch { throw "Guard operator task produced invalid JSON; native_status=$NativeStatus" }
        return [pscustomobject]@{ Output = $RawOutput; ExitCode = [int]$NativeStatus }
    }
    $diagnostic = ConvertTo-SanitizedDiagnosticOutput -Value $RawOutput
    if ($NativeStatus -ne 0) {
        throw "Guard operator command failed; native_status=$NativeStatus; output=$diagnostic"
    }
    return [pscustomobject]@{ Output = $diagnostic; ExitCode = 0 }
}

function ConvertTo-SanitizedDiagnosticOutput {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    $sanitized = $Value -replace '(?i)\b(token|secret|password|api[_-]?key)\s*[:=]\s*\S+', '$1=[redacted]'
    $sanitized = $sanitized -replace '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '?'
    if ($sanitized.Length -gt 16384) {
        $marker = "`n[output truncated]"
        $sanitized = $sanitized.Substring(0, 16384 - $marker.Length) + $marker
    }
    return $sanitized
}

function Remove-GuardOperatorArtifacts {
    param(
        [Parameter(Mandatory)][string]$TaskName,
        [Parameter(Mandatory)][string]$OutputFile,
        [switch]$PreserveOutput,
        [AllowNull()][string]$DiagnosticOutput
    )
    if ($TaskName -notmatch '^guard-op-[a-f0-9]{32}$' -or
        -not (Test-PathWithin -Path $OutputFile -Parent $TaskOutDir)) {
        throw 'Refusing to clean operator artifacts outside the validated maintenance paths.'
    }
    $lastError = $null
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $task = @(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop | Where-Object TaskName -eq $TaskName) | Select-Object -First 1
            if ($task) {
                if ($task.State -in @('Running', 'Queued')) {
                    Stop-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction Stop
                }
                Unregister-ScheduledTask -TaskName $TaskName -TaskPath '\' -Confirm:$false -ErrorAction Stop
            }
            if ($PreserveOutput -and $null -ne $DiagnosticOutput) {
                $sanitized = ConvertTo-SanitizedDiagnosticOutput -Value $DiagnosticOutput
                [IO.File]::WriteAllText($OutputFile, $sanitized, [Text.UTF8Encoding]::new($false))
            }
            elseif (Test-Path -LiteralPath $OutputFile) {
                Remove-Item -LiteralPath $OutputFile -Force -ErrorAction Stop
            }
            $taskRemaining = @(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop | Where-Object TaskName -eq $TaskName) | Select-Object -First 1
            $outputComplete = if ($PreserveOutput -and $null -ne $DiagnosticOutput) {
                Test-Path -LiteralPath $OutputFile -PathType Leaf
            }
            else { -not (Test-Path -LiteralPath $OutputFile) }
            if (-not $taskRemaining -and $outputComplete) { return }
            $lastError = 'task or output still exists after cleanup'
        }
        catch { $lastError = $_.Exception.Message }
        if ($attempt -lt 3) { Start-Sleep -Milliseconds 200 }
    }
    throw "Guard operator cleanup failed after 3 attempts: $lastError"
}

function Wait-ServiceStopped {
    param([Parameter(Mandatory)][string]$Name)
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $service) { return }
    if ($service.Status -ne 'Stopped') { Stop-Service -Name $Name }
    $service.WaitForStatus('Stopped', (New-TimeSpan -Seconds 30))
}

function Assert-ServicePathName {
    param([Parameter(Mandatory)][string]$PathName)
    if ([string]::IsNullOrWhiteSpace($PathName) -or $PathName -match '[\x00-\x1f\x7f]') {
        throw 'The Guard service command line contains an invalid character.'
    }
    $expectedToken = '"' + $DeployedExe + '"'
    if (-not $PathName.StartsWith($expectedToken, [StringComparison]::OrdinalIgnoreCase) -or
        ($PathName.Length -gt $expectedToken.Length -and -not [char]::IsWhiteSpace($PathName[$expectedToken.Length]))) {
        throw "Existing service '$ServiceName' does not use the exact installed executable token '$expectedToken'."
    }
    return $PathName
}

function Get-ServiceSnapshot {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) { return $null }
    $config = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if ($config.StartName -ne $ServiceAccount) {
        throw "Existing service '$ServiceName' uses account '$($config.StartName)'; refusing to replace it."
    }
    $servicePathName = Assert-ServicePathName -PathName ([string]$config.PathName)
    if (-not (Test-Path -LiteralPath $DeployedExe -PathType Leaf)) {
        throw "Existing service '$ServiceName' has no installed binary at '$DeployedExe'."
    }
    return [pscustomobject]@{
        WasRunning = $service.Status -eq 'Running'
        StartMode = [string]$config.StartMode
        PathName = $servicePathName
        Environment = Get-ServiceEnvironmentMap
        CatalogPresent = Test-Path -LiteralPath $VerbsPath -PathType Leaf
        BinaryVersion = Get-GuardVersion -GuardExe $DeployedExe
        BinaryHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $DeployedExe).Hash
    }
}

function Get-DatabasePaths {
    param([Parameter(Mandatory)][string]$Database)
    return @($Database, "$Database-wal", "$Database-shm", "$Database-journal")
}

function Protect-LocalMachineText {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Path
    )
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    $protected = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    [IO.File]::WriteAllBytes($Path, $protected)
}

function Unprotect-LocalMachineText {
    param([Parameter(Mandatory)][string]$Path)
    $protected = [IO.File]::ReadAllBytes($Path)
    $bytes = [Security.Cryptography.ProtectedData]::Unprotect($protected, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    return [Text.Encoding]::UTF8.GetString($bytes)
}

function Copy-BackupFile {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$BackupPath,
        [Parameter(Mandatory)][string]$RelativePath
    )
    $destination = Join-Path $BackupPath ($RelativePath -replace '/', '\')
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
    Copy-Item -LiteralPath $Source -Destination $destination
    return [ordered]@{
        path = $RelativePath
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash.ToLowerInvariant()
        length = (Get-Item -LiteralPath $destination).Length
    }
}

function Get-ApiRevertRoot {
    return (Join-Path $DataDir 'api-proxy-reverts')
}

function Protect-PrivateServiceTree {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$GuardSid
    )
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $privateEntries = @((New-AclEntry -Sid $GuardSid -Rights ([Security.AccessControl.FileSystemRights]::FullControl)))
    $items = @(Get-PrunedTreeItems -Path $Path | Sort-Object { $_.FullName.Length } -Descending)
    foreach ($item in $items) {
        $acl = New-ExactFileSystemAcl -Directory $item.PSIsContainer -OwnerSid $GuardSid -Entries $privateEntries
        Set-Acl -LiteralPath $item.FullName -AclObject $acl
    }
    $rootAcl = New-ExactFileSystemAcl -Directory $true -OwnerSid $GuardSid -Entries $privateEntries
    Set-Acl -LiteralPath $Path -AclObject $rootAcl
}

function Copy-ApiRevertBackup {
    param(
        [Parameter(Mandatory)][string]$BackupPath,
        [Parameter(Mandatory)][string]$GuardSid
    )
    $sourceRoot = Get-ApiRevertRoot
    if (-not (Test-Path -LiteralPath $sourceRoot -PathType Container)) { return @() }
    Reset-TreeForAdministrativeMaintenance -Path $sourceRoot
    try {
        $result = @()
        $prefixLength = [IO.Path]::GetFullPath($sourceRoot).TrimEnd('\').Length + 1
        foreach ($item in Get-PrunedTreeItems -Path $sourceRoot) {
            Assert-NoReparsePoint -Path $item.FullName
            if ($item.PSIsContainer) { continue }
            $relative = [IO.Path]::GetFullPath($item.FullName).Substring($prefixLength).Replace('\', '/')
            if ($relative -notmatch '^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$') {
                throw "API revert snapshot contains an unsafe relative path '$relative'."
            }
            $result += Copy-BackupFile -Source $item.FullName -BackupPath $BackupPath -RelativePath "api-proxy-reverts/$relative"
        }
        return $result
    }
    finally {
        Protect-PrivateServiceTree -Path $sourceRoot -GuardSid $GuardSid
    }
}

function New-GuardBackup {
    param(
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][string]$BeforeVersion,
        [Parameter(Mandatory)][string]$GuardSid
    )
    if ($BeforeVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') { throw 'Backup version is invalid.' }
    $name = "before-v$BeforeVersion-$(Get-Date -Format 'yyyyMMddTHHmmssZ')-$([guid]::NewGuid().ToString('N'))"
    $path = Join-Path $BackupRoot $name
    New-Item -ItemType Directory -Path $path | Out-Null
    $files = @()
    $files += Copy-BackupFile -Source $DeployedExe -BackupPath $path -RelativePath 'guard.exe'
    if ($Snapshot.CatalogPresent) {
        $files += Copy-BackupFile -Source $VerbsPath -BackupPath $path -RelativePath 'config/verbs.yaml'
    }
    foreach ($databaseFile in Get-DatabasePaths -Database $StateDb) {
        if (Test-Path -LiteralPath $databaseFile -PathType Leaf) {
            $files += Copy-BackupFile -Source $databaseFile -BackupPath $path -RelativePath "sqlite/$([IO.Path]::GetFileName($databaseFile))"
        }
    }
    $apiRevertsPresent = Test-Path -LiteralPath (Get-ApiRevertRoot) -PathType Container
    if ($apiRevertsPresent) {
        $files += Copy-ApiRevertBackup -BackupPath $path -GuardSid $GuardSid
    }
    if (-not (Test-Path -LiteralPath (Join-Path $path 'sqlite\state.db') -PathType Leaf)) {
        throw 'The quiesced Guard state database is missing; refusing to create an incomplete rollback backup.'
    }
    $environmentPath = Join-Path $path 'service-environment.dpapi'
    Protect-LocalMachineText -Value ($Snapshot.Environment | ConvertTo-Json -Compress) -Path $environmentPath
    $files += [ordered]@{
        path = 'service-environment.dpapi'
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $environmentPath).Hash.ToLowerInvariant()
        length = (Get-Item -LiteralPath $environmentPath).Length
    }
    $metadata = [ordered]@{
        format = 'guard-windows-backup'
        metadata_schema = $BackupMetadataSchema
        service_name = $ServiceName
        service_account = $ServiceAccount
        installed_path = $DeployedExe
        state_database = $StateDb
        catalog_path = $VerbsPath
        binary_version = $Snapshot.BinaryVersion
        binary_sha256 = $Snapshot.BinaryHash.ToLowerInvariant()
        catalog_present = [bool]$Snapshot.CatalogPresent
        start_mode = $Snapshot.StartMode
        was_running = [bool]$Snapshot.WasRunning
        service_path_name = $Snapshot.PathName
        api_reverts_present = [bool]$apiRevertsPresent
        files = $files
    }
    $json = $metadata | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText((Join-Path $path 'metadata.json'), $json, [Text.UTF8Encoding]::new($false))
    Set-MaintenanceAcl
    return $name
}

function Resolve-BackupPath {
    param([Parameter(Mandatory)][string]$Name)
    if ($Name -notmatch '^before-v[0-9]+\.[0-9]+\.[0-9]+-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{32}$') {
        throw 'Backup must be a release-version backup name printed by the installer.'
    }
    $path = Join-Path $BackupRoot $Name
    if (-not (Test-Path -LiteralPath $path -PathType Container)) { throw "Backup '$Name' does not exist." }
    if (-not (Test-PathWithin -Path $path -Parent $BackupRoot)) { throw 'Backup path escapes the maintenance root.' }
    Assert-NoReparsePoint -Path $path
    return (Resolve-Path -LiteralPath $path).Path
}

function Read-ValidatedGuardBackup {
    param([Parameter(Mandatory)][string]$Name)
    $path = Resolve-BackupPath -Name $Name
    $metadataPath = Join-Path $path 'metadata.json'
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) { throw 'Backup metadata is missing.' }
    Assert-NoReparsePoint -Path $metadataPath
    try { $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json }
    catch { throw 'Backup metadata is not valid JSON.' }
    if ($metadata.format -ne 'guard-windows-backup' -or
        $metadata.metadata_schema -ne $BackupMetadataSchema -or
        $metadata.service_name -ne $ServiceName -or
        $metadata.service_account -ne $ServiceAccount -or
        $metadata.installed_path -ne $DeployedExe -or
        $metadata.state_database -ne $StateDb -or
        $metadata.catalog_path -ne $VerbsPath -or
        $metadata.binary_version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or
        $metadata.binary_sha256 -notmatch '^[0-9a-f]{64}$' -or
        $metadata.start_mode -notin @('Auto', 'Manual', 'Disabled')) {
        throw 'Backup metadata does not match this Guard installation.'
    }
    [void](Assert-ServicePathName -PathName ([string]$metadata.service_path_name))
    if ($metadata.api_reverts_present -isnot [bool]) {
        throw 'Backup API revert metadata is invalid.'
    }
    $allowedFiles = @(
        'guard.exe', 'config/verbs.yaml', 'service-environment.dpapi',
        'sqlite/state.db', 'sqlite/state.db-wal', 'sqlite/state.db-shm', 'sqlite/state.db-journal'
    )
    $seen = @{}
    foreach ($file in @($metadata.files)) {
        $relativePath = [string]$file.path
        $apiRevertFile = $relativePath -match '^api-proxy-reverts/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$'
        if (($relativePath -notin $allowedFiles -and -not $apiRevertFile) -or $seen.ContainsKey($relativePath) -or
            $file.sha256 -notmatch '^[0-9a-f]{64}$' -or [int64]$file.length -lt 0) {
            throw 'Backup file metadata contains an invalid entry.'
        }
        $seen[$relativePath] = $true
        $filePath = Join-Path $path ($relativePath -replace '/', '\')
        if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) { throw "Backup file '$($file.path)' is missing." }
        Assert-NoReparsePoint -Path $filePath
        if ((Get-Item -LiteralPath $filePath).Length -ne [int64]$file.length -or
            (Get-FileHash -Algorithm SHA256 -LiteralPath $filePath).Hash.ToLowerInvariant() -ne $file.sha256) {
            throw "Backup file '$($file.path)' failed integrity validation."
        }
    }
    foreach ($required in @('guard.exe', 'service-environment.dpapi', 'sqlite/state.db')) {
        if (-not $seen.ContainsKey($required)) { throw "Backup is missing required file '$required'." }
    }
    if ([bool]$metadata.catalog_present -ne $seen.ContainsKey('config/verbs.yaml')) {
        throw 'Backup catalog metadata is inconsistent.'
    }
    if ($metadata.binary_sha256 -ne (@($metadata.files | Where-Object path -eq 'guard.exe')[0].sha256)) {
        throw 'Backup binary metadata is inconsistent.'
    }
    $apiRevertEntries = @($metadata.files | Where-Object path -like 'api-proxy-reverts/*')
    if (-not [bool]$metadata.api_reverts_present -and $apiRevertEntries.Count -ne 0) {
        throw 'Backup API revert presence metadata is inconsistent.'
    }
    $knownFiles = @('metadata.json') + @($metadata.files | ForEach-Object { [string]$_.path })
    foreach ($actual in Get-PrunedTreeItems -Path $path) {
        if ($actual.PSIsContainer) { continue }
        $prefixLength = [IO.Path]::GetFullPath($path).TrimEnd('\').Length + 1
        $actualRelative = [IO.Path]::GetFullPath($actual.FullName).Substring($prefixLength).Replace('\', '/')
        if ($actualRelative -notin $knownFiles) { throw "Backup contains untracked file '$actualRelative'." }
    }
    $environmentText = Unprotect-LocalMachineText -Path (Join-Path $path 'service-environment.dpapi')
    try { $environment = Convert-EnvironmentObjectToMap -InputObject ($environmentText | ConvertFrom-Json) }
    catch { throw 'Protected service environment backup is invalid.' }
    return [pscustomobject]@{ Name = $Name; Path = $path; Metadata = $metadata; Environment = $environment }
}

function Convert-StartModeForSc {
    param([Parameter(Mandatory)][string]$StartMode)
    switch ($StartMode) {
        'Auto' { return 'auto' }
        'Manual' { return 'demand' }
        'Disabled' { return 'disabled' }
        default { throw "Unsupported service start mode '$StartMode'." }
    }
}

function Install-FileAtomically {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$ExpectedHash
    )
    $staged = Join-Path $StagingDir "restore-$([guid]::NewGuid().ToString('N')).tmp"
    Copy-Item -LiteralPath $Source -Destination $staged
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $staged).Hash.ToLowerInvariant() -ne $ExpectedHash.ToLowerInvariant()) {
        Remove-Item -LiteralPath $staged -Force
        throw "Staged file for '$Destination' failed integrity validation."
    }
    if (Test-Path -LiteralPath $Destination) { [IO.File]::Replace($staged, $Destination, $null) }
    else { Move-Item -LiteralPath $staged -Destination $Destination }
}

function Get-ServiceBinPath {
    param(
        [Parameter(Mandatory)][bool]$HaveKey,
        [Parameter(Mandatory)][bool]$HaveVerbs
    )
    $arguments = @('server', 'start', '--socket', $SocketName, '--gate', 'consequence', '--state-db', $StateDb, '--service')
    if ($HaveVerbs) { $arguments += @('--verbs', $VerbsPath) }
    if (-not $HaveKey) { $arguments += '--no-llm' }
    foreach ($value in @($DeployedExe) + $arguments) {
        if ($value -match '["\r\n]') { throw 'Installer-controlled service arguments contain an invalid character.' }
    }
    return (@('"' + $DeployedExe + '"') + @($arguments | ForEach-Object { '"' + $_ + '"' })) -join ' '
}

function Test-InstallerManagedServicePath {
    param([Parameter(Mandatory)][string]$PathName)
    foreach ($keyState in @($false, $true)) {
        foreach ($verbState in @($false, $true)) {
            if ($PathName -eq (Get-ServiceBinPath -HaveKey $keyState -HaveVerbs $verbState)) {
                return $true
            }
        }
    }
    return $false
}

function Resolve-InstallServicePath {
    param(
        [AllowNull()][string]$ExistingPath,
        [Parameter(Mandatory)][string]$DesiredPath
    )
    if (-not $ExistingPath -or (Test-InstallerManagedServicePath -PathName $ExistingPath)) {
        return $DesiredPath
    }
    return $ExistingPath
}

function Verify-GuardService {
    param(
        [Parameter(Mandatory)][string]$ExpectedHash,
        [Parameter(Mandatory)][string]$ExpectedVersion
    )
    $deadline = (Get-Date).AddSeconds($ServiceReadinessTimeoutSeconds)
    $statusDocument = $null
    do {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
            $statusText = & $DeployedExe status --socket $SocketName --json 2>$null
            if ($LASTEXITCODE -eq 0) {
                try { $statusDocument = ($statusText -join [Environment]::NewLine) | ConvertFrom-Json }
                catch { $statusDocument = $null }
            }
        }
        if (-not $statusDocument) { Start-Sleep -Milliseconds 400 }
    } while (-not $statusDocument -and (Get-Date) -lt $deadline)
    if (-not $statusDocument) { throw 'Guard did not complete a status handshake before the readiness deadline.' }
    if ($statusDocument.type -ne 'status' -or $statusDocument.server.version_mismatch -or
        $statusDocument.client.version -ne $statusDocument.server.version -or
        $statusDocument.server.version -ne $ExpectedVersion) {
        throw 'Guard status returned an unexpected client/server version document.'
    }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $DeployedExe).Hash.ToLowerInvariant() -ne $ExpectedHash.ToLowerInvariant()) {
        throw 'Installed binary hash differs from the expected release.'
    }
    $serviceConfig = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if (-not $serviceConfig.ProcessId) { throw 'The running Guard service has no process identifier.' }
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($serviceConfig.ProcessId)"
    if (-not $process -or -not [IO.Path]::GetFullPath($process.ExecutablePath).Equals([IO.Path]::GetFullPath($DeployedExe), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The running service process does not use the installed Guard binary.'
    }
}

function Invoke-InstallerTestFault {
    param([Parameter(Mandatory)][string]$Point)
    if ($env:GUARD_INSTALLER_TEST_FAULT -eq $Point) {
        if ($env:GITHUB_ACTIONS -ne 'true' -and $env:GUARD_INSTALLER_TEST_MODE -ne '1') {
            throw 'Installer fault injection is restricted to tests.'
        }
        throw "Injected installer fault at $Point."
    }
}

function Restore-ApiRevertBackup {
    param(
        [Parameter(Mandatory)]$BackupRecord,
        [Parameter(Mandatory)][string]$GuardSid
    )
    $destinationRoot = Get-ApiRevertRoot
    if (Test-Path -LiteralPath $destinationRoot) {
        Reset-TreeForAdministrativeMaintenance -Path $destinationRoot
        Remove-Item -LiteralPath $destinationRoot -Recurse -Force
    }
    if (-not [bool]$BackupRecord.Metadata.api_reverts_present) { return }
    New-Item -ItemType Directory -Path $destinationRoot | Out-Null
    try {
        foreach ($entry in @($BackupRecord.Metadata.files | Where-Object path -like 'api-proxy-reverts/*')) {
            $relative = ([string]$entry.path).Substring('api-proxy-reverts/'.Length)
            $destination = Join-Path $destinationRoot ($relative -replace '/', '\')
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
            Install-FileAtomically -Source (Join-Path $BackupRecord.Path ([string]$entry.path -replace '/', '\')) -Destination $destination -ExpectedHash $entry.sha256
        }
    }
    finally {
        Protect-PrivateServiceTree -Path $destinationRoot -GuardSid $GuardSid
    }
}

function Set-GuardServiceConfiguration {
    param(
        [Parameter(Mandatory)][string]$PathName,
        [Parameter(Mandatory)][string]$StartMode
    )
    [void](Assert-ServicePathName -PathName $PathName)
    $scStartMode = Convert-StartModeForSc -StartMode $StartMode
    & sc.exe config $ServiceName binPath= $PathName start= $scStartMode obj= $ServiceAccount | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not update the Guard service configuration.' }
}

function Complete-RestoredServiceVerification {
    param(
        [Parameter(Mandatory)]$Metadata,
        [Parameter(Mandatory)][hashtable]$Environment,
        [Parameter(Mandatory)][string]$GuardSid
    )
    Set-GuardServiceConfiguration -PathName ([string]$Metadata.service_path_name) -StartMode 'Manual'
    Set-ServiceEnvironment -Environment $Environment -GuardSid $GuardSid
    Set-DeploymentAcls -GuardSid $GuardSid
    Start-Service -Name $ServiceName
    Verify-GuardService -ExpectedHash $Metadata.binary_sha256 -ExpectedVersion $Metadata.binary_version
    Assert-DeploymentAcls -GuardSid $GuardSid
    if (-not [bool]$Metadata.was_running) { Wait-ServiceStopped -Name $ServiceName }
    Set-GuardServiceConfiguration -PathName ([string]$Metadata.service_path_name) -StartMode ([string]$Metadata.start_mode)
}

function Restore-GuardInstallation {
    param(
        [Parameter(Mandatory)]$BackupRecord,
        [Parameter(Mandatory)][string]$GuardSid
    )
    Wait-ServiceStopped -Name $ServiceName
    $metadata = $BackupRecord.Metadata
    $binarySource = Join-Path $BackupRecord.Path 'guard.exe'
    Install-FileAtomically -Source $binarySource -Destination $DeployedExe -ExpectedHash $metadata.binary_sha256

    foreach ($databaseFile in Get-DatabasePaths -Database $StateDb) {
        if (Test-Path -LiteralPath $databaseFile) { Remove-Item -LiteralPath $databaseFile -Force }
    }
    foreach ($name in @('state.db', 'state.db-wal', 'state.db-shm', 'state.db-journal')) {
        $relative = "sqlite/$name"
        $entry = @($metadata.files | Where-Object path -eq $relative)
        if ($entry.Count -eq 1) {
            Install-FileAtomically -Source (Join-Path $BackupRecord.Path "sqlite\$name") -Destination (Join-Path $DataDir $name) -ExpectedHash $entry[0].sha256
        }
    }
    Restore-ApiRevertBackup -BackupRecord $BackupRecord -GuardSid $GuardSid
    if ([bool]$metadata.catalog_present) {
        $catalogEntry = @($metadata.files | Where-Object path -eq 'config/verbs.yaml')[0]
        Install-FileAtomically -Source (Join-Path $BackupRecord.Path 'config\verbs.yaml') -Destination $VerbsPath -ExpectedHash $catalogEntry.sha256
    }
    elseif (Test-Path -LiteralPath $VerbsPath) {
        Remove-Item -LiteralPath $VerbsPath -Force
    }

    # Verification needs a startable service even when the durable target mode
    # is Disabled. The final transition restores the exact durable mode.
    Complete-RestoredServiceVerification -Metadata $metadata -Environment $BackupRecord.Environment -GuardSid $GuardSid
}

function Assert-NewInstallationRootsAbsent {
    foreach ($path in @($InstallRoot, $ConfigRoot, $DataDir, $MaintenanceRoot)) {
        if (Test-Path -LiteralPath $path) {
            throw "Guard service is absent but deployment state exists at '$path'; recover or remove the complete deployment before installation."
        }
    }
}

function Invoke-Install {
    Assert-Admin -ForAction 'install'
    $sourceExe = Resolve-GuardExe
    $expectedHash = Assert-ExpectedCandidateHash
    $serviceBeforeInstall = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $serviceBeforeInstall) { Assert-NewInstallationRootsAbsent }
    $candidate = Stage-VerifiedGuardCandidate -SourceExe $sourceExe -ExpectedHash $expectedHash
    $stagedExe = $candidate.Path
    $expectedVersion = $candidate.Version

    try {
        $snapshot = Get-ServiceSnapshot
        if (-not $snapshot -and (Test-Path -LiteralPath $DeployedExe)) {
            throw "Installed binary '$DeployedExe' exists without the Guard service; remove or recover it before installation."
        }
        $existingEnvironment = if ($snapshot) { $snapshot.Environment } else { @{} }
        $serviceEnvironment = Merge-ServiceEnvironment -Existing $existingEnvironment -Imported (Import-LlmEnvironment -Path $EnvFile)
        $haveKey = $serviceEnvironment.ContainsKey('GUARD_LLM_API_KEY') -or $serviceEnvironment.ContainsKey('OPENROUTER_API_KEY')
        $sourceVerbs = Join-Path $RepoRoot 'examples\verbs-kubectl.yaml'
        $haveVerbs = (Test-Path -LiteralPath $VerbsPath) -or (Test-Path -LiteralPath $sourceVerbs)
        $stockBinPath = Get-ServiceBinPath -HaveKey $haveKey -HaveVerbs $haveVerbs
        $existingPath = if ($snapshot) { $snapshot.PathName } else { $null }
        $serviceBinPath = Resolve-InstallServicePath -ExistingPath $existingPath -DesiredPath $stockBinPath
    }
    catch {
        if (Test-Path -LiteralPath $stagedExe) { Remove-Item -LiteralPath $stagedExe -Force }
        throw
    }
    $createdService = $false
    $backupName = $null
    $guardSid = $null
    try {
        if (-not $snapshot) {
            & sc.exe create $ServiceName binPath= $stockBinPath start= auto obj= $ServiceAccount DisplayName= 'Guard consequence gate' | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not create the Guard service.' }
            $createdService = $true
            & sc.exe sidtype $ServiceName unrestricted | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not enable the Guard service SID.' }
        }
        $guardSid = Get-GuardSid
        if ($snapshot) {
            Wait-ServiceStopped -Name $ServiceName
        }
        Set-DeploymentAcls -GuardSid $guardSid
        Set-ServiceRegistryAcl -GuardSid $guardSid
        if ($snapshot) {
            $backupName = New-GuardBackup -Snapshot $snapshot -BeforeVersion $expectedVersion -GuardSid $guardSid
            Set-GuardServiceConfiguration -PathName $serviceBinPath -StartMode 'Manual'
        }
        Install-FileAtomically -Source $stagedExe -Destination $DeployedExe -ExpectedHash $expectedHash
        Invoke-InstallerTestFault -Point 'after-binary'
        if (-not (Test-Path -LiteralPath $VerbsPath) -and (Test-Path -LiteralPath $sourceVerbs)) {
            Copy-Item -LiteralPath $sourceVerbs -Destination $VerbsPath
        }
        Set-DeploymentAcls -GuardSid $guardSid
        Set-ServiceEnvironment -Environment $serviceEnvironment -GuardSid $guardSid
        Invoke-InstallerTestFault -Point 'after-environment'
        if ($createdService) {
            & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not configure Guard service failure recovery.' }
        }
        Start-Service -Name $ServiceName
        Invoke-InstallerTestFault -Point 'after-service-start'
        Verify-GuardService -ExpectedHash $expectedHash -ExpectedVersion $expectedVersion
        Assert-DeploymentAcls -GuardSid $guardSid
        if ($snapshot) {
            if (-not $snapshot.WasRunning) { Wait-ServiceStopped -Name $ServiceName }
            Set-GuardServiceConfiguration -PathName $serviceBinPath -StartMode $snapshot.StartMode
        }
        $finalState = (Get-Service -Name $ServiceName).Status
        Write-Host "Guard $expectedVersion completed a status handshake from $DeployedExe; service state is $finalState."
        if ($backupName) {
            Write-Host "Rollback backup: $backupName"
            Write-Host ".\install-guard.ps1 -Action rollback -Backup $backupName"
        }
        if ($haveKey) { Write-Host 'The protected service environment retains an evaluator key; values are not displayed.' }
        else { Write-Host 'No evaluator key is configured; Guard runs with --no-llm.' }
    }
    catch {
        $installError = $_
        try {
            if ($snapshot -and $backupName) {
                Restore-GuardInstallation -BackupRecord (Read-ValidatedGuardBackup -Name $backupName) -GuardSid $guardSid
            }
            elseif ($snapshot -and $snapshot.WasRunning) {
                $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                if ($service -and $service.Status -ne 'Running') { Start-Service -Name $ServiceName }
            }
            elseif ($createdService) {
                Wait-ServiceStopped -Name $ServiceName
                & sc.exe delete $ServiceName | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'Could not remove the failed Guard service.' }
                if (Test-Path -LiteralPath $InstallRoot) {
                    Remove-Item -LiteralPath $InstallRoot -Recurse -Force
                }
                foreach ($path in @($DataDir, $ConfigRoot, $MaintenanceRoot)) {
                    Remove-GuardOwnedTree -Path $path
                }
            }
        }
        catch {
            throw "Installation failed: $($installError.Exception.Message) Automatic rollback also failed: $($_.Exception.Message)"
        }
        throw "Installation failed and the prior service state was restored: $($installError.Exception.Message)"
    }
    finally {
        if (Test-Path -LiteralPath $stagedExe) { Remove-Item -LiteralPath $stagedExe -Force }
    }
}

function Invoke-Rollback {
    Assert-Admin -ForAction 'rollback'
    if (-not $Backup) { throw 'Action rollback requires -Backup <backup-name>.' }
    $target = Read-ValidatedGuardBackup -Name $Backup
    $snapshot = Get-ServiceSnapshot
    if (-not $snapshot) { throw 'Guard is not installed.' }
    $guardSid = Get-GuardSid
    Wait-ServiceStopped -Name $ServiceName
    $safetyName = New-GuardBackup -Snapshot $snapshot -BeforeVersion $target.Metadata.binary_version -GuardSid $guardSid
    try {
        Restore-GuardInstallation -BackupRecord $target -GuardSid $guardSid
        Write-Host "Guard rollback to $($target.Metadata.binary_version) completed and passed the status handshake."
        Write-Host "Rollback safety backup: $safetyName"
    }
    catch {
        $rollbackError = $_
        try {
            Restore-GuardInstallation -BackupRecord (Read-ValidatedGuardBackup -Name $safetyName) -GuardSid $guardSid
        }
        catch {
            throw "Rollback failed: $($rollbackError.Exception.Message) Safety restoration also failed: $($_.Exception.Message)"
        }
        throw "Rollback failed and the pre-rollback installation was restored: $($rollbackError.Exception.Message)"
    }
}

function Remove-GuardOwnedTree {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Reset-TreeForAdministrativeMaintenance -Path $Path
    Remove-Item -LiteralPath $Path -Recurse -Force
    if (Test-Path -LiteralPath $Path) { throw "Guard-owned tree still exists after purge: '$Path'." }
}

function Invoke-Uninstall {
    Assert-Admin -ForAction 'uninstall'
    Wait-ServiceStopped -Name $ServiceName
    & sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning "Service deletion returned exit $LASTEXITCODE." }
    if (Test-Path -LiteralPath $InstallRoot) { Remove-Item -LiteralPath $InstallRoot -Recurse -Force }
    if ($Purge) {
        foreach ($path in @($DataDir, $ConfigRoot, $MaintenanceRoot)) {
            Remove-GuardOwnedTree -Path $path
        }
        Write-Host 'Guard state, credentials, configuration, and backups were permanently removed.'
    }
    else {
        Write-Host "State remains at $DataDir; configuration remains at $ConfigRoot; backups remain at $BackupRoot."
    }
}

function Invoke-Status {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) { Write-Host 'Guard service is not installed.'; return }
    Write-Host "Service: $($service.Status)"
    Write-Host "Pipe: $PipePath"
    if ($service.Status -eq 'Running' -and (Test-Path -LiteralPath $DeployedExe)) {
        & $DeployedExe status --socket $SocketName
    }
}

function Invoke-OperatorAction {
    $result = Invoke-GuardAsOperator -Arguments (Get-GuardActionArguments) -GuardExe $DeployedExe
    if ($Json) {
        Write-Output $result.Output
        if ($result.ExitCode -ne 0) { exit $result.ExitCode }
    }
    elseif ($result.Output) { Write-Host $result.Output }
}

if (-not $env:GUARD_INSTALLER_TEST_MODE) {
    switch ($Action) {
        'install' { Invoke-Install }
        'uninstall' { Invoke-Uninstall }
        'status' { Invoke-Status }
        'rollback' { Invoke-Rollback }
        default { Invoke-OperatorAction }
    }
}
