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
    local SYSTEM identity. Guard accepts that kernel-authenticated SID as the
    packaged Windows operator, rejects an admin bearer in service mode, and
    does not grant operator authority to its daemon service SID. Task operands
    are validated and base64 encoded as data before PowerShell task syntax is
    constructed.

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

    [string]$RepoRoot,
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
$DeployedOperatorScript = Join-Path $InstallRoot 'guard-operator.ps1'
$ConfigRoot = 'C:\ProgramData\GuardConfig'
$VerbsPath = Join-Path $ConfigRoot 'verbs.yaml'
$DataDir = 'C:\ProgramData\Guard'
$StateDb = Join-Path $DataDir 'state.db'
$AuthorityKey = Join-Path $DataDir 'authority.hmac'
$KubeDir = Join-Path $ConfigRoot 'kube'
$KubeConfig = Join-Path $KubeDir 'config'
$MaintenanceRoot = 'C:\ProgramData\GuardMaintenance'
$StagingDir = Join-Path $MaintenanceRoot 'staging'
$BackupRoot = Join-Path $MaintenanceRoot 'backups'
$TaskOutDir = Join-Path $MaintenanceRoot 'task-output'
$TransactionJournal = Join-Path $MaintenanceRoot 'upgrade-transaction.json'

$ServiceReadinessTimeoutSeconds = 30
$OperatorTaskTimeoutSeconds = 60
$BackupMetadataSchema = 5
$TransactionJournalSchema = 4
$DeploymentMutexName = 'Global\GuardDeploymentTransaction'

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

function Resolve-InstallRepoRoot {
    if ($RepoRoot) {
        if (-not (Test-Path -LiteralPath $RepoRoot -PathType Container)) {
            throw "RepoRoot does not exist: '$RepoRoot'."
        }
        Assert-NoReparsePoint -Path $RepoRoot
        return (Resolve-Path -LiteralPath $RepoRoot).Path
    }
    $archiveRoot = Join-Path $PSScriptRoot '..\..'
    if (Test-Path -LiteralPath $archiveRoot -PathType Container) {
        Assert-NoReparsePoint -Path $archiveRoot
        return (Resolve-Path -LiteralPath $archiveRoot).Path
    }
    return $null
}

function Resolve-GuardExe {
    param([string]$InstallRepoRoot)
    if ($CandidateExe) {
        if (-not (Test-Path -LiteralPath $CandidateExe -PathType Leaf)) {
            throw "CandidateExe does not exist: '$CandidateExe'."
        }
        Assert-NoReparsePoint -Path $CandidateExe
        return (Resolve-Path -LiteralPath $CandidateExe).Path
    }
    $candidates = if ($InstallRepoRoot) {
        @(
            (Join-Path $InstallRepoRoot 'guard.exe'),
            (Join-Path $InstallRepoRoot 'target\release\guard.exe'),
            (Join-Path $InstallRepoRoot 'target\debug\guard.exe')
        )
    }
    else { @() }
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
    Assert-NoReparsePoint -Path $Path
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
    Assert-NoReparsePoint -Path $Path
    Assert-ExactFileSystemAcl -Path $Path -OwnerSid $OwnerSid -Entries $Entries
    foreach ($item in Get-PrunedTreeItems -Path $Path -Exclude $Exclude) {
        Assert-ExactFileSystemAcl -Path $item.FullName -OwnerSid $OwnerSid -Entries $Entries
    }
}

function Reset-TreeForAdministrativeMaintenance {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$AdditionalRoots = @()
    )
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $allowedRoots = @($InstallRoot, $DataDir, $ConfigRoot, $MaintenanceRoot) + @($AdditionalRoots)
    $withinAllowedRoot = @($allowedRoots | Where-Object { Test-PathWithin -Path $Path -Parent $_ }).Count -gt 0
    if (-not $withinAllowedRoot) {
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

function Get-DeploymentStatePaths {
    param([AllowNull()]$StatePaths)
    if ($null -ne $StatePaths) { return $StatePaths }
    return [pscustomobject]@{
        StateDb = $StateDb
        AuthorityKey = $AuthorityKey
        ApiRevertRoot = Join-Path $DataDir 'api-proxy-reverts'
        SocketName = $SocketName
    }
}

function Get-StateDirectory {
    param([Parameter(Mandatory)]$StatePaths)
    return (Split-Path -Parent ([string]$StatePaths.StateDb))
}

function Get-StatePrivateRoots {
    param([Parameter(Mandatory)]$StatePaths)
    $stateDirectory = Get-StateDirectory -StatePaths $StatePaths
    return @(
        (Join-Path $stateDirectory 'secret-files'),
        [string]$StatePaths.ApiRevertRoot
    )
}

function Get-StatePrivateFiles {
    param([Parameter(Mandatory)]$StatePaths)
    return @([string]$StatePaths.AuthorityKey)
}

function Get-StateAdministrativeRoots {
    param([Parameter(Mandatory)]$StatePaths)
    return @((Join-Path (Get-StateDirectory -StatePaths $StatePaths) 'kube'))
}

function Assert-DedicatedStateDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$StateDb
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    Assert-NoReparsePoint -Path $Path
    $databaseName = Split-Path -Leaf $StateDb
    $allowedNames = @(
        $databaseName,
        "$databaseName-wal",
        "$databaseName-shm",
        "$databaseName-journal",
        "$databaseName.daemon.lock",
        'authority.hmac',
        'api-proxy-reverts',
        'secret-files',
        'kube'
    )
    $unexpected = @(Get-ChildItem -LiteralPath $Path -Force | Where-Object { $_.Name -notin $allowedNames })
    if ($unexpected.Count -gt 0) {
        throw "Guard service --state-db must be beneath a dedicated state directory containing only Guard state."
    }
}

function Get-ActiveKubeConfigPath {
    param(
        [Parameter(Mandatory)][hashtable]$Environment,
        [Parameter(Mandatory)]$StatePaths
    )
    $legacyConfig = Join-Path (Get-StateDirectory -StatePaths $StatePaths) 'kube\config'
    if ($Environment.ContainsKey('KUBECONFIG')) {
        $selected = [string]$Environment['KUBECONFIG']
        if ($selected.Equals($KubeConfig, [StringComparison]::OrdinalIgnoreCase)) {
            return $KubeConfig
        }
        if ($selected.Equals($legacyConfig, [StringComparison]::OrdinalIgnoreCase)) {
            return $legacyConfig
        }
        throw 'Guard service KUBECONFIG must use the managed authority root.'
    }
    if (Test-Path -LiteralPath $KubeConfig -PathType Leaf) { return $KubeConfig }
    if (Test-Path -LiteralPath $legacyConfig -PathType Leaf) { return $legacyConfig }
    return $null
}

function Normalize-KubeEnvironmentAuthority {
    param(
        [Parameter(Mandatory)][hashtable]$Environment,
        [Parameter(Mandatory)]$StatePaths
    )
    $result = @{}
    foreach ($entry in $Environment.GetEnumerator()) {
        $result[[string]$entry.Key] = [string]$entry.Value
    }
    if (-not $result.ContainsKey('KUBECONFIG')) { return $result }

    $selected = [string]$result['KUBECONFIG']
    $legacyConfig = Join-Path (Get-StateDirectory -StatePaths $StatePaths) 'kube\config'
    if (-not $selected.Equals($KubeConfig, [StringComparison]::OrdinalIgnoreCase) -and
        -not $selected.Equals($legacyConfig, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Guard service KUBECONFIG must use the managed authority root.'
    }
    if (Test-Path -LiteralPath $selected -PathType Leaf) { return $result }

    [void]$result.Remove('KUBECONFIG')
    $childNames = @()
    if ($result.ContainsKey('GUARD_CHILD_ENV')) {
        $childNames += @(([string]$result['GUARD_CHILD_ENV'] -split ',') | ForEach-Object { $_.Trim() } | Where-Object {
            $_ -and -not $_.Equals('KUBECONFIG', [StringComparison]::OrdinalIgnoreCase)
        })
    }
    $childNames = @($childNames | Select-Object -Unique)
    if ($childNames.Count -gt 0) {
        $result['GUARD_CHILD_ENV'] = $childNames -join ','
    }
    else {
        [void]$result.Remove('GUARD_CHILD_ENV')
    }
    return $result
}

function Copy-KubeConfigToAuthorityRoot {
    param(
        [AllowNull()]$StatePaths,
        [Parameter(Mandatory)][hashtable]$Environment
    )
    $statePaths = Get-DeploymentStatePaths -StatePaths $StatePaths
    $source = Get-ActiveKubeConfigPath -Environment $Environment -StatePaths $statePaths
    if ($null -eq $source) { return }
    if ($source.Equals($KubeConfig, [StringComparison]::OrdinalIgnoreCase)) {
        if (-not (Test-Path -LiteralPath $KubeConfig -PathType Leaf)) {
            throw 'Guard service KUBECONFIG does not exist in the managed authority root.'
        }
        Assert-NoReparsePoint -Path $KubeConfig
        return
    }
    $stateDirectory = Get-StateDirectory -StatePaths $statePaths
    Assert-NoReparsePoint -Path $stateDirectory
    Assert-NoReparsePoint -Path (Split-Path -Parent $source)
    Assert-NoReparsePoint -Path $source
    if (Test-Path -LiteralPath $ConfigRoot) { Assert-NoReparsePoint -Path $ConfigRoot }
    if (Test-Path -LiteralPath $KubeConfig) {
        Assert-NoReparsePoint -Path $KubeConfig
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash -ne
            (Get-FileHash -Algorithm SHA256 -LiteralPath $KubeConfig).Hash) {
            throw 'Guard kube configuration exists in both state and authority roots with different content.'
        }
        return
    }
    New-Item -ItemType Directory -Force -Path $KubeDir | Out-Null
    $sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash
    Install-FileAtomically -Source $source -Destination $KubeConfig -ExpectedHash $sourceHash
}

function Convert-LegacyKubeEnvironment {
    param(
        [Parameter(Mandatory)][hashtable]$Environment,
        [Parameter(Mandatory)]$StatePaths
    )
    $result = @{}
    foreach ($entry in $Environment.GetEnumerator()) {
        $result[[string]$entry.Key] = [string]$entry.Value
    }
    if (-not $result.ContainsKey('KUBECONFIG')) { return $result }
    $legacyConfig = Join-Path (Get-StateDirectory -StatePaths $StatePaths) 'kube\config'
    if (-not ([string]$result['KUBECONFIG']).Equals($legacyConfig, [StringComparison]::OrdinalIgnoreCase)) {
        return $result
    }
    if (-not (Test-Path -LiteralPath $KubeConfig -PathType Leaf)) {
        throw 'The legacy service environment requires kube authority that has not been migrated.'
    }
    $result['KUBECONFIG'] = $KubeConfig
    return $result
}

function Complete-ManagedKubeEnvironment {
    param([Parameter(Mandatory)][hashtable]$Environment)
    $result = @{}
    foreach ($entry in $Environment.GetEnumerator()) {
        $result[[string]$entry.Key] = [string]$entry.Value
    }
    $childNames = @()
    if ($result.ContainsKey('GUARD_CHILD_ENV')) {
        $childNames += @(([string]$result['GUARD_CHILD_ENV'] -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne 'KUBECONFIG' })
    }
    if (Test-Path -LiteralPath $KubeConfig -PathType Leaf) {
        $result['KUBECONFIG'] = $KubeConfig
        $childNames += 'KUBECONFIG'
    }
    else {
        [void]$result.Remove('KUBECONFIG')
    }
    $childNames = @($childNames | Select-Object -Unique)
    if ($childNames.Count -gt 0) {
        $result['GUARD_CHILD_ENV'] = $childNames -join ','
    }
    else {
        [void]$result.Remove('GUARD_CHILD_ENV')
    }
    return $result
}

function Assert-PrivateServiceTree {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$GuardSid
    )
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $entries = @((New-AclEntry -Sid $GuardSid -Rights ([Security.AccessControl.FileSystemRights]::FullControl)))
    Assert-ExactAclTree -Path $Path -OwnerSid $GuardSid -Entries $entries
}

function Set-DeploymentAcls {
    param(
        [Parameter(Mandatory)][string]$GuardSid,
        [AllowNull()]$StatePaths
    )
    $statePaths = Get-DeploymentStatePaths -StatePaths $StatePaths
    $stateDirectory = Get-StateDirectory -StatePaths $statePaths
    $privateRoots = Get-StatePrivateRoots -StatePaths $statePaths
    $privateFiles = Get-StatePrivateFiles -StatePaths $statePaths
    $administrativeRoots = Get-StateAdministrativeRoots -StatePaths $statePaths
    if (-not (Test-PathWithin -Path $KubeDir -Parent $ConfigRoot)) {
        throw "Guard kube configuration must remain beneath the administrator-owned configuration directory."
    }
    New-Item -ItemType Directory -Force -Path $InstallRoot, $ConfigRoot, $stateDirectory, $KubeDir | Out-Null
    Assert-DedicatedStateDirectory -Path $stateDirectory -StateDb $statePaths.StateDb
    Set-ExactAclTree -Path $InstallRoot -OwnerSid $SidAdmins -Entries (Get-ServiceReadAclEntries -GuardSid $GuardSid)
    Set-ExactAclTree -Path $ConfigRoot -OwnerSid $SidAdmins -Entries (Get-ServiceReadAclEntries -GuardSid $GuardSid)
    Set-ExactAclTree -Path $stateDirectory -OwnerSid $SidAdmins -Entries (Get-ServiceWriteAclEntries -GuardSid $GuardSid) -Exclude ($privateRoots + $privateFiles + $administrativeRoots)
    foreach ($administrativeRoot in $administrativeRoots) {
        if (Test-Path -LiteralPath $administrativeRoot -PathType Container) {
            Set-ExactAclTree -Path $administrativeRoot -OwnerSid $SidAdmins -Entries (Get-AdministrativeAclEntries)
        }
    }
    foreach ($privateRoot in $privateRoots) {
        Protect-PrivateServiceTree -Path $privateRoot -GuardSid $GuardSid
    }
    foreach ($privateFile in $privateFiles) {
        if (Test-Path -LiteralPath $privateFile -PathType Leaf) {
            Set-ExactFileSystemAcl -Path $privateFile -OwnerSid $GuardSid -Entries @((New-AclEntry -Sid $GuardSid -Rights ([Security.AccessControl.FileSystemRights]::FullControl)))
        }
    }
    Set-MaintenanceAcl
}

function Assert-DeploymentAcls {
    param(
        [Parameter(Mandatory)][string]$GuardSid,
        [AllowNull()]$StatePaths,
        [bool]$AuthorityKeyPresent = $true
    )
    $statePaths = Get-DeploymentStatePaths -StatePaths $StatePaths
    $stateDirectory = Get-StateDirectory -StatePaths $statePaths
    $privateRoots = Get-StatePrivateRoots -StatePaths $statePaths
    $privateFiles = Get-StatePrivateFiles -StatePaths $statePaths
    $administrativeRoots = Get-StateAdministrativeRoots -StatePaths $statePaths
    $readEntries = Get-ServiceReadAclEntries -GuardSid $GuardSid
    $writeEntries = Get-ServiceWriteAclEntries -GuardSid $GuardSid
    $administrativeEntries = Get-AdministrativeAclEntries
    if (-not (Test-PathWithin -Path $KubeDir -Parent $ConfigRoot)) {
        throw "Guard kube configuration must remain beneath the administrator-owned configuration directory."
    }
    Assert-ExactAclTree -Path $InstallRoot -OwnerSid $SidAdmins -Entries $readEntries
    Assert-ExactAclTree -Path $ConfigRoot -OwnerSid $SidAdmins -Entries $readEntries
    Assert-ExactAclTree -Path $stateDirectory -OwnerSid $SidAdmins -Entries $writeEntries -Exclude ($privateRoots + $privateFiles + $administrativeRoots)
    foreach ($administrativeRoot in $administrativeRoots) {
        if (Test-Path -LiteralPath $administrativeRoot -PathType Container) {
            Assert-ExactAclTree -Path $administrativeRoot -OwnerSid $SidAdmins -Entries $administrativeEntries
        }
    }
    foreach ($privateRoot in $privateRoots) {
        Assert-PrivateServiceTree -Path $privateRoot -GuardSid $GuardSid
    }
    foreach ($privateFile in $privateFiles) {
        $privateFilePresent = Test-Path -LiteralPath $privateFile -PathType Leaf
        if ($privateFile.Equals([string]$statePaths.AuthorityKey, [StringComparison]::OrdinalIgnoreCase)) {
            if ($privateFilePresent -ne $AuthorityKeyPresent) {
                throw 'Daemon authority file presence does not match the recorded deployment state.'
            }
            if (-not $privateFilePresent) {
                continue
            }
        }
        elseif (-not $privateFilePresent) {
            throw "Daemon authority file is missing: '$privateFile'."
        }
        Assert-ExactFileSystemAcl -Path $privateFile -OwnerSid $GuardSid -Entries @((New-AclEntry -Sid $GuardSid -Rights ([Security.AccessControl.FileSystemRights]::FullControl)))
    }
    Assert-ExactAclTree -Path $MaintenanceRoot -OwnerSid $SidAdmins -Entries $administrativeEntries
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

function Write-ServiceRegistryAclObject {
    param([Parameter(Mandatory)][object]$AclObject)
    $subKey = "SYSTEM\CurrentControlSet\Services\$ServiceName"
    $rights = [Security.AccessControl.RegistryRights]::ReadPermissions `
        -bor [Security.AccessControl.RegistryRights]::ChangePermissions `
        -bor [Security.AccessControl.RegistryRights]::TakeOwnership
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        $subKey,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        $rights
    )
    if ($null -eq $key) { throw 'service registry key is not visible' }
    try {
        [Microsoft.Win32.RegistryAclExtensions]::SetAccessControl($key, $AclObject)
    }
    finally {
        $key.Dispose()
    }
}

function Set-ServiceRegistryAclObject {
    param([Parameter(Mandatory)][object]$AclObject)
    $lastError = 'service registry ACL was not written'
    for ($attempt = 1; $attempt -le 20; $attempt++) {
        try {
            Write-ServiceRegistryAclObject -AclObject $AclObject
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
    Set-ServiceRegistryAclObject -AclObject $acl

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
    param([Parameter(Mandatory)][string]$Socket)
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
    [void]$arguments.Add('--socket'); [void]$arguments.Add((Assert-CanonicalSocketName -Socket $Socket))
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
    $encodedStatus = ConvertTo-Base64Utf8 "$OutputFile.status"
    $encodedArguments = @($Arguments | ForEach-Object { "'$(ConvertTo-Base64Utf8 $_)'" }) -join ','
    $script = @"
`$ErrorActionPreference = 'Stop'
function Decode([string]`$value) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(`$value)) }
`$guardExe = Decode '$encodedExe'
`$outputFile = Decode '$encodedOutput'
`$statusFile = Decode '$encodedStatus'
`$guardArguments = @($encodedArguments) | ForEach-Object { Decode `$_ }
`$nativeStatus = 1
try {
    & `$guardExe @guardArguments *> `$outputFile
    `$nativeStatus = `$LASTEXITCODE
}
finally {
    [IO.File]::WriteAllText(`$statusFile, [string]`$nativeStatus, [Text.UTF8Encoding]::new(`$false))
}
exit `$nativeStatus
"@
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
}

function Read-GuardOperatorStatus {
    param([Parameter(Mandatory)][string]$StatusFile)
    if (-not (Test-Path -LiteralPath $StatusFile -PathType Leaf)) { return $null }
    $raw = (Get-Content -LiteralPath $StatusFile -Raw).Trim()
    $status = 0
    if ($raw -notmatch '^[0-9]{1,10}$' -or -not [int]::TryParse($raw, [ref]$status) -or $status -lt 0) {
        throw 'Guard operator task produced an invalid native status.'
    }
    return [int64]$status
}

function Invoke-GuardAsOperator {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$GuardExe,
        [switch]$JsonOutput
    )
    Assert-Admin -ForAction $Action
    if (-not (Test-Path -LiteralPath $GuardExe -PathType Leaf)) { throw "Installed Guard binary not found at '$GuardExe'." }
    $taskName = "guard-op-$([guid]::NewGuid().ToString('N'))"
    $outputFile = Join-Path $TaskOutDir "$taskName.out"
    $statusFile = "$outputFile.status"
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
            $statusReady = Test-Path -LiteralPath $statusFile -PathType Leaf
        } while ((-not $triggered -or $active -or -not $statusReady) -and (Get-Date) -lt $deadline)
        $nativeStatus = if ($statusReady) {
            Read-GuardOperatorStatus -StatusFile $statusFile
        }
        else { [int64]$taskInfo.LastTaskResult }
        if (Test-Path -LiteralPath $outputFile) {
            $output = Get-Content -LiteralPath $outputFile -Raw
        }
        if (-not $triggered -or $active -or -not $statusReady) {
            $diagnostic = if ($null -eq $output) { '' } else { ConvertTo-SanitizedDiagnosticOutput -Value $output }
            throw "Guard operator task timed out; native_status=$nativeStatus; output=$diagnostic"
        }
        return Resolve-GuardOperatorResult -RawOutput $output -NativeStatus $nativeStatus -JsonOutput:($JsonOutput -or $Json)
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

function Get-GuardServiceStartupDiagnostic {
    $serviceLog = Join-Path $DataDir 'guard.log'
    if (-not (Test-Path -LiteralPath $serviceLog -PathType Leaf)) { return '' }
    try {
        $lines = @(Get-Content -LiteralPath $serviceLog -Tail 80 -ErrorAction Stop |
            Where-Object { $_ -match 'guard service.*error|daemon terminated with error' })
        if ($lines.Count -eq 0) { return '' }
        $errorLine = [string]$lines[-1]
        if ($errorLine -match '(?i)verb catalog|catalog authority') { return 'verb-catalog' }
        if ($errorLine -match '(?i)state database|state-db|sqlite|authority file') { return 'durable-state' }
        if ($errorLine -match '(?i)named pipe|socket|listener|endpoint') { return 'local-endpoint' }
        if ($errorLine -match '(?i)kubeconfig|api proxy|brokered') { return 'brokered-api' }
        if ($errorLine -match '(?i)permission|access is denied|dacl|acl') { return 'filesystem-authority' }
        return 'daemon-startup'
    }
    catch { return '' }
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
    $statusFile = "$OutputFile.status"
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
            if (Test-Path -LiteralPath $statusFile) {
                Remove-Item -LiteralPath $statusFile -Force -ErrorAction Stop
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
            $statusComplete = -not (Test-Path -LiteralPath $statusFile)
            if (-not $taskRemaining -and $outputComplete -and $statusComplete) { return }
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

function Start-GuardService {
    param([Parameter(Mandatory)][string]$Name)
    $lastStatus = 'Unavailable'
    $lastError = 'the service controller did not expose the service'
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($service) {
            $service.Refresh()
            $lastStatus = [string]$service.Status
            if ($service.Status -eq 'Running') { return }
        }

        $startFailed = $false
        if ($service -and $service.Status -eq 'Stopped') {
            try {
                Start-Service -Name $Name -ErrorAction Stop
            }
            catch {
                $startFailed = $true
                $lastError = $_.Exception.Message
            }
            $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
            if ($service) {
                $service.Refresh()
                $lastStatus = [string]$service.Status
                if ($service.Status -eq 'Running') { return }
            }
        }

        if ($service -and ($service.Status -eq 'StartPending' -or -not $startFailed)) {
            try {
                $service.WaitForStatus('Running', (New-TimeSpan -Seconds 10))
                $service.Refresh()
                $lastStatus = [string]$service.Status
                if ($service.Status -eq 'Running') { return }
                $lastError = "the bounded transition completed in state '$lastStatus'"
            }
            catch {
                $service.Refresh()
                $lastStatus = [string]$service.Status
                $lastError = $_.Exception.Message
            }
        }
        if ($attempt -lt 3) { Start-Sleep -Milliseconds 200 }
    }
    $daemonDiagnostic = Get-GuardServiceStartupDiagnostic
    $diagnosticSuffix = if ([string]::IsNullOrWhiteSpace($daemonDiagnostic)) {
        ''
    }
    else {
        "; daemon diagnostic: $daemonDiagnostic"
    }
    throw "Guard service '$Name' did not reach Running after 3 bounded state-transition attempts. Last observed status: '$lastStatus'. Last transition error: $lastError$diagnosticSuffix"
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

function ConvertFrom-GuardServiceCommandLine {
    param([Parameter(Mandatory)][string]$PathName)
    [void](Assert-ServicePathName -PathName $PathName)
    $tokens = [Collections.Generic.List[string]]::new()
    $index = 0
    while ($index -lt $PathName.Length) {
        while ($index -lt $PathName.Length -and [char]::IsWhiteSpace($PathName[$index])) { $index++ }
        if ($index -ge $PathName.Length) { break }
        if ($PathName[$index] -eq '"') {
            $index++
            $start = $index
            while ($index -lt $PathName.Length -and $PathName[$index] -ne '"') { $index++ }
            if ($index -ge $PathName.Length -or $index -eq $start) {
                throw 'The Guard service command line contains an empty or unterminated quoted argument.'
            }
            $tokens.Add($PathName.Substring($start, $index - $start))
            $index++
            if ($index -lt $PathName.Length -and -not [char]::IsWhiteSpace($PathName[$index])) {
                throw 'The Guard service command line contains unsupported quoted argument escaping.'
            }
        }
        else {
            $start = $index
            while ($index -lt $PathName.Length -and -not [char]::IsWhiteSpace($PathName[$index])) {
                if ($PathName[$index] -eq '"') {
                    throw 'The Guard service command line contains unsupported embedded quotes.'
                }
                $index++
            }
            $tokens.Add($PathName.Substring($start, $index - $start))
        }
    }
    if ($tokens.Count -eq 0 -or -not $tokens[0].Equals($DeployedExe, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The Guard service command line does not begin with the installed executable.'
    }
    return [string[]]$tokens.ToArray()
}

function Assert-CanonicalStateDatabasePath {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -notmatch '^[A-Za-z]:\\[A-Za-z0-9 _().,@+=\-$]+(?:\\[A-Za-z0-9 _().,@+=\-$]+)*$') {
        throw 'Guard service --state-db must be a canonical absolute Windows path.'
    }
    foreach ($component in $Path.Substring(3).Split([char[]]@('\'))) {
        if ([string]::IsNullOrWhiteSpace($component) -or $component -in @('.', '..')) {
            throw 'Guard service --state-db must be a canonical absolute Windows path.'
        }
    }
    return $Path
}

function Assert-CanonicalSocketName {
    param([Parameter(Mandatory)][string]$Socket)
    if ($Socket -notmatch '^(?:[A-Za-z0-9._-]{1,128}|\\\\[.?]\\pipe\\[A-Za-z0-9._-]{1,128})$') {
        throw 'Guard service --socket must be a bare pipe name or canonical local named-pipe path.'
    }
    return $Socket
}

function Get-GuardStatePaths {
    param([Parameter(Mandatory)][string]$ServicePathName)
    $arguments = ConvertFrom-GuardServiceCommandLine -PathName $ServicePathName
    $candidates = [Collections.Generic.List[string]]::new()
    for ($index = 1; $index -lt $arguments.Count; $index++) {
        if ($arguments[$index] -eq '--state-db') {
            if ($index + 1 -ge $arguments.Count) {
                throw 'Guard service --state-db is missing its path value.'
            }
            $candidates.Add($arguments[$index + 1])
            $index++
        }
        elseif ($arguments[$index].StartsWith('--state-db=', [StringComparison]::Ordinal)) {
            $candidates.Add($arguments[$index].Substring('--state-db='.Length))
        }
    }
    if ($candidates.Count -ne 1) {
        throw 'Guard service must define exactly one --state-db setting.'
    }
    $socketCandidates = [Collections.Generic.List[string]]::new()
    for ($index = 1; $index -lt $arguments.Count; $index++) {
        if ($arguments[$index] -eq '--socket') {
            if ($index + 1 -ge $arguments.Count) {
                throw 'Guard service --socket is missing its pipe value.'
            }
            $socketCandidates.Add($arguments[$index + 1])
            $index++
        }
        elseif ($arguments[$index].StartsWith('--socket=', [StringComparison]::Ordinal)) {
            $socketCandidates.Add($arguments[$index].Substring('--socket='.Length))
        }
    }
    if ($socketCandidates.Count -ne 1) {
        throw 'Guard service must define exactly one --socket setting.'
    }
    $stateDatabase = Assert-CanonicalStateDatabasePath -Path $candidates[0]
    $stateDirectory = Split-Path -Parent $stateDatabase
    if ($stateDirectory -match '^[A-Za-z]:\\?$') {
        throw 'Guard service --state-db must be beneath a dedicated state directory, not a volume root.'
    }
    return [pscustomobject]@{
        StateDb = $stateDatabase
        AuthorityKey = Join-Path $stateDirectory 'authority.hmac'
        ApiRevertRoot = Join-Path $stateDirectory 'api-proxy-reverts'
        SocketName = Assert-CanonicalSocketName -Socket $socketCandidates[0]
    }
}

function Assert-GuardSnapshotStatePaths {
    param([Parameter(Mandatory)]$Snapshot)
    if ($null -eq $Snapshot.StatePaths -or [string]::IsNullOrWhiteSpace([string]$Snapshot.PathName)) {
        throw 'Guard service snapshot is missing state path metadata.'
    }
    $parsed = Get-GuardStatePaths -ServicePathName ([string]$Snapshot.PathName)
    if (-not ([string]$Snapshot.StatePaths.StateDb).Equals($parsed.StateDb, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([string]$Snapshot.StatePaths.AuthorityKey).Equals($parsed.AuthorityKey, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([string]$Snapshot.StatePaths.ApiRevertRoot).Equals($parsed.ApiRevertRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([string]$Snapshot.StatePaths.SocketName).Equals($parsed.SocketName, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Guard service snapshot state paths do not match its service command line.'
    }
    return $parsed
}

function Get-GuardStateCompatibilityReport {
    param(
        [Parameter(Mandatory)][string]$GuardExe,
        [Parameter(Mandatory)][string]$StateDb
    )
    $output = & $GuardExe state-db check --file $StateDb --json 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw 'The staged Guard candidate rejected the existing state database.'
    }
    try { $report = ($output -join [Environment]::NewLine) | ConvertFrom-Json }
    catch { throw 'The staged Guard candidate produced an invalid state database compatibility report.' }
    return $report
}

function Assert-CandidateStateCompatibility {
    param(
        [Parameter(Mandatory)][string]$GuardExe,
        [Parameter(Mandatory)][string]$StateDb
    )
    $report = Get-GuardStateCompatibilityReport -GuardExe $GuardExe -StateDb $StateDb
    if ($report.type -ne 'state_db_compatibility' -or $report.compatible -ne $true -or
        $report.simulated_open -ne $true -or $null -eq $report.simulated_startup -or
        $report.simulated_startup.succeeded -ne $true) {
        throw 'The staged Guard candidate reported that the existing state database is incompatible.'
    }
}

function Get-ServiceSnapshot {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) { return $null }
    $config = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if ($config.StartName -ne $ServiceAccount) {
        throw "Existing service '$ServiceName' uses account '$($config.StartName)'; refusing to replace it."
    }
    $servicePathName = Assert-ServicePathName -PathName ([string]$config.PathName)
    $statePaths = Get-GuardStatePaths -ServicePathName $servicePathName
    if (-not (Test-Path -LiteralPath $DeployedExe -PathType Leaf)) {
        throw "Existing service '$ServiceName' has no installed binary at '$DeployedExe'."
    }
    $environment = Normalize-KubeEnvironmentAuthority -Environment (Get-ServiceEnvironmentMap) -StatePaths $statePaths
    return [pscustomobject]@{
        WasRunning = $service.Status -eq 'Running'
        StartMode = [string]$config.StartMode
        PathName = $servicePathName
        StatePaths = $statePaths
        SocketName = $statePaths.SocketName
        Environment = $environment
        CatalogPresent = Test-Path -LiteralPath $VerbsPath -PathType Leaf
        AuthorityKeyPresent = Test-Path -LiteralPath $statePaths.AuthorityKey -PathType Leaf
        BinaryVersion = Get-GuardVersion -GuardExe $DeployedExe
        BinaryHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $DeployedExe).Hash
    }
}

function Get-ServiceStatusMetadata {
    $config = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    $servicePathName = Assert-ServicePathName -PathName ([string]$config.PathName)
    $statePaths = Get-GuardStatePaths -ServicePathName $servicePathName
    return [pscustomobject]@{
        PathName = $servicePathName
        StatePaths = $statePaths
        SocketName = $statePaths.SocketName
    }
}

function Assert-ExactJournalProperties {
    param(
        [Parameter(Mandatory)]$Document,
        [Parameter(Mandatory)][string[]]$Expected,
        [Parameter(Mandatory)][string]$Description
    )
    if ($Document -isnot [pscustomobject]) {
        throw "$Description must be a JSON object."
    }
    $actual = @($Document.PSObject.Properties.Name)
    if ($actual.Count -ne $Expected.Count) {
        throw "$Description contains fields outside its schema."
    }
    foreach ($name in $Expected) {
        if ($actual -cnotcontains $name) {
            throw "$Description is missing required field '$name'."
        }
    }
}

function Test-JsonInteger {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $false }
    return [Type]::GetTypeCode($Value.GetType()) -in @(
        [TypeCode]::Byte,
        [TypeCode]::SByte,
        [TypeCode]::Int16,
        [TypeCode]::UInt16,
        [TypeCode]::Int32,
        [TypeCode]::UInt32,
        [TypeCode]::Int64,
        [TypeCode]::UInt64
    )
}

function Test-ExactPathValue {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory)][string]$Expected
    )
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value)) { return $false }
    try {
        $fullValue = [IO.Path]::GetFullPath($Value)
        $fullExpected = [IO.Path]::GetFullPath($Expected)
        return $Value.Equals($fullValue, [StringComparison]::OrdinalIgnoreCase) -and
            $fullValue.Equals($fullExpected, [StringComparison]::OrdinalIgnoreCase)
    }
    catch { return $false }
}

function Write-GuardTransactionJournal {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Transaction)
    Set-MaintenanceAcl
    $temporary = Join-Path $MaintenanceRoot ".guard-upgrade-$([guid]::NewGuid().ToString('N')).tmp"
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($Transaction | ConvertTo-Json -Depth 4))
        $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
        Set-ExactFileSystemAcl -Path $temporary -OwnerSid $SidAdmins -Entries (Get-AdministrativeAclEntries)
        [IO.File]::Move($temporary, $TransactionJournal, $true)
        Assert-ExactFileSystemAcl -Path $TransactionJournal -OwnerSid $SidAdmins -Entries (Get-AdministrativeAclEntries)
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function New-GuardTransactionJournal {
    param(
        [Parameter(Mandatory)][ValidateSet('install', 'rollback')][string]$Operation,
        [Parameter(Mandatory)]$Snapshot
    )
    $statePaths = Assert-GuardSnapshotStatePaths -Snapshot $Snapshot
    if ($Snapshot.PSObject.Properties.Name -notcontains 'AuthorityKeyPresent' -or
        $Snapshot.AuthorityKeyPresent -isnot [bool] -or
        $Snapshot.BinaryHash -isnot [string] -or $Snapshot.BinaryHash -notmatch '^[0-9a-fA-F]{64}$' -or
        $Snapshot.BinaryVersion -isnot [string] -or $Snapshot.BinaryVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or
        $Snapshot.StartMode -isnot [string] -or $Snapshot.StartMode -cnotin @('Auto', 'Manual', 'Disabled') -or
        $Snapshot.WasRunning -isnot [bool]) {
        throw 'Guard service snapshot transaction metadata is invalid.'
    }
    $socketName = Assert-CanonicalSocketName -Socket ([string]$statePaths.SocketName)
    return [ordered]@{
        format = 'guard-windows-transaction'
        schema = $TransactionJournalSchema
        operation = $Operation
        deployment_absent = $false
        phase = 'quiescing'
        backup_name = $null
        completed_binary_sha256 = $null
        completed_binary_version = $null
        completed_service_path_name = $null
        completed_state_database = $null
        completed_socket_name = $null
        completed_authority_key_present = $null
        completed_start_mode = $null
        completed_was_running = $null
        service_path_name = $Snapshot.PathName
        state_database = $statePaths.StateDb
        socket_name = $socketName
        authority_key_present = [bool]$Snapshot.AuthorityKeyPresent
        binary_sha256 = $Snapshot.BinaryHash.ToLowerInvariant()
        binary_version = $Snapshot.BinaryVersion
        start_mode = $Snapshot.StartMode
        was_running = [bool]$Snapshot.WasRunning
    }
}

function Start-NewInstallationTransaction {
    if (Test-Path -LiteralPath $TransactionJournal) {
        throw 'An interrupted Guard transaction requires recovery before another deployment action.'
    }
    $transaction = [ordered]@{
        format = 'guard-windows-transaction'
        schema = $TransactionJournalSchema
        operation = 'install'
        deployment_absent = $true
        phase = 'staging'
        service_name = $ServiceName
        service_account = $ServiceAccount
        service_path_name = $null
        install_root = [IO.Path]::GetFullPath($InstallRoot)
        config_root = [IO.Path]::GetFullPath($ConfigRoot)
        data_directory = [IO.Path]::GetFullPath($DataDir)
        maintenance_root = [IO.Path]::GetFullPath($MaintenanceRoot)
    }
    Write-GuardTransactionJournal -Transaction $transaction
    return $transaction
}

function Set-NewInstallationTransactionMutating {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Transaction,
        [Parameter(Mandatory)][string]$ServicePathName
    )
    if ($Transaction['deployment_absent'] -ne $true -or $Transaction['phase'] -ne 'staging') {
        throw 'New-installation transaction phase transition is invalid.'
    }
    $servicePathName = Assert-ServicePathName -PathName $ServicePathName
    $statePaths = Get-GuardStatePaths -ServicePathName $servicePathName
    $expectedStatePaths = Get-DeploymentStatePaths -StatePaths $null
    if (-not $statePaths.StateDb.Equals($expectedStatePaths.StateDb, [StringComparison]::OrdinalIgnoreCase) -or
        -not $statePaths.SocketName.Equals($expectedStatePaths.SocketName, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'New-installation service command line does not use the managed state and socket paths.'
    }
    $Transaction['phase'] = 'mutating'
    $Transaction['service_path_name'] = $servicePathName
    Write-GuardTransactionJournal -Transaction $Transaction
}

function Start-GuardTransaction {
    param(
        [Parameter(Mandatory)][ValidateSet('install', 'rollback')][string]$Operation,
        [Parameter(Mandatory)]$Snapshot
    )
    if (Test-Path -LiteralPath $TransactionJournal) {
        throw 'An interrupted Guard transaction requires recovery before another deployment action.'
    }
    $transaction = New-GuardTransactionJournal -Operation $Operation -Snapshot $Snapshot
    Write-GuardTransactionJournal -Transaction $transaction
    return $transaction
}

function Set-GuardTransactionPhase {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Transaction,
        [Parameter(Mandatory)][ValidateSet('prepared', 'mutating')][string]$Phase,
        [Parameter(Mandatory)][string]$BackupName
    )
    if ($BackupName -notmatch '^before-v[0-9]+\.[0-9]+\.[0-9]+-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{32}$') {
        throw 'Guard transaction backup name is invalid.'
    }
    $Transaction['phase'] = $Phase
    $Transaction['backup_name'] = $BackupName
    Write-GuardTransactionJournal -Transaction $Transaction
}

function Mark-GuardTransactionVerified {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Transaction,
        [Parameter(Mandatory)]$CompletedSnapshot
    )
    $completedStatePaths = Assert-GuardSnapshotStatePaths -Snapshot $CompletedSnapshot
    if ($Transaction['phase'] -ne 'mutating' -or
        $CompletedSnapshot.BinaryHash -isnot [string] -or $CompletedSnapshot.BinaryHash -notmatch '^[0-9a-fA-F]{64}$' -or
        $CompletedSnapshot.BinaryVersion -isnot [string] -or $CompletedSnapshot.BinaryVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or
        $CompletedSnapshot.StartMode -isnot [string] -or $CompletedSnapshot.StartMode -cnotin @('Auto', 'Manual', 'Disabled') -or
        $CompletedSnapshot.WasRunning -isnot [bool] -or
        $CompletedSnapshot.AuthorityKeyPresent -isnot [bool]) {
        throw 'Guard transaction completion metadata is invalid.'
    }
    $Transaction['phase'] = 'verified'
    $Transaction['completed_binary_sha256'] = $CompletedSnapshot.BinaryHash.ToLowerInvariant()
    $Transaction['completed_binary_version'] = $CompletedSnapshot.BinaryVersion
    $Transaction['completed_service_path_name'] = $CompletedSnapshot.PathName
    $Transaction['completed_state_database'] = $completedStatePaths.StateDb
    $Transaction['completed_socket_name'] = $completedStatePaths.SocketName
    $Transaction['completed_authority_key_present'] = [bool]$CompletedSnapshot.AuthorityKeyPresent
    $Transaction['completed_start_mode'] = $CompletedSnapshot.StartMode
    $Transaction['completed_was_running'] = [bool]$CompletedSnapshot.WasRunning
    Write-GuardTransactionJournal -Transaction $Transaction
}

function Read-GuardTransactionJournal {
    if (-not (Test-Path -LiteralPath $TransactionJournal)) { return $null }
    if (-not (Test-Path -LiteralPath $MaintenanceRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $TransactionJournal -PathType Leaf)) {
        throw 'Guard transaction journal is not a regular file in the maintenance root.'
    }
    Assert-NoReparsePoint -Path $MaintenanceRoot
    Assert-ExactFileSystemAcl -Path $MaintenanceRoot -OwnerSid $SidAdmins -Entries (Get-AdministrativeAclEntries)
    Assert-NoReparsePoint -Path $TransactionJournal
    if (-not (Test-PathWithin -Path $TransactionJournal -Parent $MaintenanceRoot)) {
        throw 'Guard transaction journal escapes the maintenance root.'
    }
    Assert-ExactFileSystemAcl -Path $TransactionJournal -OwnerSid $SidAdmins -Entries (Get-AdministrativeAclEntries)
    if ((Get-Item -LiteralPath $TransactionJournal -Force).Length -gt 65536) {
        throw 'Guard transaction journal exceeds the maximum supported size.'
    }
    try { $transaction = Get-Content -LiteralPath $TransactionJournal -Raw | ConvertFrom-Json }
    catch { throw 'Guard transaction journal is not valid JSON.' }
    if ($transaction -isnot [pscustomobject] -or
        (@($transaction.PSObject.Properties.Name) -cnotcontains 'deployment_absent') -or
        $transaction.deployment_absent -isnot [bool]) {
        throw 'Guard transaction journal metadata is invalid.'
    }
    if ($transaction.deployment_absent -eq $true) {
        $expectedProperties = @(
            'format',
            'schema',
            'operation',
            'deployment_absent',
            'phase',
            'service_name',
            'service_account',
            'service_path_name',
            'install_root',
            'config_root',
            'data_directory',
            'maintenance_root'
        )
        Assert-ExactJournalProperties -Document $transaction -Expected $expectedProperties -Description 'New-installation transaction journal'
        if ($transaction.format -isnot [string] -or $transaction.format -cne 'guard-windows-transaction' -or
            -not (Test-JsonInteger -Value $transaction.schema) -or [int64]$transaction.schema -ne $TransactionJournalSchema -or
            $transaction.operation -isnot [string] -or $transaction.operation -cne 'install' -or
            $transaction.phase -isnot [string] -or $transaction.phase -cnotin @('staging', 'mutating') -or
            $transaction.service_name -isnot [string] -or $transaction.service_name -cne $ServiceName -or
            $transaction.service_account -isnot [string] -or $transaction.service_account -cne $ServiceAccount -or
            -not (Test-ExactPathValue -Value $transaction.install_root -Expected $InstallRoot) -or
            -not (Test-ExactPathValue -Value $transaction.config_root -Expected $ConfigRoot) -or
            -not (Test-ExactPathValue -Value $transaction.data_directory -Expected $DataDir) -or
            -not (Test-ExactPathValue -Value $transaction.maintenance_root -Expected $MaintenanceRoot)) {
            throw 'New-installation transaction journal metadata is invalid.'
        }
        if ($transaction.phase -eq 'staging') {
            if ($null -ne $transaction.service_path_name) {
                throw 'Staging new-installation transaction unexpectedly has a service command line.'
            }
        }
        else {
            if ($transaction.service_path_name -isnot [string]) {
                throw 'Mutating new-installation transaction has no service command line.'
            }
            $servicePathName = Assert-ServicePathName -PathName $transaction.service_path_name
            $statePaths = Get-GuardStatePaths -ServicePathName $servicePathName
            $expectedStatePaths = Get-DeploymentStatePaths -StatePaths $null
            if (-not $statePaths.StateDb.Equals($expectedStatePaths.StateDb, [StringComparison]::OrdinalIgnoreCase) -or
                -not $statePaths.SocketName.Equals($expectedStatePaths.SocketName, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'New-installation transaction service command line does not use the managed state and socket paths.'
            }
        }
        return [pscustomobject]@{
            Document = $transaction
            StatePaths = $null
            CompletedStatePaths = $null
        }
    }
    $expectedProperties = @(
        'format',
        'schema',
        'operation',
        'deployment_absent',
        'phase',
        'backup_name',
        'completed_binary_sha256',
        'completed_binary_version',
        'completed_service_path_name',
        'completed_state_database',
        'completed_socket_name',
        'completed_authority_key_present',
        'completed_start_mode',
        'completed_was_running',
        'service_path_name',
        'state_database',
        'socket_name',
        'authority_key_present',
        'binary_sha256',
        'binary_version',
        'start_mode',
        'was_running'
    )
    Assert-ExactJournalProperties -Document $transaction -Expected $expectedProperties -Description 'Guard transaction journal'
    if ($transaction.format -isnot [string] -or $transaction.format -cne 'guard-windows-transaction' -or
        -not (Test-JsonInteger -Value $transaction.schema) -or [int64]$transaction.schema -ne $TransactionJournalSchema -or
        $transaction.operation -isnot [string] -or $transaction.operation -cnotin @('install', 'rollback') -or
        $transaction.deployment_absent -ne $false -or
        $transaction.phase -isnot [string] -or $transaction.phase -cnotin @('quiescing', 'prepared', 'mutating', 'verified') -or
        $transaction.service_path_name -isnot [string] -or
        $transaction.state_database -isnot [string] -or
        $transaction.socket_name -isnot [string] -or
        $transaction.binary_sha256 -isnot [string] -or $transaction.binary_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $transaction.binary_version -isnot [string] -or $transaction.binary_version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or
        $transaction.start_mode -isnot [string] -or $transaction.start_mode -cnotin @('Auto', 'Manual', 'Disabled') -or
        $transaction.was_running -isnot [bool] -or
        $transaction.authority_key_present -isnot [bool]) {
        throw 'Guard transaction journal metadata is invalid.'
    }
    $statePaths = Get-GuardStatePaths -ServicePathName ([string]$transaction.service_path_name)
    if (-not ([string]$transaction.state_database).Equals($statePaths.StateDb, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Guard transaction state path does not match its service command line.'
    }
    if (-not ([string]$transaction.socket_name).Equals($statePaths.SocketName, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Guard transaction socket does not match its service command line.'
    }
    if ($transaction.phase -eq 'quiescing') {
        if ($null -ne $transaction.backup_name) { throw 'Quiescing Guard transaction unexpectedly has a backup.' }
    }
    else {
        if ($transaction.backup_name -isnot [string] -or
            $transaction.backup_name -cnotmatch '^before-v[0-9]+\.[0-9]+\.[0-9]+-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{32}$') {
            throw 'Guard transaction backup name is invalid.'
        }
    }
    $completedStatePaths = $null
    if ($transaction.phase -eq 'verified') {
        if ($transaction.completed_binary_sha256 -isnot [string] -or $transaction.completed_binary_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $transaction.completed_binary_version -isnot [string] -or $transaction.completed_binary_version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or
            $transaction.completed_service_path_name -isnot [string] -or
            $transaction.completed_state_database -isnot [string] -or
            $transaction.completed_socket_name -isnot [string] -or
            $transaction.completed_start_mode -isnot [string] -or $transaction.completed_start_mode -cnotin @('Auto', 'Manual', 'Disabled') -or
            $transaction.completed_was_running -isnot [bool] -or
            $transaction.completed_authority_key_present -isnot [bool]) {
            throw 'Verified Guard transaction completion metadata is invalid.'
        }
        $completedStatePaths = Get-GuardStatePaths -ServicePathName ([string]$transaction.completed_service_path_name)
        if (-not ([string]$transaction.completed_state_database).Equals($completedStatePaths.StateDb, [StringComparison]::OrdinalIgnoreCase) -or
            -not ([string]$transaction.completed_socket_name).Equals($completedStatePaths.SocketName, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Verified Guard transaction state paths do not match its completed service command line.'
        }
    }
    elseif (@(
        $transaction.completed_binary_sha256,
        $transaction.completed_binary_version,
        $transaction.completed_service_path_name,
        $transaction.completed_state_database,
        $transaction.completed_socket_name,
        $transaction.completed_authority_key_present,
        $transaction.completed_start_mode,
        $transaction.completed_was_running
    ) | Where-Object { $null -ne $_ }) {
        throw 'Unverified Guard transaction unexpectedly has completion metadata.'
    }
    return [pscustomobject]@{
        Document = $transaction
        StatePaths = $statePaths
        CompletedStatePaths = $completedStatePaths
    }
}

function Complete-GuardTransaction {
    if (-not (Test-Path -LiteralPath $TransactionJournal)) { return }
    $null = Read-GuardTransactionJournal
    $lastError = $null
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            Assert-NoReparsePoint -Path $TransactionJournal
            Remove-Item -LiteralPath $TransactionJournal -Force -ErrorAction Stop
            if (-not (Test-Path -LiteralPath $TransactionJournal)) { return }
            $lastError = 'journal still exists after cleanup'
        }
        catch { $lastError = $_.Exception.Message }
        if ($attempt -lt 3) { Start-Sleep -Milliseconds 200 }
    }
    throw "Guard transaction journal cleanup failed after 3 attempts: $lastError"
}

function Restore-SnapshotPrivateServiceAcls {
    param(
        [Parameter(Mandatory)]$StatePaths,
        [Parameter(Mandatory)][string]$GuardSid,
        [Parameter(Mandatory)][bool]$AuthorityKeyPresent
    )
    $authorityKeyExists = Test-Path -LiteralPath $StatePaths.AuthorityKey -PathType Leaf
    if ($authorityKeyExists -ne $AuthorityKeyPresent) {
        throw 'The Guard authority file no longer matches the unmutated transaction snapshot.'
    }
    if ($AuthorityKeyPresent) {
        Set-ExactFileSystemAcl -Path $StatePaths.AuthorityKey -OwnerSid $GuardSid -Entries @((New-AclEntry -Sid $GuardSid -Rights ([Security.AccessControl.FileSystemRights]::FullControl)))
    }
    foreach ($privateRoot in Get-StatePrivateRoots -StatePaths $StatePaths) {
        Protect-PrivateServiceTree -Path $privateRoot -GuardSid $GuardSid
    }
}

function Recover-UnmutatedGuardTransaction {
    param([Parameter(Mandatory)]$TransactionRecord)
    $transaction = $TransactionRecord.Document
    $snapshot = Get-ServiceSnapshot
    if ($null -eq $snapshot -or
        -not $snapshot.PathName.Equals([string]$transaction.service_path_name, [StringComparison]::OrdinalIgnoreCase) -or
        -not $snapshot.StatePaths.StateDb.Equals($TransactionRecord.StatePaths.StateDb, [StringComparison]::OrdinalIgnoreCase) -or
        -not $snapshot.StatePaths.SocketName.Equals($TransactionRecord.StatePaths.SocketName, [StringComparison]::OrdinalIgnoreCase) -or
        -not $snapshot.BinaryHash.Equals([string]$transaction.binary_sha256, [StringComparison]::OrdinalIgnoreCase) -or
        $snapshot.BinaryVersion -ne $transaction.binary_version) {
        throw 'Unmutated Guard transaction no longer matches the recorded deployment.'
    }
    Restore-SnapshotPrivateServiceAcls -StatePaths $TransactionRecord.StatePaths -GuardSid (Get-GuardSid) -AuthorityKeyPresent ([bool]$transaction.authority_key_present)
    if ([bool]$transaction.was_running) {
        Set-GuardServiceConfiguration -PathName $snapshot.PathName -StartMode 'Manual'
        Start-GuardService -Name $ServiceName
        Verify-GuardService -ExpectedHash $transaction.binary_sha256 -ExpectedVersion $transaction.binary_version -ExpectedStateDb $TransactionRecord.StatePaths.StateDb -ExpectedSocket $TransactionRecord.StatePaths.SocketName
    }
    else {
        Wait-ServiceStopped -Name $ServiceName
    }
    Set-GuardServiceConfiguration -PathName $snapshot.PathName -StartMode $transaction.start_mode
}

function Wait-GuardServiceAbsent {
    $deadline = (Get-Date).AddSeconds(30)
    do {
        if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { return }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    throw 'The interrupted new Guard service remains after deletion.'
}

function Remove-InterruptedNewInstallationService {
    param([Parameter(Mandatory)]$Transaction)
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) { return }
    if ($Transaction.phase -ne 'mutating') {
        throw 'A Guard service appeared during a staging-only new-installation transaction.'
    }
    $config = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if ($null -eq $config -or
        -not ([string]$config.StartName).Equals([string]$Transaction.service_account, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([string]$config.PathName).Equals([string]$Transaction.service_path_name, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The Guard service does not match the interrupted new-installation transaction.'
    }
    Wait-ServiceStopped -Name $ServiceName
    & sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -notin @(0, 1072)) { throw 'Could not remove the interrupted new Guard service.' }
    Wait-GuardServiceAbsent
}

function Clear-NewInstallationMaintenanceArtifacts {
    if (-not (Test-Path -LiteralPath $MaintenanceRoot -PathType Container)) {
        throw 'New-installation transaction maintenance root is missing.'
    }
    Assert-NoReparsePoint -Path $MaintenanceRoot
    Assert-ExactFileSystemAcl -Path $MaintenanceRoot -OwnerSid $SidAdmins -Entries (Get-AdministrativeAclEntries)
    foreach ($item in @(Get-ChildItem -LiteralPath $MaintenanceRoot -Force)) {
        if ($item.FullName.Equals([IO.Path]::GetFullPath($TransactionJournal), [StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        Remove-GuardOwnedTree -Path $item.FullName
    }
    $remaining = @(Get-ChildItem -LiteralPath $MaintenanceRoot -Force)
    if ($remaining.Count -ne 1 -or
        -not $remaining[0].FullName.Equals([IO.Path]::GetFullPath($TransactionJournal), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'New-installation maintenance cleanup did not retain exactly the transaction journal.'
    }
}

function Recover-GuardTransaction {
    $transactionRecord = Read-GuardTransactionJournal
    if ($null -eq $transactionRecord) { return }
    if ($transactionRecord.Document.deployment_absent -eq $true) {
        Remove-InterruptedNewInstallationService -Transaction $transactionRecord.Document
        if ($transactionRecord.Document.phase -eq 'staging') {
            foreach ($path in @($InstallRoot, $ConfigRoot, $DataDir)) {
                if (Test-Path -LiteralPath $path) {
                    throw "Staging-only new-installation transaction does not own deployment state at '$path'."
                }
            }
        }
        else {
            foreach ($path in @($InstallRoot, $ConfigRoot, $DataDir)) {
                Remove-GuardOwnedTree -Path $path
            }
        }
        Clear-NewInstallationMaintenanceArtifacts
        Complete-GuardTransaction
        Remove-GuardOwnedTree -Path $MaintenanceRoot
        return
    }
    if ($transactionRecord.Document.phase -eq 'verified') {
        $snapshot = Get-ServiceSnapshot
        if ($null -eq $snapshot -or
            -not $snapshot.PathName.Equals([string]$transactionRecord.Document.completed_service_path_name, [StringComparison]::OrdinalIgnoreCase) -or
            -not $snapshot.StatePaths.StateDb.Equals($transactionRecord.CompletedStatePaths.StateDb, [StringComparison]::OrdinalIgnoreCase) -or
            -not $snapshot.StatePaths.SocketName.Equals($transactionRecord.CompletedStatePaths.SocketName, [StringComparison]::OrdinalIgnoreCase) -or
            -not $snapshot.BinaryHash.Equals([string]$transactionRecord.Document.completed_binary_sha256, [StringComparison]::OrdinalIgnoreCase) -or
            $snapshot.BinaryVersion -ne $transactionRecord.Document.completed_binary_version -or
            $snapshot.AuthorityKeyPresent -ne [bool]$transactionRecord.Document.completed_authority_key_present) {
            throw 'Verified Guard transaction no longer matches the completed deployment.'
        }
        if ([bool]$transactionRecord.Document.completed_was_running) {
            Set-GuardServiceConfiguration -PathName $snapshot.PathName -StartMode 'Manual'
            Start-GuardService -Name $ServiceName
            Verify-GuardService -ExpectedHash $transactionRecord.Document.completed_binary_sha256 -ExpectedVersion $transactionRecord.Document.completed_binary_version -ExpectedStateDb $transactionRecord.CompletedStatePaths.StateDb -ExpectedSocket $transactionRecord.CompletedStatePaths.SocketName
        }
        else {
            Wait-ServiceStopped -Name $ServiceName
        }
        Set-GuardServiceConfiguration -PathName $snapshot.PathName -StartMode $transactionRecord.Document.completed_start_mode
        Assert-DeploymentAcls -GuardSid (Get-GuardSid) -StatePaths $transactionRecord.CompletedStatePaths -AuthorityKeyPresent ([bool]$transactionRecord.Document.completed_authority_key_present)
    }
    elseif ($transactionRecord.Document.phase -eq 'mutating') {
        $backup = Read-ValidatedGuardBackup -Name ([string]$transactionRecord.Document.backup_name)
        Restore-GuardInstallation -BackupRecord $backup -GuardSid (Get-GuardSid)
    }
    else {
        Recover-UnmutatedGuardTransaction -TransactionRecord $transactionRecord
    }
    Complete-GuardTransaction
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
    param([Parameter(Mandatory)]$StatePaths)
    return $StatePaths.ApiRevertRoot
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
        [Parameter(Mandatory)][string]$GuardSid,
        [Parameter(Mandatory)]$StatePaths
    )
    $sourceRoot = Get-ApiRevertRoot -StatePaths $StatePaths
    if (-not (Test-Path -LiteralPath $sourceRoot -PathType Container)) { return @() }
    Reset-TreeForAdministrativeMaintenance -Path $sourceRoot -AdditionalRoots @(Get-StateDirectory -StatePaths $StatePaths)
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
    $statePaths = Assert-GuardSnapshotStatePaths -Snapshot $Snapshot
    if ($Snapshot.PSObject.Properties.Name -notcontains 'AuthorityKeyPresent' -or
        $Snapshot.AuthorityKeyPresent -isnot [bool]) {
        throw 'Guard service snapshot authority presence is invalid.'
    }
    $backupEnvironment = Normalize-KubeEnvironmentAuthority -Environment $Snapshot.Environment -StatePaths $statePaths
    $name = "before-v$BeforeVersion-$(Get-Date -Format 'yyyyMMddTHHmmssZ')-$([guid]::NewGuid().ToString('N'))"
    $path = Join-Path $BackupRoot $name
    New-Item -ItemType Directory -Path $path | Out-Null
    $files = @()
    $files += Copy-BackupFile -Source $DeployedExe -BackupPath $path -RelativePath 'guard.exe'
    $operatorScriptPresent = Test-Path -LiteralPath $DeployedOperatorScript -PathType Leaf
    if ($operatorScriptPresent) {
        $files += Copy-BackupFile -Source $DeployedOperatorScript -BackupPath $path -RelativePath 'guard-operator.ps1'
    }
    if ($Snapshot.CatalogPresent) {
        $files += Copy-BackupFile -Source $VerbsPath -BackupPath $path -RelativePath 'config/verbs.yaml'
    }
    foreach ($databaseFile in Get-DatabasePaths -Database $statePaths.StateDb) {
        if (Test-Path -LiteralPath $databaseFile -PathType Leaf) {
            $suffix = $databaseFile.Substring($statePaths.StateDb.Length)
            $files += Copy-BackupFile -Source $databaseFile -BackupPath $path -RelativePath "sqlite/state.db$suffix"
        }
    }
    $authorityKeyPresent = Test-Path -LiteralPath $statePaths.AuthorityKey -PathType Leaf
    if ($authorityKeyPresent -ne [bool]$Snapshot.AuthorityKeyPresent) {
        throw 'The quiesced Guard authority file no longer matches the service snapshot.'
    }
    if ($authorityKeyPresent) {
        Assert-ExactFileSystemAcl -Path $statePaths.AuthorityKey -OwnerSid $GuardSid -Entries @((New-AclEntry -Sid $GuardSid -Rights ([Security.AccessControl.FileSystemRights]::FullControl)))
        Reset-TreeForAdministrativeMaintenance -Path $statePaths.AuthorityKey -AdditionalRoots @(Get-StateDirectory -StatePaths $statePaths)
        try {
            $files += Copy-BackupFile -Source $statePaths.AuthorityKey -BackupPath $path -RelativePath 'authority.hmac'
        }
        finally {
            Set-ExactFileSystemAcl -Path $statePaths.AuthorityKey -OwnerSid $GuardSid -Entries @((New-AclEntry -Sid $GuardSid -Rights ([Security.AccessControl.FileSystemRights]::FullControl)))
        }
    }
    $apiRevertsPresent = Test-Path -LiteralPath (Get-ApiRevertRoot -StatePaths $statePaths) -PathType Container
    if ($apiRevertsPresent) {
        $files += Copy-ApiRevertBackup -BackupPath $path -GuardSid $GuardSid -StatePaths $statePaths
    }
    $activeKubeConfig = Get-ActiveKubeConfigPath -Environment $backupEnvironment -StatePaths $statePaths
    $kubeAuthorityPresent = $null -ne $activeKubeConfig
    if ($kubeAuthorityPresent) {
        if (-not (Test-Path -LiteralPath $activeKubeConfig -PathType Leaf)) {
            throw 'The active Guard kube authority file is missing.'
        }
        Assert-NoReparsePoint -Path (Split-Path -Parent $activeKubeConfig)
        Assert-NoReparsePoint -Path $activeKubeConfig
        $files += Copy-BackupFile -Source $activeKubeConfig -BackupPath $path -RelativePath 'config/kube/config'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $path 'sqlite\state.db') -PathType Leaf)) {
        throw 'The quiesced Guard state database is missing; refusing to create an incomplete rollback backup.'
    }
    $environmentPath = Join-Path $path 'service-environment.dpapi'
    Protect-LocalMachineText -Value ($backupEnvironment | ConvertTo-Json -Compress) -Path $environmentPath
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
        state_database = $statePaths.StateDb
        socket_name = $statePaths.SocketName
        authority_key = $statePaths.AuthorityKey
        authority_key_present = [bool]$authorityKeyPresent
        api_revert_root = $statePaths.ApiRevertRoot
        catalog_path = $VerbsPath
        binary_version = $Snapshot.BinaryVersion
        binary_sha256 = $Snapshot.BinaryHash.ToLowerInvariant()
        operator_script_present = [bool]$operatorScriptPresent
        catalog_present = [bool]$Snapshot.CatalogPresent
        start_mode = $Snapshot.StartMode
        was_running = [bool]$Snapshot.WasRunning
        service_path_name = $Snapshot.PathName
        api_reverts_present = [bool]$apiRevertsPresent
        kube_authority_present = [bool]$kubeAuthorityPresent
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
    $backupSchema = $metadata.metadata_schema
    if ($metadata.format -ne 'guard-windows-backup' -or
        $backupSchema -notin @(2, 3, 4, $BackupMetadataSchema) -or
        $metadata.service_name -ne $ServiceName -or
        $metadata.service_account -ne $ServiceAccount -or
        $metadata.installed_path -ne $DeployedExe -or
        $metadata.catalog_path -ne $VerbsPath -or
        $metadata.binary_version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or
        $metadata.binary_sha256 -notmatch '^[0-9a-f]{64}$' -or
        $metadata.start_mode -notin @('Auto', 'Manual', 'Disabled')) {
        throw 'Backup metadata does not match this Guard installation.'
    }
    $statePaths = Get-GuardStatePaths -ServicePathName ([string]$metadata.service_path_name)
    if ($backupSchema -eq 2) {
        foreach ($property in @('socket_name', 'authority_key', 'authority_key_present', 'api_revert_root', 'kube_authority_present')) {
            if ($metadata.PSObject.Properties.Name -contains $property) {
                throw 'Legacy backup metadata contains fields outside its schema.'
            }
        }
        $metadata | Add-Member -NotePropertyName socket_name -NotePropertyValue $statePaths.SocketName
        $metadata | Add-Member -NotePropertyName authority_key -NotePropertyValue $statePaths.AuthorityKey
        $metadata | Add-Member -NotePropertyName api_revert_root -NotePropertyValue $statePaths.ApiRevertRoot
    }
    $hasSocketName = $metadata.PSObject.Properties.Name -contains 'socket_name'
    if (($backupSchema -ge 4 -and -not $hasSocketName) -or
        $metadata.PSObject.Properties.Name -notcontains 'authority_key' -or
        $metadata.PSObject.Properties.Name -notcontains 'api_revert_root' -or
        -not ([string]$metadata.state_database).Equals($statePaths.StateDb, [StringComparison]::OrdinalIgnoreCase) -or
        ($hasSocketName -and -not ([string]$metadata.socket_name).Equals($statePaths.SocketName, [StringComparison]::OrdinalIgnoreCase)) -or
        -not ([string]$metadata.authority_key).Equals($statePaths.AuthorityKey, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([string]$metadata.api_revert_root).Equals($statePaths.ApiRevertRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Backup state path metadata does not match its service command line.'
    }
    if ($metadata.api_reverts_present -isnot [bool]) {
        throw 'Backup API revert metadata is invalid.'
    }
    $authorityKeyPresent = $false
    if ($backupSchema -eq $BackupMetadataSchema) {
        if ($metadata.PSObject.Properties.Name -notcontains 'authority_key_present' -or
            $metadata.authority_key_present -isnot [bool]) {
            throw 'Backup authority presence metadata is invalid.'
        }
        $authorityKeyPresent = [bool]$metadata.authority_key_present
    }
    else {
        $authorityKeyPresent = $backupSchema -ge 3
        if ($metadata.PSObject.Properties.Name -contains 'authority_key_present') {
            $metadata.authority_key_present = $authorityKeyPresent
        }
        else {
            $metadata | Add-Member -NotePropertyName authority_key_present -NotePropertyValue $authorityKeyPresent
        }
    }
    $kubeAuthorityPresent = $false
    if ($backupSchema -eq $BackupMetadataSchema) {
        if ($metadata.PSObject.Properties.Name -notcontains 'kube_authority_present' -or
            $metadata.kube_authority_present -isnot [bool]) {
            throw 'Backup kube authority metadata is invalid.'
        }
        $kubeAuthorityPresent = [bool]$metadata.kube_authority_present
    }
    else {
        if ($metadata.PSObject.Properties.Name -contains 'kube_authority_present') {
            $metadata.kube_authority_present = $false
        }
        else {
            $metadata | Add-Member -NotePropertyName kube_authority_present -NotePropertyValue $false
        }
    }
    $operatorScriptPresent = $false
    if ($metadata.PSObject.Properties.Name -contains 'operator_script_present') {
        if ($metadata.operator_script_present -isnot [bool]) {
            throw 'Backup operator script metadata is invalid.'
        }
        $operatorScriptPresent = [bool]$metadata.operator_script_present
    }
    else {
        $metadata | Add-Member -NotePropertyName operator_script_present -NotePropertyValue $false
    }
    $allowedFiles = @(
        'guard.exe', 'guard-operator.ps1', 'config/verbs.yaml', 'service-environment.dpapi', 'authority.hmac',
        'config/kube/config',
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
    if ($authorityKeyPresent -ne $seen.ContainsKey('authority.hmac')) {
        throw 'Backup authority presence metadata is inconsistent.'
    }
    if ([bool]$metadata.catalog_present -ne $seen.ContainsKey('config/verbs.yaml')) {
        throw 'Backup catalog metadata is inconsistent.'
    }
    if ($operatorScriptPresent -ne $seen.ContainsKey('guard-operator.ps1')) {
        throw 'Backup operator script metadata is inconsistent.'
    }
    if ($kubeAuthorityPresent -ne $seen.ContainsKey('config/kube/config')) {
        throw 'Backup kube authority metadata is inconsistent.'
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
    if (-not $kubeAuthorityPresent -and $environment.ContainsKey('KUBECONFIG')) {
        if ($backupSchema -lt $BackupMetadataSchema) {
            throw 'Legacy backup references Kubernetes authority that its schema did not capture.'
        }
        throw 'Backup environment references Kubernetes authority that the backup records as absent.'
    }
    return [pscustomobject]@{ Name = $Name; Path = $path; Metadata = $metadata; Environment = $environment; StatePaths = $statePaths }
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

function Get-AtomicReplacementPaths {
    param([Parameter(Mandatory)][string]$Destination)
    $destinationDirectory = Split-Path -Parent $Destination
    $identifier = [guid]::NewGuid().ToString('N')
    return [pscustomobject]@{
        Staged = Join-Path $destinationDirectory ".guard-replace-$identifier.tmp"
        Replaced = Join-Path $destinationDirectory ".guard-replaced-$identifier.tmp"
    }
}

function Install-FileAtomically {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$ExpectedHash
    )
    $destinationDirectory = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $destinationDirectory -PathType Container)) {
        throw "Atomic replacement destination directory does not exist: '$destinationDirectory'."
    }
    Assert-NoReparsePoint -Path $destinationDirectory
    $replacementPaths = Get-AtomicReplacementPaths -Destination $Destination
    $staged = $replacementPaths.Staged
    $replaced = $replacementPaths.Replaced
    try {
        Copy-Item -LiteralPath $Source -Destination $staged
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $staged).Hash.ToLowerInvariant() -ne $ExpectedHash.ToLowerInvariant()) {
            throw "Staged file for '$Destination' failed integrity validation."
        }
        if (Test-Path -LiteralPath $Destination) {
            Assert-NoReparsePoint -Path $Destination
            Set-Acl -LiteralPath $staged -AclObject (Get-Acl -LiteralPath $Destination)
            [IO.File]::Replace($staged, $Destination, $replaced)
            Remove-Item -LiteralPath $replaced -Force -ErrorAction Stop
        }
        else {
            Set-Acl -LiteralPath $staged -AclObject (Get-Acl -LiteralPath (Split-Path -Parent $Destination))
            Move-Item -LiteralPath $staged -Destination $Destination
        }
    }
    finally {
        foreach ($temporaryPath in @($staged, $replaced)) {
            if (Test-Path -LiteralPath $temporaryPath) {
                Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
            }
        }
    }
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
        [Parameter(Mandatory)][string]$ExpectedVersion,
        [Parameter(Mandatory)][string]$ExpectedStateDb,
        [Parameter(Mandatory)][string]$ExpectedSocket
    )
    $ExpectedSocket = Assert-CanonicalSocketName -Socket $ExpectedSocket
    $deadline = (Get-Date).AddSeconds($ServiceReadinessTimeoutSeconds)
    $statusDocument = $null
    do {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
            try {
                $statusResult = Invoke-GuardAsOperator -Arguments @('status', '--socket', $ExpectedSocket, '--json') -GuardExe $DeployedExe -JsonOutput
                if ($statusResult.ExitCode -eq 0) {
                    $statusDocument = $statusResult.Output | ConvertFrom-Json
                }
            }
            catch {
                $statusDocument = $null
            }
        }
        if (-not $statusDocument) { Start-Sleep -Milliseconds 400 }
    } while (-not $statusDocument -and (Get-Date) -lt $deadline)
    if (-not $statusDocument) { throw 'Guard did not complete a status handshake before the readiness deadline.' }
    Assert-GuardStatusDocument -StatusDocument $statusDocument -ExpectedVersion $ExpectedVersion -ExpectedStateDb $ExpectedStateDb -ExpectedSocket $ExpectedSocket
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

function Assert-GuardStatusDocument {
    param(
        [Parameter(Mandatory)]$StatusDocument,
        [Parameter(Mandatory)][string]$ExpectedVersion,
        [Parameter(Mandatory)][string]$ExpectedStateDb,
        [Parameter(Mandatory)][string]$ExpectedSocket
    )
    $ExpectedSocket = Assert-CanonicalSocketName -Socket $ExpectedSocket
    if ($statusDocument.type -ne 'status' -or $statusDocument.server.version_mismatch -or
        $statusDocument.client.version -ne $statusDocument.server.version -or
        $statusDocument.server.version -ne $ExpectedVersion) {
        throw 'Guard status returned an unexpected client/server version document.'
    }
    if ($statusDocument.server.full_restricted -ne $false -or $null -eq $statusDocument.server.full -or
        [string]::IsNullOrWhiteSpace([string]$statusDocument.server.full.state_db_path) -or
        -not ([string]$statusDocument.server.full.state_db_path).Equals($ExpectedStateDb, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([string]$statusDocument.server.full.socket_path).Equals($ExpectedSocket, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Guard status did not report the state database and socket selected by the service command line.'
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
        [Parameter(Mandatory)][string]$GuardSid,
        [Parameter(Mandatory)]$StatePaths
    )
    $destinationRoot = Get-ApiRevertRoot -StatePaths $StatePaths
    if (Test-Path -LiteralPath $destinationRoot) {
        Reset-TreeForAdministrativeMaintenance -Path $destinationRoot -AdditionalRoots @(Get-StateDirectory -StatePaths $StatePaths)
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
        [Parameter(Mandatory)][string]$GuardSid,
        [Parameter(Mandatory)][bool]$AuthorityKeyPresent
    )
    $statePaths = Get-GuardStatePaths -ServicePathName ([string]$Metadata.service_path_name)
    $serviceEnvironment = Convert-LegacyKubeEnvironment -Environment $Environment -StatePaths $statePaths
    $serviceEnvironment = Complete-ManagedKubeEnvironment -Environment $serviceEnvironment
    Set-GuardServiceConfiguration -PathName ([string]$Metadata.service_path_name) -StartMode 'Manual'
    Set-ServiceEnvironment -Environment $serviceEnvironment -GuardSid $GuardSid
    Set-DeploymentAcls -GuardSid $GuardSid -StatePaths $statePaths
    Start-GuardService -Name $ServiceName
    Verify-GuardService -ExpectedHash $Metadata.binary_sha256 -ExpectedVersion $Metadata.binary_version -ExpectedStateDb $statePaths.StateDb -ExpectedSocket $statePaths.SocketName
    Assert-DeploymentAcls -GuardSid $GuardSid -StatePaths $statePaths -AuthorityKeyPresent $AuthorityKeyPresent
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
    $statePaths = Get-GuardStatePaths -ServicePathName ([string]$metadata.service_path_name)
    if ($BackupRecord.PSObject.Properties.Name -contains 'StatePaths' -and $null -ne $BackupRecord.StatePaths -and
        (-not ([string]$BackupRecord.StatePaths.StateDb).Equals($statePaths.StateDb, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([string]$BackupRecord.StatePaths.AuthorityKey).Equals($statePaths.AuthorityKey, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([string]$BackupRecord.StatePaths.ApiRevertRoot).Equals($statePaths.ApiRevertRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([string]$BackupRecord.StatePaths.SocketName).Equals($statePaths.SocketName, [StringComparison]::OrdinalIgnoreCase))) {
        throw 'Backup record state paths do not match its service command line.'
    }
    Set-DeploymentAcls -GuardSid $GuardSid -StatePaths $statePaths
    if ([bool]$metadata.kube_authority_present) {
        $kubeAuthorityEntry = @($metadata.files | Where-Object path -eq 'config/kube/config')
        if ($kubeAuthorityEntry.Count -ne 1) { throw 'Backup is missing kube authority.' }
        Install-FileAtomically -Source (Join-Path $BackupRecord.Path 'config\kube\config') -Destination $KubeConfig -ExpectedHash $kubeAuthorityEntry[0].sha256
    }
    elseif (Test-Path -LiteralPath $KubeConfig) {
        Assert-NoReparsePoint -Path $KubeDir
        Assert-NoReparsePoint -Path $KubeConfig
        Remove-Item -LiteralPath $KubeConfig -Force
        if (Test-Path -LiteralPath $KubeConfig) {
            throw 'Managed kube authority remains after restoring a backup that records its absence.'
        }
    }
    $binarySource = Join-Path $BackupRecord.Path 'guard.exe'
    Install-FileAtomically -Source $binarySource -Destination $DeployedExe -ExpectedHash $metadata.binary_sha256
    if ([bool]$metadata.operator_script_present) {
        $operatorScriptEntry = @($metadata.files | Where-Object path -eq 'guard-operator.ps1')[0]
        Install-FileAtomically -Source (Join-Path $BackupRecord.Path 'guard-operator.ps1') -Destination $DeployedOperatorScript -ExpectedHash $operatorScriptEntry.sha256
    }
    elseif (Test-Path -LiteralPath $DeployedOperatorScript) {
        Remove-Item -LiteralPath $DeployedOperatorScript -Force
    }

    foreach ($databaseFile in Get-DatabasePaths -Database $statePaths.StateDb) {
        if (Test-Path -LiteralPath $databaseFile) { Remove-Item -LiteralPath $databaseFile -Force }
    }
    foreach ($name in @('state.db', 'state.db-wal', 'state.db-shm', 'state.db-journal')) {
        $relative = "sqlite/$name"
        $entry = @($metadata.files | Where-Object path -eq $relative)
        if ($entry.Count -eq 1) {
            $suffix = $name.Substring('state.db'.Length)
            Install-FileAtomically -Source (Join-Path $BackupRecord.Path "sqlite\$name") -Destination "$($statePaths.StateDb)$suffix" -ExpectedHash $entry[0].sha256
        }
    }
    if ([bool]$metadata.authority_key_present) {
        $authorityKeyEntry = @($metadata.files | Where-Object path -eq 'authority.hmac')
        if ($authorityKeyEntry.Count -ne 1) { throw 'Backup is missing the Guard authority file.' }
        if (Test-Path -LiteralPath $statePaths.AuthorityKey) {
            Reset-TreeForAdministrativeMaintenance -Path $statePaths.AuthorityKey -AdditionalRoots @(Get-StateDirectory -StatePaths $statePaths)
        }
        Install-FileAtomically -Source (Join-Path $BackupRecord.Path 'authority.hmac') -Destination $statePaths.AuthorityKey -ExpectedHash $authorityKeyEntry[0].sha256
        Set-ExactFileSystemAcl -Path $statePaths.AuthorityKey -OwnerSid $GuardSid -Entries @((New-AclEntry -Sid $GuardSid -Rights ([Security.AccessControl.FileSystemRights]::FullControl)))
    }
    elseif (Test-Path -LiteralPath $statePaths.AuthorityKey) {
        Reset-TreeForAdministrativeMaintenance -Path $statePaths.AuthorityKey -AdditionalRoots @(Get-StateDirectory -StatePaths $statePaths)
        Remove-Item -LiteralPath $statePaths.AuthorityKey -Force
        if (Test-Path -LiteralPath $statePaths.AuthorityKey) {
            throw 'The Guard authority file remains after restoring a backup that records its absence.'
        }
    }
    Restore-ApiRevertBackup -BackupRecord $BackupRecord -GuardSid $GuardSid -StatePaths $statePaths
    if ([bool]$metadata.catalog_present) {
        $catalogEntry = @($metadata.files | Where-Object path -eq 'config/verbs.yaml')[0]
        Install-FileAtomically -Source (Join-Path $BackupRecord.Path 'config\verbs.yaml') -Destination $VerbsPath -ExpectedHash $catalogEntry.sha256
    }
    elseif (Test-Path -LiteralPath $VerbsPath) {
        Remove-Item -LiteralPath $VerbsPath -Force
    }

    # Verification needs a startable service even when the durable target mode
    # is Disabled. The final transition restores the exact durable mode.
    Complete-RestoredServiceVerification -Metadata $metadata -Environment $BackupRecord.Environment -GuardSid $GuardSid -AuthorityKeyPresent ([bool]$metadata.authority_key_present)
}

function Assert-NewInstallationRootsAbsent {
    foreach ($path in @($InstallRoot, $ConfigRoot, $DataDir, $MaintenanceRoot)) {
        if (Test-Path -LiteralPath $path) {
            throw "Guard service is absent but deployment state exists at '$path'; recover or remove the complete deployment before installation."
        }
    }
}

function Remove-CompletedNewInstallationMaintenanceRoot {
    if (-not (Test-Path -LiteralPath $MaintenanceRoot -PathType Container) -or
        (Test-Path -LiteralPath $TransactionJournal)) {
        return
    }
    foreach ($path in @($InstallRoot, $ConfigRoot, $DataDir)) {
        if (Test-Path -LiteralPath $path) { return }
    }
    Assert-NoReparsePoint -Path $MaintenanceRoot
    Assert-ExactFileSystemAcl -Path $MaintenanceRoot -OwnerSid $SidAdmins -Entries (Get-AdministrativeAclEntries)
    $allowedEmptyDirectories = @(
        [IO.Path]::GetFullPath($StagingDir),
        [IO.Path]::GetFullPath($BackupRoot),
        [IO.Path]::GetFullPath($TaskOutDir)
    )
    foreach ($item in @(Get-ChildItem -LiteralPath $MaintenanceRoot -Force)) {
        Assert-NoReparsePoint -Path $item.FullName
        $itemPath = [IO.Path]::GetFullPath($item.FullName)
        $pathAllowed = @($allowedEmptyDirectories | Where-Object {
            $_.Equals($itemPath, [StringComparison]::OrdinalIgnoreCase)
        }).Count -eq 1
        if (-not $item.PSIsContainer -or
            -not $pathAllowed -or
            @(Get-ChildItem -LiteralPath $item.FullName -Force).Count -ne 0) {
            return
        }
        Assert-ExactFileSystemAcl -Path $item.FullName -OwnerSid $SidAdmins -Entries (Get-AdministrativeAclEntries)
    }
    Remove-GuardOwnedTree -Path $MaintenanceRoot
}

function Invoke-Install {
    Assert-Admin -ForAction 'install'
    Recover-GuardTransaction
    $installRepoRoot = Resolve-InstallRepoRoot
    $sourceExe = Resolve-GuardExe -InstallRepoRoot $installRepoRoot
    $operatorScriptSource = (Resolve-Path -LiteralPath $PSCommandPath).Path
    Assert-NoReparsePoint -Path $operatorScriptSource
    $operatorScriptHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $operatorScriptSource).Hash.ToLowerInvariant()
    $expectedHash = Assert-ExpectedCandidateHash
    $serviceBeforeInstall = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $transaction = $null
    if (-not $serviceBeforeInstall) {
        Remove-CompletedNewInstallationMaintenanceRoot
        Assert-NewInstallationRootsAbsent
        $transaction = Start-NewInstallationTransaction
    }
    try {
        $candidate = Stage-VerifiedGuardCandidate -SourceExe $sourceExe -ExpectedHash $expectedHash
    }
    catch {
        if ($null -ne $transaction) { Recover-GuardTransaction }
        throw
    }
    $stagedExe = $candidate.Path
    $expectedVersion = $candidate.Version

    try {
        $snapshot = Get-ServiceSnapshot
        if ($null -ne $transaction -and $null -ne $snapshot) {
            throw 'Guard service appeared after the new-installation transaction recorded an absent deployment.'
        }
        if ($null -eq $transaction -and $null -eq $snapshot) {
            throw 'Guard service disappeared before the existing installation could be snapshotted.'
        }
        if (-not $snapshot -and (Test-Path -LiteralPath $DeployedExe)) {
            throw "Installed binary '$DeployedExe' exists without the Guard service; remove or recover it before installation."
        }
        if ($snapshot) {
            Assert-CandidateStateCompatibility -GuardExe $stagedExe -StateDb $snapshot.StatePaths.StateDb
        }
        $existingEnvironment = if ($snapshot) { $snapshot.Environment } else { @{} }
        $serviceEnvironment = Merge-ServiceEnvironment -Existing $existingEnvironment -Imported (Import-LlmEnvironment -Path $EnvFile)
        $haveKey = $serviceEnvironment.ContainsKey('GUARD_LLM_API_KEY') -or $serviceEnvironment.ContainsKey('OPENROUTER_API_KEY')
        $sourceVerbs = if ($installRepoRoot) { Join-Path $installRepoRoot 'examples\verbs-kubectl.yaml' } else { $null }
        $haveSourceVerbs = $sourceVerbs -and (Test-Path -LiteralPath $sourceVerbs)
        $haveVerbs = (Test-Path -LiteralPath $VerbsPath) -or $haveSourceVerbs
        $stockBinPath = Get-ServiceBinPath -HaveKey $haveKey -HaveVerbs $haveVerbs
        $existingPath = if ($snapshot) { $snapshot.PathName } else { $null }
        $serviceBinPath = Resolve-InstallServicePath -ExistingPath $existingPath -DesiredPath $stockBinPath
    }
    catch {
        $preflightError = $_
        if (Test-Path -LiteralPath $stagedExe) { Remove-Item -LiteralPath $stagedExe -Force }
        if ($null -ne $transaction) {
            try { Recover-GuardTransaction }
            catch {
                throw "Installation preflight failed: $($preflightError.Exception.Message) New-installation recovery also failed: $($_.Exception.Message)"
            }
        }
        throw $preflightError
    }
    $createdService = $false
    $backupName = $null
    $guardSid = $null
    try {
        if (-not $snapshot) {
            Set-NewInstallationTransactionMutating -Transaction $transaction -ServicePathName $stockBinPath
            & sc.exe create $ServiceName binPath= $stockBinPath start= auto obj= $ServiceAccount DisplayName= 'Guard consequence gate' | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not create the Guard service.' }
            $createdService = $true
            & sc.exe sidtype $ServiceName unrestricted | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not enable the Guard service SID.' }
        }
        $guardSid = Get-GuardSid
        if ($snapshot) {
            $transaction = Start-GuardTransaction -Operation install -Snapshot $snapshot
            Wait-ServiceStopped -Name $ServiceName
            $backupName = New-GuardBackup -Snapshot $snapshot -BeforeVersion $snapshot.BinaryVersion -GuardSid $guardSid
            Set-GuardTransactionPhase -Transaction $transaction -Phase prepared -BackupName $backupName
            Set-GuardTransactionPhase -Transaction $transaction -Phase mutating -BackupName $backupName
        }
        Set-DeploymentAcls -GuardSid $guardSid -StatePaths $(if ($snapshot) { $snapshot.StatePaths } else { $null })
        Set-ServiceRegistryAcl -GuardSid $guardSid
        if ($snapshot) {
            Set-GuardServiceConfiguration -PathName $serviceBinPath -StartMode 'Manual'
        }
        Copy-KubeConfigToAuthorityRoot -StatePaths $(if ($snapshot) { $snapshot.StatePaths } else { $null }) -Environment $serviceEnvironment
        $serviceEnvironment = Convert-LegacyKubeEnvironment -Environment $serviceEnvironment -StatePaths $(if ($snapshot) { $snapshot.StatePaths } else { Get-DeploymentStatePaths -StatePaths $null })
        $serviceEnvironment = Complete-ManagedKubeEnvironment -Environment $serviceEnvironment
        Install-FileAtomically -Source $stagedExe -Destination $DeployedExe -ExpectedHash $expectedHash
        Install-FileAtomically -Source $operatorScriptSource -Destination $DeployedOperatorScript -ExpectedHash $operatorScriptHash
        Invoke-InstallerTestFault -Point 'after-binary'
        if (-not (Test-Path -LiteralPath $VerbsPath) -and $haveSourceVerbs) {
            Copy-Item -LiteralPath $sourceVerbs -Destination $VerbsPath
        }
        Set-DeploymentAcls -GuardSid $guardSid -StatePaths $(if ($snapshot) { $snapshot.StatePaths } else { $null })
        Set-ServiceEnvironment -Environment $serviceEnvironment -GuardSid $guardSid
        Invoke-InstallerTestFault -Point 'after-environment'
        if ($createdService) {
            & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not configure Guard service failure recovery.' }
        }
        Start-GuardService -Name $ServiceName
        Invoke-InstallerTestFault -Point 'after-service-start'
        $expectedStatePaths = if ($snapshot) { $snapshot.StatePaths } else { Get-DeploymentStatePaths -StatePaths $null }
        Verify-GuardService -ExpectedHash $expectedHash -ExpectedVersion $expectedVersion -ExpectedStateDb $expectedStatePaths.StateDb -ExpectedSocket $expectedStatePaths.SocketName
        Assert-DeploymentAcls -GuardSid $guardSid -StatePaths $(if ($snapshot) { $snapshot.StatePaths } else { $null })
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $DeployedOperatorScript).Hash.ToLowerInvariant() -ne $operatorScriptHash) {
            throw 'Installed operator script failed integrity validation.'
        }
        if ($snapshot) {
            if (-not $snapshot.WasRunning) { Wait-ServiceStopped -Name $ServiceName }
            Set-GuardServiceConfiguration -PathName $serviceBinPath -StartMode $snapshot.StartMode
            Mark-GuardTransactionVerified -Transaction $transaction -CompletedSnapshot (Get-ServiceSnapshot)
            Complete-GuardTransaction
        }
        else {
            Complete-GuardTransaction
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
            if ($null -ne $transaction) {
                Recover-GuardTransaction
            }
            elseif ($snapshot -and $snapshot.WasRunning) {
                $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                if ($service -and $service.Status -ne 'Running') { Start-GuardService -Name $ServiceName }
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
    Recover-GuardTransaction
    if (-not $Backup) { throw 'Action rollback requires -Backup <backup-name>.' }
    $target = Read-ValidatedGuardBackup -Name $Backup
    $snapshot = Get-ServiceSnapshot
    if (-not $snapshot) { throw 'Guard is not installed.' }
    $guardSid = Get-GuardSid
    $transaction = Start-GuardTransaction -Operation rollback -Snapshot $snapshot
    $safetyName = $null
    try {
        Wait-ServiceStopped -Name $ServiceName
        $safetyName = New-GuardBackup -Snapshot $snapshot -BeforeVersion $snapshot.BinaryVersion -GuardSid $guardSid
        Set-GuardTransactionPhase -Transaction $transaction -Phase prepared -BackupName $safetyName
        Set-GuardTransactionPhase -Transaction $transaction -Phase mutating -BackupName $safetyName
        Restore-GuardInstallation -BackupRecord $target -GuardSid $guardSid
        Mark-GuardTransactionVerified -Transaction $transaction -CompletedSnapshot (Get-ServiceSnapshot)
        Complete-GuardTransaction
        Write-Host "Guard rollback to $($target.Metadata.binary_version) completed and passed the status handshake."
        Write-Host "Rollback safety backup: $safetyName"
    }
    catch {
        $rollbackError = $_
        try {
            Recover-GuardTransaction
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
    $lastError = $null
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            Reset-TreeForAdministrativeMaintenance -Path $Path
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            if (-not (Test-Path -LiteralPath $Path)) { return }
            $lastError = 'path still exists after cleanup'
        }
        catch { $lastError = $_.Exception.Message }
        if ($attempt -lt 3) { Start-Sleep -Milliseconds 200 }
    }
    throw "Guard-owned tree cleanup failed after 3 attempts for '$Path': $lastError"
}

function Invoke-Uninstall {
    Assert-Admin -ForAction 'uninstall'
    Recover-GuardTransaction
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
    $statusMetadata = Get-ServiceStatusMetadata
    Write-Host "Pipe: $($statusMetadata.SocketName)"
    if ($service.Status -eq 'Running' -and (Test-Path -LiteralPath $DeployedExe)) {
        & $DeployedExe status --socket $statusMetadata.SocketName
    }
}

function Invoke-OperatorAction {
    $snapshot = Get-ServiceSnapshot
    if ($null -eq $snapshot) { throw 'Guard service is not installed.' }
    $result = Invoke-GuardAsOperator -Arguments (Get-GuardActionArguments -Socket $snapshot.SocketName) -GuardExe $DeployedExe
    if ($Json) {
        Write-Output $result.Output
        if ($result.ExitCode -ne 0) { exit $result.ExitCode }
    }
    elseif ($result.Output) { Write-Host $result.Output }
}

function New-GuardDeploymentMutex {
    return [Threading.Mutex]::new($false, $DeploymentMutexName)
}

function Invoke-WithGuardDeploymentLock {
    param([Parameter(Mandatory)][scriptblock]$Operation)
    $mutex = New-GuardDeploymentMutex
    $acquired = $false
    try {
        try { $acquired = $mutex.WaitOne(0) }
        catch {
            $waitError = $_.Exception
            $abandoned = $false
            while ($null -ne $waitError) {
                if ($waitError -is [Threading.AbandonedMutexException]) {
                    $abandoned = $true
                    break
                }
                $waitError = $waitError.InnerException
            }
            if (-not $abandoned) { throw }
            $acquired = $true
        }
        if (-not $acquired) { throw 'Another Guard deployment action is active.' }
        & $Operation
    }
    finally {
        if ($acquired) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

if (-not $env:GUARD_INSTALLER_TEST_MODE) {
    switch ($Action) {
        'install' { Invoke-WithGuardDeploymentLock { Invoke-Install } }
        'uninstall' { Invoke-WithGuardDeploymentLock { Invoke-Uninstall } }
        'status' { Invoke-Status }
        'rollback' { Invoke-WithGuardDeploymentLock { Invoke-Rollback } }
        default { Invoke-OperatorAction }
    }
}
