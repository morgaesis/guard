BeforeAll {
    $InstallerTestModeBeforeTests = $env:GUARD_INSTALLER_TEST_MODE
    $env:GUARD_INSTALLER_TEST_MODE = '1'
    $script:TestGuardSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

    function script:New-GuardTestIdentifier {
        return [guid]::NewGuid().ToString('N')
    }

    function script:New-GuardTestDigest {
        return (New-GuardTestIdentifier) + (New-GuardTestIdentifier)
    }

    function script:New-GuardTestGrantReference {
        return "gr-$(New-GuardTestIdentifier)"
    }

    function script:New-GuardTestSessionReference {
        $identifier = New-GuardTestIdentifier
        return "session:$($identifier.Substring(0, 16))"
    }

    function script:New-GuardTestAgentReference {
        $identifier = [guid]::NewGuid().ToByteArray()
        $subAuthorities = @(0, 4, 8, 12 | ForEach-Object {
            [BitConverter]::ToUInt32($identifier, $_)
        })
        $sid = [Security.Principal.SecurityIdentifier]("S-1-5-21-$($subAuthorities -join '-')")
        return "agent:$($sid.Value)"
    }

    function script:New-GuardTestBackupName {
        param([string]$Version = '1.2.3')
        return "before-v$Version-$(Get-Date -Format 'yyyyMMddTHHmmssZ')-$(New-GuardTestIdentifier)"
    }

    function script:New-GuardTestTaskName {
        return "guard-op-$(New-GuardTestIdentifier)"
    }

    function script:New-GuardTestServiceController {
        param(
            [Parameter(Mandatory)][string]$Status,
            [Parameter(Mandatory)][string]$StatusAfterWait
        )
        $controller = [pscustomobject]@{
            Status = $Status
            StatusAfterWait = $StatusAfterWait
            WaitCalls = 0
            RefreshCalls = 0
        }
        $controller | Add-Member -MemberType ScriptMethod -Name WaitForStatus -Value {
            param($DesiredStatus, $Timeout)
            $this.WaitCalls++
            $this.Status = $this.StatusAfterWait
        }
        $controller | Add-Member -MemberType ScriptMethod -Name Refresh -Value {
            $this.RefreshCalls++
        }
        return $controller
    }
}

AfterAll {
    if ($null -eq $InstallerTestModeBeforeTests) {
        Remove-Item Env:GUARD_INSTALLER_TEST_MODE -ErrorAction SilentlyContinue
    }
    else {
        $env:GUARD_INSTALLER_TEST_MODE = $InstallerTestModeBeforeTests
    }
}

Describe 'Guard Windows operator command contract' {
    BeforeEach {
        . (Join-Path $PSScriptRoot 'install-guard.ps1') -Action status
        $Reference = @()
        $ApprovalMode = 'ordinary'
        $Uses = 0
        $Intent = $null
        $Reason = $null
        $Json = $false
        $SessionReference = New-GuardTestSessionReference
    }

    It 'maps ordinary, once, N-use, and batch approvals' {
        $Action = 'access-approve'
        $Reference = @((New-GuardTestGrantReference), (New-GuardTestGrantReference))
        (Get-GuardActionArguments -Socket $SocketName) -join ' ' | Should -Be "access approve $($Reference -join ' ') --socket guard"

        $ApprovalMode = 'once'
        (Get-GuardActionArguments -Socket $SocketName) -join ' ' | Should -Be "access approve $($Reference -join ' ') --once --socket guard"

        $ApprovalMode = 'uses'
        $Uses = 3
        (Get-GuardActionArguments -Socket $SocketName) -join ' ' | Should -Be "access approve $($Reference -join ' ') --uses 3 --socket guard"
    }

    It 'maps deny, extend, revoke, list, show, confirm, and revert' {
        $Action = 'access-deny'
        $Reference = @((New-GuardTestGrantReference))
        $Reason = 'outside the approved task'
        (Get-GuardActionArguments -Socket $SocketName) -join ' ' | Should -Be "access deny $Reference --reason outside the approved task --socket guard"

        $Action = 'access-extend'
        $Reference = @($SessionReference)
        $Intent = 'Inspect service health.'
        $ApprovalMode = 'once'
        (Get-GuardActionArguments -Socket $SocketName) -join ' ' | Should -Be "access extend $SessionReference Inspect service health. --once --socket guard"

        $Action = 'access-revoke'
        $agentReference = New-GuardTestAgentReference
        $Reference = @($agentReference)
        $ApprovalMode = 'ordinary'
        (Get-GuardActionArguments -Socket $SocketName) -join ' ' | Should -Be "access revoke $agentReference --socket guard"

        $Action = 'access-list'
        $Reference = @()
        (Get-GuardActionArguments -Socket $SocketName) -join ' ' | Should -Be 'access list --socket guard'

        $Action = 'access-show'
        foreach ($inspectable in @((New-GuardTestGrantReference), (New-GuardTestIdentifier), $SessionReference)) {
            $Reference = @($inspectable)
            (Get-GuardActionArguments -Socket $SocketName) -join ' ' | Should -Be "access show $inspectable --socket guard"
        }

        foreach ($operatorAction in @('confirm', 'revert')) {
            $Action = $operatorAction
            $Reference = @((New-GuardTestIdentifier))
            (Get-GuardActionArguments -Socket $SocketName) -join ' ' | Should -Be "$operatorAction $Reference --socket guard"
        }
    }

    It 'maps held execution references through access approve and deny' {
        foreach ($operatorAction in @('access-approve', 'access-deny')) {
            $Action = $operatorAction
            $Reference = @((New-GuardTestIdentifier))
            (Get-GuardActionArguments -Socket $SocketName) -join ' ' | Should -Be (($operatorAction -replace '-', ' ') + " $Reference --socket guard")
        }
    }

    It 'rejects malformed references, control characters, and invalid use counts' {
        $Action = 'access-approve'
        $Reference = @('request & whoami')
        { Get-GuardActionArguments -Socket $SocketName } | Should -Throw

        $Action = 'access-extend'
        $Reference = @($SessionReference)
        $Intent = "inspect`nwhoami"
        { Get-GuardActionArguments -Socket $SocketName } | Should -Throw

        $Action = 'access-approve'
        $Reference = @((New-GuardTestGrantReference))
        $ApprovalMode = 'uses'
        $Uses = 0
        { Get-GuardActionArguments -Socket $SocketName } | Should -Throw

        $Action = 'confirm'
        $Reference = @((New-GuardTestGrantReference))
        { Get-GuardActionArguments -Socket $SocketName } | Should -Throw

        $Action = 'access-revoke'
        $agentReference = New-GuardTestAgentReference
        $Reference = @($SessionReference, $agentReference)
        { Get-GuardActionArguments -Socket $SocketName } | Should -Throw
    }

    It 'keeps untrusted prose out of executable task syntax' {
        $Action = 'access-deny'
        $Reference = @((New-GuardTestGrantReference))
        $Reason = 'maintenance & whoami | calc.exe > output'
        $arguments = Get-GuardActionArguments -Socket $SocketName
        $output = Join-Path $TaskOutDir "$(New-GuardTestTaskName).out"
        $payload = New-GuardOperatorPayload -GuardExe $DeployedExe -Arguments $arguments -OutputFile $output
        $decodedPayload = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($payload))

        $decodedPayload | Should -Not -Match ([regex]::Escape($Reason))
        $decodedPayload | Should -Not -Match 'cmd\.exe'
        $decodedPayload | Should -Match ([regex]::Escape((ConvertTo-Base64Utf8 $Reason)))
        $decodedPayload | Should -Match ([regex]::Escape((ConvertTo-Base64Utf8 "$output.status")))
        $decodedPayload | Should -Match '\$nativeStatus = 1'
        $decodedPayload | Should -Match 'finally'
        $decodedPayload | Should -Match 'WriteAllText'
    }

    It 'rejects task executable and output paths outside installer-owned roots' {
        $Action = 'access-list'
        $arguments = Get-GuardActionArguments -Socket $SocketName
        { New-GuardOperatorPayload -GuardExe 'C:\Windows\System32\whoami.exe' -Arguments $arguments -OutputFile (Join-Path $TaskOutDir "$(New-GuardTestTaskName).out") } | Should -Throw
        { New-GuardOperatorPayload -GuardExe $DeployedExe -Arguments $arguments -OutputFile (Join-Path 'C:\Temp' "$(New-GuardTestTaskName).out") } | Should -Throw
    }

    It 'preserves valid JSON for mixed decisions and propagates its native status' {
        $token = New-GuardTestIdentifier
        $body = '{"schema_version":1,"items":[{"success":true},{"success":false}],"message":"token=' + $token + '"}'
        $result = Resolve-GuardOperatorResult -RawOutput $body -NativeStatus 1 -JsonOutput
        $result.Output | Should -Be $body
        $result.ExitCode | Should -Be 1
        ($result.Output | ConvertFrom-Json).items.Count | Should -Be 2
    }

    It 'reads the task-authored native status and rejects malformed status' {
        $status = Join-Path $TestDrive 'operator.status'
        Set-Content -LiteralPath $status -Value '125' -NoNewline
        Read-GuardOperatorStatus -StatusFile $status | Should -Be 125
        Set-Content -LiteralPath $status -Value 'not-a-status' -NoNewline
        { Read-GuardOperatorStatus -StatusFile $status } | Should -Throw '*invalid native status*'
    }

    It 'does not truncate large structured output' {
        $body = '{"schema_version":1,"body":"' + ('x' * 20000) + '"}'
        $result = Resolve-GuardOperatorResult -RawOutput $body -NativeStatus 0 -JsonOutput
        $result.Output.Length | Should -Be $body.Length
        $result.Output | Should -Not -Match 'output truncated'
    }

    It 'rejects malformed structured output without echoing it' {
        $token = New-GuardTestIdentifier
        { Resolve-GuardOperatorResult -RawOutput "{token=$token" -NativeStatus 1 -JsonOutput } |
            Should -Throw '*invalid JSON; native_status=1*'
    }
}

Describe 'Guard Windows installer state and ACL contract' {
    BeforeEach {
        . (Join-Path $PSScriptRoot 'install-guard.ps1') -Action status
    }

    It 'rejects every orphaned deployment root when the service is absent' {
        $saved = @($InstallRoot, $ConfigRoot, $DataDir, $MaintenanceRoot)
        try {
            $InstallRoot = Join-Path $TestDrive 'program'
            $ConfigRoot = Join-Path $TestDrive 'config'
            $DataDir = Join-Path $TestDrive 'data'
            $MaintenanceRoot = Join-Path $TestDrive 'maintenance'
            foreach ($path in @($InstallRoot, $ConfigRoot, $DataDir, $MaintenanceRoot)) {
                New-Item -ItemType Directory -Path $path | Out-Null
                { Assert-NewInstallationRootsAbsent } | Should -Throw '*deployment state exists*'
                Remove-Item -LiteralPath $path -Recurse -Force
            }
            { Assert-NewInstallationRootsAbsent } | Should -Not -Throw
        }
        finally {
            $InstallRoot = $saved[0]
            $ConfigRoot = $saved[1]
            $DataDir = $saved[2]
            $MaintenanceRoot = $saved[3]
        }
    }

    It 'requires a verified release digest before staging' {
        $ExpectedSha256 = $null
        { Assert-ExpectedCandidateHash } | Should -Throw
        $ExpectedSha256 = New-GuardTestDigest
        Assert-ExpectedCandidateHash | Should -Be $ExpectedSha256
    }

    It 'parses the version format emitted by shipped binaries' {
        ConvertFrom-GuardVersionOutput -Text @('guard v0.6.0 (abcdef0)') -NativeStatus 0 | Should -Be '0.6.0'
        { ConvertFrom-GuardVersionOutput -Text @('guard 0.6.0') -NativeStatus 0 } | Should -Throw
        { ConvertFrom-GuardVersionOutput -Text @('guard v0.6.0') -NativeStatus 1 } | Should -Throw
    }

    It 'retries transient service registry provider failures' {
        $script:registryReadAttempts = 0
        Mock Test-Path { return $true }
        Mock Get-Acl {
            $script:registryReadAttempts++
            if ($script:registryReadAttempts -lt 2) { throw 'fixture registry read race' }
            return [pscustomobject]@{ Marker = 'expected' }
        }
        Mock Start-Sleep { return }
        (Get-ServiceRegistryAclObject -Path 'HKLM:\fixture').Marker | Should -Be 'expected'
        Should -Invoke Get-Acl -Times 2 -Exactly
        Should -Invoke Start-Sleep -Times 1 -Exactly

        $script:registryWriteAttempts = 0
        Mock Write-ServiceRegistryAclObject {
            $script:registryWriteAttempts++
            if ($script:registryWriteAttempts -lt 2) { throw 'fixture registry write race' }
        }
        Set-ServiceRegistryAclObject -AclObject ([pscustomobject]@{ Marker = 'acl' })
        Should -Invoke Write-ServiceRegistryAclObject -Times 2 -Exactly -ParameterFilter {
            $AclObject.Marker -eq 'acl'
        }
        Should -Invoke Start-Sleep -Times 2 -Exactly
    }

    It 'executes only the protected, digest-verified staged candidate' {
        $oldStagingDir = $StagingDir
        $StagingDir = Join-Path $TestDrive 'staging'
        New-Item -ItemType Directory -Path $StagingDir | Out-Null
        $source = Join-Path $TestDrive 'untrusted.exe'
        Set-Content -LiteralPath $source -Value 'fixture' -NoNewline
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash
        $script:executedCandidate = $null
        Mock Set-MaintenanceAcl { return }
        Mock Get-GuardVersion { param($GuardExe) $script:executedCandidate = $GuardExe; return '1.2.3' }
        try {
            $candidate = Stage-VerifiedGuardCandidate -SourceExe $source -ExpectedHash $hash
            $candidate.Version | Should -Be '1.2.3'
            $script:executedCandidate | Should -Not -Be $source
            (Test-PathWithin -Path $script:executedCandidate -Parent $StagingDir) | Should -BeTrue
            { Stage-VerifiedGuardCandidate -SourceExe $source -ExpectedHash ('00' * 32) } | Should -Throw
            Should -Invoke Get-GuardVersion -Times 1 -Exactly
        }
        finally {
            $StagingDir = $oldStagingDir
        }
    }

    It 'removes maintenance roots created by a failed first staging attempt' {
        $saved = @($MaintenanceRoot, $StagingDir, $BackupRoot, $TaskOutDir)
        $MaintenanceRoot = Join-Path $TestDrive 'new-maintenance'
        $StagingDir = Join-Path $MaintenanceRoot 'staging'
        $BackupRoot = Join-Path $MaintenanceRoot 'backups'
        $TaskOutDir = Join-Path $MaintenanceRoot 'task-output'
        $source = Join-Path $TestDrive 'invalid-candidate.exe'
        Set-Content -LiteralPath $source -Value 'fixture' -NoNewline
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash
        Mock Set-MaintenanceAcl {
            New-Item -ItemType Directory -Force -Path $MaintenanceRoot, $StagingDir, $BackupRoot, $TaskOutDir | Out-Null
        }
        Mock Get-GuardVersion { throw 'invalid candidate version' }
        Mock Remove-GuardOwnedTree {
            param($Path)
            Remove-Item -LiteralPath $Path -Recurse -Force
        }
        try {
            { Stage-VerifiedGuardCandidate -SourceExe $source -ExpectedHash $hash } | Should -Throw '*invalid candidate version*'
            Test-Path -LiteralPath $MaintenanceRoot | Should -BeFalse
            Should -Invoke Remove-GuardOwnedTree -Times 1 -Exactly
        }
        finally {
            $MaintenanceRoot = $saved[0]
            $StagingDir = $saved[1]
            $BackupRoot = $saved[2]
            $TaskOutDir = $saved[3]
        }
    }

    It 'preserves existing environment entries and merges managed values' {
        $existing = @{
            GUARD_LLM_API_KEY = 'existing-placeholder'
            UNRELATED_SETTING = 'retained'
            GUARD_CHILD_ENV = 'EXISTING_PATH'
        }
        $merged = Merge-ServiceEnvironment -Existing $existing -Imported @{}
        $merged['GUARD_LLM_API_KEY'] | Should -Be 'existing-placeholder'
        $merged['UNRELATED_SETTING'] | Should -Be 'retained'
        $merged['GUARD_CHILD_ENV'] | Should -Be 'EXISTING_PATH'
        $merged.ContainsKey('KUBECONFIG') | Should -BeFalse
    }

    It 'lets an allowlisted input replace only its matching value' {
        $merged = Merge-ServiceEnvironment -Existing @{ GUARD_LLM_API_KEY = 'old-placeholder'; KEEP = 'yes' } -Imported @{ GUARD_LLM_API_KEY = 'new-placeholder' }
        $merged['GUARD_LLM_API_KEY'] | Should -Be 'new-placeholder'
        $merged['KEEP'] | Should -Be 'yes'
    }

    It 'adds managed kube environment only when authority exists' {
        $saved = @($ConfigRoot, $KubeDir, $KubeConfig)
        try {
            $ConfigRoot = Join-Path $TestDrive 'managed-environment'
            $KubeDir = Join-Path $ConfigRoot 'kube'
            $KubeConfig = Join-Path $KubeDir 'config'
            $environment = @{ GUARD_CHILD_ENV = 'EXISTING_PATH,KUBECONFIG'; KEEP = 'fixture' }

            $withoutAuthority = Complete-ManagedKubeEnvironment -Environment $environment
            $withoutAuthority.ContainsKey('KUBECONFIG') | Should -BeFalse
            $withoutAuthority['GUARD_CHILD_ENV'] | Should -Be 'EXISTING_PATH'

            New-Item -ItemType Directory -Force -Path $KubeDir | Out-Null
            Set-Content -LiteralPath $KubeConfig -Value 'context' -NoNewline
            $withAuthority = Complete-ManagedKubeEnvironment -Environment $withoutAuthority
            $withAuthority['KUBECONFIG'] | Should -Be $KubeConfig
            $withAuthority['GUARD_CHILD_ENV'] | Should -Be 'EXISTING_PATH,KUBECONFIG'
            $withAuthority['KEEP'] | Should -Be 'fixture'
        }
        finally {
            $ConfigRoot = $saved[0]
            $KubeDir = $saved[1]
            $KubeConfig = $saved[2]
        }
    }

    It 'enumerates the complete SQLite file set' {
        (Get-DatabasePaths -Database 'D:\Guard State\primary.sqlite') -join '|' | Should -Be 'D:\Guard State\primary.sqlite|D:\Guard State\primary.sqlite-wal|D:\Guard State\primary.sqlite-shm|D:\Guard State\primary.sqlite-journal'
    }

    It 'gives the service read-execute without write in program and config ACLs' {
        $guardSid = $script:TestGuardSid
        $entries = Get-ServiceReadAclEntries -GuardSid $guardSid
        $guardEntry = @($entries | Where-Object Sid -eq $guardSid)
        $guardEntry.Count | Should -Be 1
        (([int64]$guardEntry[0].Rights) -band ([int64][Security.AccessControl.FileSystemRights]::Write)) | Should -Be 0
        (([int64]$guardEntry[0].Rights) -band ([int64][Security.AccessControl.FileSystemRights]::ReadAndExecute)) | Should -Be ([int64][Security.AccessControl.FileSystemRights]::ReadAndExecute)
    }

    It 'constructs protected directory ACLs with only explicit inheritable rules' {
        $guardSid = $script:TestGuardSid
        $entries = Get-ServiceReadAclEntries -GuardSid $guardSid
        $acl = New-ExactFileSystemAcl -Directory $true -OwnerSid $SidAdmins -Entries $entries
        $rules = @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))
        $acl.AreAccessRulesProtected | Should -BeTrue
        $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value | Should -Be $SidAdmins
        $rules.Count | Should -Be 3
        foreach ($rule in $rules) {
            $rule.IsInherited | Should -BeFalse
            $rule.InheritanceFlags | Should -Be (
                [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit
            )
            $rule.PropagationFlags | Should -Be ([Security.AccessControl.PropagationFlags]::None)
            (([int64]$rule.FileSystemRights) -band ([int64][Security.AccessControl.FileSystemRights]::Synchronize) ) | Should -Be ([int64][Security.AccessControl.FileSystemRights]::Synchronize)
        }
    }

    It 'applies and verifies the normalized exact ACL on disk' {
        $root = Join-Path $TestDrive 'acl-root'
        $file = Join-Path $root 'fixture.txt'
        New-Item -ItemType Directory -Path $root | Out-Null
        Set-Content -LiteralPath $file -Value 'fixture'
        $entries = Get-AdministrativeAclEntries
        Set-ExactFileSystemAcl -Path $root -OwnerSid $SidAdmins -Entries $entries
        Set-ExactFileSystemAcl -Path $file -OwnerSid $SidAdmins -Entries $entries
        { Assert-ExactFileSystemAcl -Path $root -OwnerSid $SidAdmins -Entries $entries } | Should -Not -Throw
        { Assert-ExactFileSystemAcl -Path $file -OwnerSid $SidAdmins -Entries $entries } | Should -Not -Throw
    }

    It 'applies a protected owner-only ACL to a private service tree' {
        $root = Join-Path $TestDrive 'private-acl-root'
        New-Item -ItemType Directory -Path $root | Out-Null
        Set-Content -LiteralPath (Join-Path $root 'body.bin') -Value 'fixture'
        $ownerSid = $script:TestGuardSid
        Protect-PrivateServiceTree -Path $root -GuardSid $ownerSid
        $entries = @((New-AclEntry -Sid $ownerSid -Rights ([Security.AccessControl.FileSystemRights]::FullControl)))
        { Assert-ExactAclTree -Path $root -OwnerSid $ownerSid -Entries $entries } | Should -Not -Throw
    }

    It 'prunes private roots before recursive enumeration' {
        $root = Join-Path $TestDrive 'tree'
        $private = Join-Path $root 'private'
        New-Item -ItemType Directory -Path $private -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $private 'unreadable.fixture') -Value 'fixture'
        Set-Content -LiteralPath (Join-Path $root 'visible.fixture') -Value 'fixture'
        $items = @(Get-PrunedTreeItems -Path $root -Exclude @($private))
        @($items | ForEach-Object FullName) | Should -Contain (Join-Path $root 'visible.fixture')
        @($items | ForEach-Object FullName) | Should -Not -Contain $private
        @($items | ForEach-Object FullName) | Should -Not -Contain (Join-Path $private 'unreadable.fixture')
    }

    It 'takes administrative ownership before purging a private tree' {
        $expectedPath = Join-Path $TestDrive 'purge-tree'
        New-Item -ItemType Directory -Path $expectedPath | Out-Null
        Mock Reset-TreeForAdministrativeMaintenance { return }
        Remove-GuardOwnedTree -Path $expectedPath
        Should -Invoke Reset-TreeForAdministrativeMaintenance -Times 1 -Exactly -ParameterFilter { $Path -eq $expectedPath }
        Test-Path -LiteralPath $expectedPath | Should -BeFalse
    }

    It 'rejects a nested junction without following or changing its target' {
        $oldDataDir = $DataDir
        $DataDir = Join-Path $TestDrive 'maintenance-data'
        $root = Join-Path $DataDir 'private'
        $outside = Join-Path $TestDrive 'junction-target'
        New-Item -ItemType Directory -Path $root, $outside -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $outside 'sentinel.txt') -Value 'unchanged'
        $targetAcl = (Get-Acl -LiteralPath $outside).Sddl
        $junction = Join-Path $root 'nested-junction'
        New-Item -ItemType Junction -Path $junction -Target $outside | Out-Null
        try {
            { Reset-TreeForAdministrativeMaintenance -Path $root } | Should -Throw '*reparse point*'
            Get-Content -LiteralPath (Join-Path $outside 'sentinel.txt') | Should -Be 'unchanged'
            (Get-Acl -LiteralPath $outside).Sddl | Should -Be $targetAcl
        }
        finally {
            Remove-Item -LiteralPath $junction -Force -ErrorAction SilentlyContinue
            $DataDir = $oldDataDir
        }
    }

    It 'uses only explicit non-recursive ownership and ACL commands' {
        $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'install-guard.ps1') -Raw
        $functionSource = ($source -split 'function Reset-TreeForAdministrativeMaintenance', 2)[1] -split 'function Get-AdministrativeAclEntries', 2 | Select-Object -First 1
        $functionSource | Should -Not -Match '(?i)takeown\.exe[^\r\n]*/R'
        $functionSource | Should -Not -Match '(?i)icacls\.exe[^\r\n]*/T'
        $functionSource | Should -Match 'Assert-NoReparsePoint -Path \$child\.FullName'
    }

    It 'accepts only an exact quoted installed executable token and preserves arguments' {
        $pathName = '"C:\Program Files\Guard\guard.exe" "server" "start" "--audit-log" "C:\ProgramData\Guard\audit.log"'
        Assert-ServicePathName -PathName $pathName | Should -Be $pathName
        { Assert-ServicePathName -PathName 'C:\Program Files\Guard\guard.exe server start' } | Should -Throw
        { Assert-ServicePathName -PathName '"C:\Program Files\Guard\guard.exe.evil" server start' } | Should -Throw
    }

    It 'updates installer-managed evaluator flags while preserving custom service commands' {
        $withoutKey = Get-ServiceBinPath -HaveKey $false -HaveVerbs $true
        $withKey = Get-ServiceBinPath -HaveKey $true -HaveVerbs $true
        $withoutKey | Should -Match ([regex]::Escape('--no-llm'))
        $withKey | Should -Not -Match ([regex]::Escape('--no-llm'))
        Test-InstallerManagedServicePath -PathName $withoutKey | Should -BeTrue
        Resolve-InstallServicePath -ExistingPath $withoutKey -DesiredPath $withKey | Should -Be $withKey

        $custom = '"C:\Program Files\Guard\guard.exe" "server" "start" "--socket" "guard-custom" "--state-db" "D:\Guard State\primary.sqlite" "--audit-log" "D:\custom\audit.log"'
        Test-InstallerManagedServicePath -PathName $custom | Should -BeFalse
        Resolve-InstallServicePath -ExistingPath $custom -DesiredPath $withKey | Should -Be $custom
    }

    It 'derives custom state authority paths from exactly one service setting' {
        $pathName = '"C:\Program Files\Guard\guard.exe" "server" "start" "--socket" "guard-custom" "--state-db" "D:\Guard State\primary.sqlite" "--service"'
        $paths = Get-GuardStatePaths -ServicePathName $pathName
        $paths.StateDb | Should -Be 'D:\Guard State\primary.sqlite'
        $paths.AuthorityKey | Should -Be 'D:\Guard State\authority.hmac'
        $paths.ApiRevertRoot | Should -Be 'D:\Guard State\api-proxy-reverts'
        $paths.SocketName | Should -Be 'guard-custom'
        (Get-DatabasePaths -Database $paths.StateDb) | Should -Contain 'D:\Guard State\primary.sqlite-wal'

        foreach ($invalid in @(
            '"C:\Program Files\Guard\guard.exe" "server" "start"',
            '"C:\Program Files\Guard\guard.exe" "server" "start" "--socket" "guard" "--state-db" "relative.sqlite"',
            '"C:\Program Files\Guard\guard.exe" "server" "start" "--socket" "guard" "--state-db" "D:\primary.sqlite"',
            '"C:\Program Files\Guard\guard.exe" "server" "start" "--socket" "guard" "--state-db" "D:\Guard\..\primary.sqlite"',
            '"C:\Program Files\Guard\guard.exe" "server" "start" "--socket" "guard" "--state-db" "D:\one.sqlite" "--state-db" "D:\two.sqlite"',
            '"C:\Program Files\Guard\guard.exe" "server" "start" "--state-db" "D:\Guard\primary.sqlite"',
            '"C:\Program Files\Guard\guard.exe" "server" "start" "--socket" "one" "--socket" "two" "--state-db" "D:\Guard\primary.sqlite"'
        )) {
            { Get-GuardStatePaths -ServicePathName $invalid } | Should -Throw
        }
    }

    It 'requires a dedicated custom state directory before changing its ACL tree' {
        $stateRoot = Join-Path $TestDrive "custom-state-$(New-GuardTestIdentifier)"
        $stateDb = Join-Path $stateRoot 'primary.sqlite'
        New-Item -ItemType Directory -Force -Path $stateRoot | Out-Null
        New-Item -ItemType File -Force -Path (Join-Path $stateRoot 'unrelated.txt') | Out-Null
        { Assert-DedicatedStateDirectory -Path $stateRoot -StateDb $stateDb } | Should -Throw '*dedicated state directory*'

        Remove-Item -LiteralPath (Join-Path $stateRoot 'unrelated.txt')
        New-Item -ItemType File -Force -Path $stateDb | Out-Null
        New-Item -ItemType File -Force -Path "$stateDb-wal" | Out-Null
        New-Item -ItemType Directory -Force -Path (Join-Path $stateRoot 'api-proxy-reverts') | Out-Null
        { Assert-DedicatedStateDirectory -Path $stateRoot -StateDb $stateDb } | Should -Not -Throw
    }

    It 'copies kube authority into the administrator-owned configuration root' {
        $saved = @($DataDir, $ConfigRoot, $KubeDir, $KubeConfig)
        try {
            $DataDir = Join-Path $TestDrive 'state-root'
            $ConfigRoot = Join-Path $TestDrive 'authority-root'
            $KubeDir = Join-Path $ConfigRoot 'kube'
            $KubeConfig = Join-Path $KubeDir 'config'
            $sourceDirectory = Join-Path $DataDir 'kube'
            $source = Join-Path $sourceDirectory 'config'
            $statePaths = [pscustomobject]@{
                StateDb = Join-Path $DataDir 'state.db'
                AuthorityKey = Join-Path $DataDir 'authority.hmac'
                ApiRevertRoot = Join-Path $DataDir 'api-proxy-reverts'
                SocketName = 'guard'
            }
            $environment = @{ KUBECONFIG = $source }
            New-Item -ItemType Directory -Force -Path $sourceDirectory | Out-Null
            Set-Content -LiteralPath $source -Value 'fixture-context' -NoNewline

            Copy-KubeConfigToAuthorityRoot -StatePaths $statePaths -Environment $environment
            (Get-Content -LiteralPath $KubeConfig -Raw) | Should -Be 'fixture-context'

            Set-Content -LiteralPath $KubeConfig -Value 'different-context' -NoNewline
            { Copy-KubeConfigToAuthorityRoot -StatePaths $statePaths -Environment $environment } | Should -Throw '*different content*'
        }
        finally {
            $DataDir = $saved[0]
            $ConfigRoot = $saved[1]
            $KubeDir = $saved[2]
            $KubeConfig = $saved[3]
        }
    }

    It 'copies kube authority from the active custom state directory' {
        $saved = @($DataDir, $ConfigRoot, $KubeDir, $KubeConfig)
        try {
            $DataDir = Join-Path $TestDrive 'default-state-decoy'
            $ConfigRoot = Join-Path $TestDrive 'authority-root-custom'
            $KubeDir = Join-Path $ConfigRoot 'kube'
            $KubeConfig = Join-Path $KubeDir 'config'
            $customStateDirectory = Join-Path $TestDrive 'active-custom-state'
            $customKubeDirectory = Join-Path $customStateDirectory 'kube'
            New-Item -ItemType Directory -Force -Path $customKubeDirectory | Out-Null
            Set-Content -LiteralPath (Join-Path $customKubeDirectory 'config') -Value 'custom-context' -NoNewline
            $statePaths = [pscustomobject]@{
                StateDb = Join-Path $customStateDirectory 'primary.sqlite'
                AuthorityKey = Join-Path $customStateDirectory 'authority.hmac'
                ApiRevertRoot = Join-Path $customStateDirectory 'api-proxy-reverts'
                SocketName = 'guard-custom'
            }

            $environment = @{ KUBECONFIG = Join-Path $customKubeDirectory 'config' }
            Copy-KubeConfigToAuthorityRoot -StatePaths $statePaths -Environment $environment

            (Get-Content -LiteralPath $KubeConfig -Raw) | Should -Be 'custom-context'
            Test-Path -LiteralPath (Join-Path $DataDir 'kube\config') | Should -BeFalse
        }
        finally {
            $DataDir = $saved[0]
            $ConfigRoot = $saved[1]
            $KubeDir = $saved[2]
            $KubeConfig = $saved[3]
        }
    }

    It 'migrates only the legacy kube environment binding' {
        $saved = @($ConfigRoot, $KubeDir, $KubeConfig)
        try {
            $ConfigRoot = Join-Path $TestDrive 'authority-environment'
            $KubeDir = Join-Path $ConfigRoot 'kube'
            $KubeConfig = Join-Path $KubeDir 'config'
            New-Item -ItemType Directory -Force -Path $KubeDir | Out-Null
            Set-Content -LiteralPath $KubeConfig -Value 'context' -NoNewline
            $stateDirectory = Join-Path $TestDrive 'legacy-environment-state'
            $statePaths = [pscustomobject]@{
                StateDb = Join-Path $stateDirectory 'state.db'
                AuthorityKey = Join-Path $stateDirectory 'authority.hmac'
                ApiRevertRoot = Join-Path $stateDirectory 'api-proxy-reverts'
                SocketName = 'guard'
            }
            $legacyConfig = Join-Path $stateDirectory 'kube\config'
            $environment = @{ KUBECONFIG = $legacyConfig; KEEP = 'fixture' }

            $converted = Convert-LegacyKubeEnvironment -Environment $environment -StatePaths $statePaths
            $completed = Complete-ManagedKubeEnvironment -Environment $converted

            $converted['KUBECONFIG'] | Should -Be $KubeConfig
            $converted['KEEP'] | Should -Be 'fixture'
            $completed['KUBECONFIG'] | Should -Be $KubeConfig
            $completed['GUARD_CHILD_ENV'] | Should -Be 'KUBECONFIG'
            $environment['KUBECONFIG'] | Should -Be $legacyConfig
            Remove-Item -LiteralPath $KubeConfig
            { Convert-LegacyKubeEnvironment -Environment $environment -StatePaths $statePaths } | Should -Throw '*has not been migrated*'
        }
        finally {
            $ConfigRoot = $saved[0]
            $KubeDir = $saved[1]
            $KubeConfig = $saved[2]
        }
    }

    It 'removes a missing released kube binding and its child authority' {
        $saved = @($ConfigRoot, $KubeDir, $KubeConfig)
        try {
            $ConfigRoot = Join-Path $TestDrive 'missing-kube-authority'
            $KubeDir = Join-Path $ConfigRoot 'kube'
            $KubeConfig = Join-Path $KubeDir 'config'
            $stateDirectory = Join-Path $TestDrive 'released-state'
            $statePaths = [pscustomobject]@{
                StateDb = Join-Path $stateDirectory 'state.db'
                AuthorityKey = Join-Path $stateDirectory 'authority.hmac'
                ApiRevertRoot = Join-Path $stateDirectory 'api-proxy-reverts'
                SocketName = 'guard'
            }
            $legacyConfig = Join-Path $stateDirectory 'kube\config'
            $environment = @{
                KUBECONFIG = $legacyConfig
                GUARD_CHILD_ENV = 'KEEP,KUBECONFIG'
                KEEP = 'fixture'
            }

            $normalized = Normalize-KubeEnvironmentAuthority -Environment $environment -StatePaths $statePaths

            $normalized.ContainsKey('KUBECONFIG') | Should -BeFalse
            $normalized['GUARD_CHILD_ENV'] | Should -Be 'KEEP'
            $normalized['KEEP'] | Should -Be 'fixture'
            $environment['KUBECONFIG'] | Should -Be $legacyConfig
            { Normalize-KubeEnvironmentAuthority -Environment @{ KUBECONFIG = 'C:\outside\config' } -StatePaths $statePaths } | Should -Throw '*managed authority root*'
        }
        finally {
            $ConfigRoot = $saved[0]
            $KubeDir = $saved[1]
            $KubeConfig = $saved[2]
        }
    }

    It 'accepts a fresh state directory without a legacy kube root' {
        $saved = @($InstallRoot, $ConfigRoot, $DataDir, $KubeDir, $KubeConfig, $MaintenanceRoot, $StagingDir, $BackupRoot, $TaskOutDir, $DeployedExe, $DeployedOperatorScript, $VerbsPath)
        try {
            $InstallRoot = Join-Path $TestDrive 'fresh-program'
            $ConfigRoot = Join-Path $TestDrive 'fresh-config'
            $DataDir = Join-Path $TestDrive 'fresh-state'
            $KubeDir = Join-Path $ConfigRoot 'kube'
            $KubeConfig = Join-Path $KubeDir 'config'
            $MaintenanceRoot = Join-Path $TestDrive 'fresh-maintenance'
            $StagingDir = Join-Path $MaintenanceRoot 'staging'
            $BackupRoot = Join-Path $MaintenanceRoot 'backups'
            $TaskOutDir = Join-Path $MaintenanceRoot 'task-output'
            $DeployedExe = Join-Path $InstallRoot 'guard.exe'
            $DeployedOperatorScript = Join-Path $InstallRoot 'guard-operator.ps1'
            $VerbsPath = Join-Path $ConfigRoot 'verbs.yaml'
            $statePaths = [pscustomobject]@{
                StateDb = Join-Path $DataDir 'state.db'
                AuthorityKey = Join-Path $DataDir 'authority.hmac'
                ApiRevertRoot = Join-Path $DataDir 'api-proxy-reverts'
                SocketName = 'guard'
            }
            $guardSid = $script:TestGuardSid

            Set-DeploymentAcls -GuardSid $guardSid -StatePaths $statePaths
            Set-Content -LiteralPath $statePaths.AuthorityKey -Value (New-GuardTestIdentifier) -NoNewline
            Set-DeploymentAcls -GuardSid $guardSid -StatePaths $statePaths

            { Assert-DeploymentAcls -GuardSid $guardSid -StatePaths $statePaths } | Should -Not -Throw
            Test-Path -LiteralPath (Join-Path $DataDir 'kube') | Should -BeFalse
        }
        finally {
            $InstallRoot = $saved[0]
            $ConfigRoot = $saved[1]
            $DataDir = $saved[2]
            $KubeDir = $saved[3]
            $KubeConfig = $saved[4]
            $MaintenanceRoot = $saved[5]
            $StagingDir = $saved[6]
            $BackupRoot = $saved[7]
            $TaskOutDir = $saved[8]
            $DeployedExe = $saved[9]
            $DeployedOperatorScript = $saved[10]
            $VerbsPath = $saved[11]
        }
    }

    It 'uses the validated custom service socket for operator RPCs' {
        $Action = 'access-list'
        $Reference = @()
        Mock Get-ServiceSnapshot { [pscustomobject]@{ SocketName = 'guard-custom' } }
        Mock Invoke-GuardAsOperator { [pscustomobject]@{ Output = 'ok'; ExitCode = 0 } }

        Invoke-OperatorAction

        Should -Invoke Invoke-GuardAsOperator -Times 1 -Exactly -ParameterFilter {
            $Arguments[-2] -eq '--socket' -and $Arguments[-1] -eq 'guard-custom'
        }
    }

    It 'accepts the bare service socket reported by daemon status' {
        $status = [pscustomobject]@{
            type = 'status'
            client = [pscustomobject]@{ version = '1.2.3' }
            server = [pscustomobject]@{
                version = '1.2.3'
                version_mismatch = $false
                full_restricted = $false
                full = [pscustomobject]@{
                    state_db_path = 'C:\ProgramData\Guard\state.db'
                    socket_path = 'guard'
                }
            }
        }

        { Assert-GuardStatusDocument -StatusDocument $status -ExpectedVersion '1.2.3' -ExpectedStateDb 'C:\ProgramData\Guard\state.db' -ExpectedSocket 'guard' } | Should -Not -Throw
    }

    It 'performs readiness status as SYSTEM and validates server.full.socket_path' {
        $expectedHash = New-GuardTestDigest
        $expectedSocket = 'guard-custom'
        $status = [ordered]@{
            type = 'status'
            client = [ordered]@{ version = '1.2.3' }
            server = [ordered]@{
                version = '1.2.3'
                version_mismatch = $false
                full_restricted = $false
                full = [ordered]@{
                    state_db_path = 'C:\ProgramData\Guard\state.db'
                    socket_path = $expectedSocket
                }
            }
        } | ConvertTo-Json -Depth 5 -Compress
        Mock Get-Service { [pscustomobject]@{ Status = 'Running' } }
        Mock Invoke-GuardAsOperator { [pscustomobject]@{ Output = $status; ExitCode = 0 } }
        Mock Get-FileHash { [pscustomobject]@{ Hash = $expectedHash } }
        Mock Get-CimInstance {
            if ($Filter -like 'Name=*') { return [pscustomobject]@{ ProcessId = 42 } }
            return [pscustomobject]@{ ExecutablePath = $DeployedExe }
        }

        Verify-GuardService -ExpectedHash $expectedHash -ExpectedVersion '1.2.3' -ExpectedStateDb 'C:\ProgramData\Guard\state.db' -ExpectedSocket $expectedSocket

        $OperatorAccount | Should -Be 'SYSTEM'
        Should -Invoke Invoke-GuardAsOperator -Times 1 -Exactly -ParameterFilter {
            $JsonOutput -and
            $GuardExe -eq $DeployedExe -and
            ($Arguments -join '|') -eq 'status|--socket|guard-custom|--json'
        }
    }

    It 'reports installed service state and pipe when the binary is missing' {
        $savedDeployedExe = $DeployedExe
        try {
            $DeployedExe = Join-Path $TestDrive 'missing\guard.exe'
            $servicePathName = '"' + $DeployedExe + '" "server" "start" "--socket" "guard-custom" "--state-db" "C:\ProgramData\Guard\state.db"'
            $script:statusOutput = [Collections.Generic.List[string]]::new()
            Mock Get-Service { [pscustomobject]@{ Status = 'Running' } }
            Mock Get-CimInstance { [pscustomobject]@{ PathName = $servicePathName } }
            Mock Get-ServiceSnapshot { throw 'Status must not probe the installed binary.' }
            Mock Write-Host { param($Object) [void]$script:statusOutput.Add([string]$Object) }

            { Invoke-Status } | Should -Not -Throw

            $script:statusOutput | Should -Contain 'Service: Running'
            $script:statusOutput | Should -Contain 'Pipe: guard-custom'
            Should -Invoke Get-ServiceSnapshot -Times 0 -Exactly
        }
        finally { $DeployedExe = $savedDeployedExe }
    }

    It 'stages custom state authority replacements on the destination volume' {
        $replacement = Get-AtomicReplacementPaths -Destination 'D:\Guard State\authority.hmac'
        $replacement.Staged | Should -Match '^D:\\Guard State\\\.guard-replace-[a-f0-9]{32}\.tmp$'
        $replacement.Replaced | Should -Match '^D:\\Guard State\\\.guard-replaced-[a-f0-9]{32}\.tmp$'
        $replacement.Staged | Should -Not -Match ([regex]::Escape($StagingDir))
    }

    It 'enforces the daemon authority ACL contract for fresh and upgraded custom state' {
        $saved = @($InstallRoot, $ConfigRoot, $DataDir, $KubeDir, $KubeConfig, $MaintenanceRoot, $StagingDir, $BackupRoot, $TaskOutDir, $DeployedExe, $DeployedOperatorScript, $VerbsPath)
        try {
            $InstallRoot = Join-Path $TestDrive 'program'
            $ConfigRoot = Join-Path $TestDrive 'config'
            $DataDir = Join-Path $TestDrive 'default-data-decoy'
            $KubeDir = Join-Path $ConfigRoot 'kube'
            $KubeConfig = Join-Path $KubeDir 'config'
            $MaintenanceRoot = Join-Path $TestDrive 'maintenance'
            $StagingDir = Join-Path $MaintenanceRoot 'staging'
            $BackupRoot = Join-Path $MaintenanceRoot 'backups'
            $TaskOutDir = Join-Path $MaintenanceRoot 'task-output'
            $DeployedExe = Join-Path $InstallRoot 'guard.exe'
            $DeployedOperatorScript = Join-Path $InstallRoot 'guard-operator.ps1'
            $VerbsPath = Join-Path $ConfigRoot 'verbs.yaml'
            $customStateDirectory = Join-Path $TestDrive "custom-state-$(New-GuardTestIdentifier)"
            $statePaths = [pscustomobject]@{
                StateDb = Join-Path $customStateDirectory 'primary.sqlite'
                AuthorityKey = Join-Path $customStateDirectory 'authority.hmac'
                ApiRevertRoot = Join-Path $customStateDirectory 'api-proxy-reverts'
                SocketName = 'guard-custom'
            }
            New-Item -ItemType Directory -Force -Path $customStateDirectory, $statePaths.ApiRevertRoot | Out-Null
            Set-Content -LiteralPath $statePaths.StateDb -Value 'state' -NoNewline
            Set-Content -LiteralPath (Join-Path $statePaths.ApiRevertRoot 'body.json') -Value 'revert' -NoNewline
            $legacyKubeRoot = Join-Path $customStateDirectory 'kube'
            New-Item -ItemType Directory -Force -Path $legacyKubeRoot | Out-Null
            Set-Content -LiteralPath (Join-Path $legacyKubeRoot 'config') -Value 'context' -NoNewline

            $customGuardSid = $script:TestGuardSid
            Set-DeploymentAcls -GuardSid $customGuardSid -StatePaths $statePaths
            Set-Content -LiteralPath $statePaths.AuthorityKey -Value (New-GuardTestIdentifier) -NoNewline
            Set-DeploymentAcls -GuardSid $customGuardSid -StatePaths $statePaths
            Assert-DeploymentAcls -GuardSid $customGuardSid -StatePaths $statePaths
            Assert-ExactFileSystemAcl -Path $statePaths.AuthorityKey -OwnerSid $customGuardSid -Entries @((New-AclEntry -Sid $customGuardSid -Rights ([Security.AccessControl.FileSystemRights]::FullControl)))
            Assert-ExactAclTree -Path $legacyKubeRoot -OwnerSid $SidAdmins -Entries (Get-AdministrativeAclEntries)
            { Reset-TreeForAdministrativeMaintenance -Path $statePaths.ApiRevertRoot -AdditionalRoots @($customStateDirectory) } | Should -Not -Throw
            Protect-PrivateServiceTree -Path $statePaths.ApiRevertRoot -GuardSid $customGuardSid
            Assert-PrivateServiceTree -Path $statePaths.ApiRevertRoot -GuardSid $customGuardSid
        }
        finally {
            $InstallRoot = $saved[0]
            $ConfigRoot = $saved[1]
            $DataDir = $saved[2]
            $KubeDir = $saved[3]
            $KubeConfig = $saved[4]
            $MaintenanceRoot = $saved[5]
            $StagingDir = $saved[6]
            $BackupRoot = $saved[7]
            $TaskOutDir = $saved[8]
            $DeployedExe = $saved[9]
            $DeployedOperatorScript = $saved[10]
            $VerbsPath = $saved[11]
        }
    }

    It 'validates absent-install journals as an exact fail-closed schema' {
        $saved = @(
            $InstallRoot, $ConfigRoot, $DataDir, $StateDb, $AuthorityKey,
            $KubeDir, $KubeConfig, $MaintenanceRoot, $StagingDir, $BackupRoot,
            $TaskOutDir, $TransactionJournal, $DeployedExe, $DeployedOperatorScript, $VerbsPath
        )
        try {
            $InstallRoot = Join-Path $TestDrive 'journal-program'
            $ConfigRoot = Join-Path $TestDrive 'journal-config'
            $DataDir = Join-Path $TestDrive 'journal-data'
            $StateDb = Join-Path $DataDir 'state.db'
            $AuthorityKey = Join-Path $DataDir 'authority.hmac'
            $KubeDir = Join-Path $ConfigRoot 'kube'
            $KubeConfig = Join-Path $KubeDir 'config'
            $MaintenanceRoot = Join-Path $TestDrive 'journal-maintenance'
            $StagingDir = Join-Path $MaintenanceRoot 'staging'
            $BackupRoot = Join-Path $MaintenanceRoot 'backups'
            $TaskOutDir = Join-Path $MaintenanceRoot 'task-output'
            $TransactionJournal = Join-Path $MaintenanceRoot 'upgrade-transaction.json'
            $DeployedExe = Join-Path $InstallRoot 'guard.exe'
            $DeployedOperatorScript = Join-Path $InstallRoot 'guard-operator.ps1'
            $VerbsPath = Join-Path $ConfigRoot 'verbs.yaml'
            Mock Set-MaintenanceAcl {
                New-Item -ItemType Directory -Force -Path $MaintenanceRoot, $StagingDir, $BackupRoot, $TaskOutDir | Out-Null
            }
            Mock Set-ExactFileSystemAcl { return }
            Mock Assert-ExactFileSystemAcl { return }

            $transaction = Start-NewInstallationTransaction
            $record = Read-GuardTransactionJournal
            $record.Document.schema | Should -Be 4
            $record.Document.phase | Should -Be 'staging'
            $record.Document.service_path_name | Should -BeNullOrEmpty

            $transaction['unexpected_field'] = 'fixture'
            Write-GuardTransactionJournal -Transaction $transaction
            { Read-GuardTransactionJournal } | Should -Throw '*fields outside its schema*'
            Test-Path -LiteralPath $TransactionJournal | Should -BeTrue

            $transaction.Remove('unexpected_field')
            $transaction['schema'] = '4'
            Write-GuardTransactionJournal -Transaction $transaction
            { Read-GuardTransactionJournal } | Should -Throw '*metadata is invalid*'
            Test-Path -LiteralPath $TransactionJournal | Should -BeTrue
        }
        finally {
            $InstallRoot = $saved[0]
            $ConfigRoot = $saved[1]
            $DataDir = $saved[2]
            $StateDb = $saved[3]
            $AuthorityKey = $saved[4]
            $KubeDir = $saved[5]
            $KubeConfig = $saved[6]
            $MaintenanceRoot = $saved[7]
            $StagingDir = $saved[8]
            $BackupRoot = $saved[9]
            $TaskOutDir = $saved[10]
            $TransactionJournal = $saved[11]
            $DeployedExe = $saved[12]
            $DeployedOperatorScript = $saved[13]
            $VerbsPath = $saved[14]
        }
    }

    It 'recovers a crashed initial install only when the service matches its journal' {
        $saved = @(
            $InstallRoot, $ConfigRoot, $DataDir, $StateDb, $AuthorityKey,
            $KubeDir, $KubeConfig, $MaintenanceRoot, $StagingDir, $BackupRoot,
            $TaskOutDir, $TransactionJournal, $DeployedExe, $DeployedOperatorScript, $VerbsPath
        )
        try {
            $InstallRoot = Join-Path $TestDrive 'initial-program'
            $ConfigRoot = Join-Path $TestDrive 'initial-config'
            $DataDir = Join-Path $TestDrive 'initial-data'
            $StateDb = Join-Path $DataDir 'state.db'
            $AuthorityKey = Join-Path $DataDir 'authority.hmac'
            $KubeDir = Join-Path $ConfigRoot 'kube'
            $KubeConfig = Join-Path $KubeDir 'config'
            $MaintenanceRoot = Join-Path $TestDrive 'initial-maintenance'
            $StagingDir = Join-Path $MaintenanceRoot 'staging'
            $BackupRoot = Join-Path $MaintenanceRoot 'backups'
            $TaskOutDir = Join-Path $MaintenanceRoot 'task-output'
            $TransactionJournal = Join-Path $MaintenanceRoot 'upgrade-transaction.json'
            $DeployedExe = Join-Path $InstallRoot 'guard.exe'
            $DeployedOperatorScript = Join-Path $InstallRoot 'guard-operator.ps1'
            $VerbsPath = Join-Path $ConfigRoot 'verbs.yaml'
            Mock Set-MaintenanceAcl {
                New-Item -ItemType Directory -Force -Path $MaintenanceRoot, $StagingDir, $BackupRoot, $TaskOutDir | Out-Null
            }
            Mock Set-ExactFileSystemAcl { return }
            Mock Assert-ExactFileSystemAcl { return }
            Mock Reset-TreeForAdministrativeMaintenance { return }
            Mock Wait-ServiceStopped { return }

            $transaction = Start-NewInstallationTransaction
            $servicePathName = Get-ServiceBinPath -HaveKey $false -HaveVerbs $false
            Set-NewInstallationTransactionMutating -Transaction $transaction -ServicePathName $servicePathName
            New-Item -ItemType Directory -Force -Path $InstallRoot, $ConfigRoot, $DataDir | Out-Null
            Set-Content -LiteralPath $DeployedExe -Value 'interrupted-binary' -NoNewline
            Set-Content -LiteralPath $StateDb -Value 'interrupted-state' -NoNewline
            $script:initialServicePresent = $true
            $script:initialServicePathName = "$servicePathName `"--unexpected-setting`""
            Mock Get-Service {
                if ($script:initialServicePresent) { return [pscustomobject]@{ Status = 'Running' } }
                return $null
            }
            Mock Get-CimInstance {
                [pscustomobject]@{ StartName = $ServiceAccount; PathName = $script:initialServicePathName }
            }
            Mock sc.exe {
                $script:initialServicePresent = $false
                $global:LASTEXITCODE = 0
            }

            { Recover-GuardTransaction } | Should -Throw '*does not match*'
            Test-Path -LiteralPath $TransactionJournal | Should -BeTrue
            Should -Invoke sc.exe -Times 0 -Exactly

            $script:initialServicePathName = $servicePathName
            Recover-GuardTransaction

            Should -Invoke sc.exe -Times 1 -Exactly
            foreach ($path in @($InstallRoot, $ConfigRoot, $DataDir, $MaintenanceRoot, $TransactionJournal)) {
                Test-Path -LiteralPath $path | Should -BeFalse
            }
        }
        finally {
            $InstallRoot = $saved[0]
            $ConfigRoot = $saved[1]
            $DataDir = $saved[2]
            $StateDb = $saved[3]
            $AuthorityKey = $saved[4]
            $KubeDir = $saved[5]
            $KubeConfig = $saved[6]
            $MaintenanceRoot = $saved[7]
            $StagingDir = $saved[8]
            $BackupRoot = $saved[9]
            $TaskOutDir = $saved[10]
            $TransactionJournal = $saved[11]
            $DeployedExe = $saved[12]
            $DeployedOperatorScript = $saved[13]
            $VerbsPath = $saved[14]
        }
    }

    It 'retries journal cleanup and verifies durable removal' {
        $saved = @($MaintenanceRoot, $StagingDir, $BackupRoot, $TaskOutDir, $TransactionJournal)
        try {
            $MaintenanceRoot = Join-Path $TestDrive 'durable-journal-maintenance'
            $StagingDir = Join-Path $MaintenanceRoot 'staging'
            $BackupRoot = Join-Path $MaintenanceRoot 'backups'
            $TaskOutDir = Join-Path $MaintenanceRoot 'task-output'
            $TransactionJournal = Join-Path $MaintenanceRoot 'upgrade-transaction.json'
            Mock Set-MaintenanceAcl {
                New-Item -ItemType Directory -Force -Path $MaintenanceRoot, $StagingDir, $BackupRoot, $TaskOutDir | Out-Null
            }
            Mock Set-ExactFileSystemAcl { return }
            Mock Assert-ExactFileSystemAcl { return }
            $null = Start-NewInstallationTransaction
            $script:journalCleanupAttempts = 0
            Mock Remove-Item {
                $script:journalCleanupAttempts++
                if ($script:journalCleanupAttempts -lt 3) { throw 'fixture journal lock' }
                [IO.File]::Delete($LiteralPath)
            }
            Mock Start-Sleep { return }

            Complete-GuardTransaction

            $script:journalCleanupAttempts | Should -Be 3
            Test-Path -LiteralPath $TransactionJournal | Should -BeFalse
            Should -Invoke Start-Sleep -Times 2 -Exactly
        }
        finally {
            $MaintenanceRoot = $saved[0]
            $StagingDir = $saved[1]
            $BackupRoot = $saved[2]
            $TaskOutDir = $saved[3]
            $TransactionJournal = $saved[4]
        }
    }

    It 'removes a protected empty maintenance layout left after journal cleanup' {
        $saved = @($InstallRoot, $ConfigRoot, $DataDir, $MaintenanceRoot, $StagingDir, $BackupRoot, $TaskOutDir, $TransactionJournal)
        try {
            $InstallRoot = Join-Path $TestDrive 'completed-program'
            $ConfigRoot = Join-Path $TestDrive 'completed-config'
            $DataDir = Join-Path $TestDrive 'completed-data'
            $MaintenanceRoot = Join-Path $TestDrive 'completed-maintenance'
            $StagingDir = Join-Path $MaintenanceRoot 'staging'
            $BackupRoot = Join-Path $MaintenanceRoot 'backups'
            $TaskOutDir = Join-Path $MaintenanceRoot 'task-output'
            $TransactionJournal = Join-Path $MaintenanceRoot 'upgrade-transaction.json'
            New-Item -ItemType Directory -Force -Path $StagingDir, $BackupRoot, $TaskOutDir | Out-Null
            Mock Assert-NoReparsePoint { return }
            Mock Assert-ExactFileSystemAcl { return }
            Mock Reset-TreeForAdministrativeMaintenance { return }

            Remove-CompletedNewInstallationMaintenanceRoot

            Test-Path -LiteralPath $MaintenanceRoot | Should -BeFalse
        }
        finally {
            $InstallRoot = $saved[0]
            $ConfigRoot = $saved[1]
            $DataDir = $saved[2]
            $MaintenanceRoot = $saved[3]
            $StagingDir = $saved[4]
            $BackupRoot = $saved[5]
            $TaskOutDir = $saved[6]
            $TransactionJournal = $saved[7]
        }
    }

    It 'excludes a concurrent deployment action with the Global mutex' {
        $mutex = [pscustomobject]@{ Released = $false; Disposed = $false }
        $mutex | Add-Member -MemberType ScriptMethod -Name WaitOne -Value { param($MillisecondsTimeout) return $false }
        $mutex | Add-Member -MemberType ScriptMethod -Name ReleaseMutex -Value { $this.Released = $true }
        $mutex | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $this.Disposed = $true }
        Mock New-GuardDeploymentMutex { return $mutex }
        $script:excludedOperationRan = $false

        { Invoke-WithGuardDeploymentLock { $script:excludedOperationRan = $true } } | Should -Throw '*deployment action is active*'

        $DeploymentMutexName | Should -Be 'Global\GuardDeploymentTransaction'
        $script:excludedOperationRan | Should -BeFalse
        $mutex.Released | Should -BeFalse
        $mutex.Disposed | Should -BeTrue
    }

    It 'claims an abandoned deployment mutex so crash recovery can continue' {
        $mutex = [pscustomobject]@{ Released = $false; Disposed = $false }
        $mutex | Add-Member -MemberType ScriptMethod -Name WaitOne -Value {
            param($MillisecondsTimeout)
            throw [Threading.AbandonedMutexException]::new()
        }
        $mutex | Add-Member -MemberType ScriptMethod -Name ReleaseMutex -Value { $this.Released = $true }
        $mutex | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $this.Disposed = $true }
        Mock New-GuardDeploymentMutex { return $mutex }
        $script:abandonedOperationRan = $false

        Invoke-WithGuardDeploymentLock { $script:abandonedOperationRan = $true }

        $script:abandonedOperationRan | Should -BeTrue
        $mutex.Released | Should -BeTrue
        $mutex.Disposed | Should -BeTrue
    }

    It 'recovers a persisted mutating transaction before another deployment action' {
        $saved = @($InstallRoot, $ConfigRoot, $DataDir, $MaintenanceRoot, $StagingDir, $BackupRoot, $TaskOutDir, $TransactionJournal, $DeployedExe)
        try {
            $InstallRoot = Join-Path $TestDrive 'program'
            $ConfigRoot = Join-Path $TestDrive 'config'
            $DataDir = Join-Path $TestDrive 'data'
            $MaintenanceRoot = Join-Path $TestDrive 'maintenance'
            $StagingDir = Join-Path $MaintenanceRoot 'staging'
            $BackupRoot = Join-Path $MaintenanceRoot 'backups'
            $TaskOutDir = Join-Path $MaintenanceRoot 'task-output'
            $TransactionJournal = Join-Path $MaintenanceRoot 'upgrade-transaction.json'
            $DeployedExe = Join-Path $InstallRoot 'guard.exe'
            $statePaths = [pscustomobject]@{
                StateDb = Join-Path $DataDir 'state.db'
                AuthorityKey = Join-Path $DataDir 'authority.hmac'
                ApiRevertRoot = Join-Path $DataDir 'api-proxy-reverts'
                SocketName = 'guard'
            }
            $snapshot = [pscustomobject]@{
                PathName = ('"' + $DeployedExe + '" "server" "start" "--socket" "guard" "--state-db" "' + $statePaths.StateDb + '"')
                StatePaths = $statePaths
                BinaryHash = New-GuardTestDigest
                BinaryVersion = '1.2.3'
                StartMode = 'Auto'
                WasRunning = $true
                AuthorityKeyPresent = $false
            }
            $transaction = Start-GuardTransaction -Operation install -Snapshot $snapshot
            $transaction.authority_key_present | Should -BeFalse
            $backupName = New-GuardTestBackupName
            Set-GuardTransactionPhase -Transaction $transaction -Phase prepared -BackupName $backupName
            Set-GuardTransactionPhase -Transaction $transaction -Phase mutating -BackupName $backupName
            Mock Read-ValidatedGuardBackup { [pscustomobject]@{ Name = 'fixture' } }
            Mock Restore-GuardInstallation { return }
            Mock Get-GuardSid { return $script:TestGuardSid }

            Recover-GuardTransaction

            Should -Invoke Read-ValidatedGuardBackup -Times 1 -Exactly -ParameterFilter { $Name -eq $backupName }
            Should -Invoke Restore-GuardInstallation -Times 1 -Exactly
            Test-Path -LiteralPath $TransactionJournal | Should -BeFalse
        }
        finally {
            $InstallRoot = $saved[0]
            $ConfigRoot = $saved[1]
            $DataDir = $saved[2]
            $MaintenanceRoot = $saved[3]
            $StagingDir = $saved[4]
            $BackupRoot = $saved[5]
            $TaskOutDir = $saved[6]
            $TransactionJournal = $saved[7]
            $DeployedExe = $saved[8]
        }
    }

    It 'recovers an unmutated released layout without inventing authority state' {
        $stateDirectory = Join-Path $TestDrive 'released-layout-state'
        New-Item -ItemType Directory -Path $stateDirectory | Out-Null
        $statePaths = [pscustomobject]@{
            StateDb = Join-Path $stateDirectory 'state.db'
            AuthorityKey = Join-Path $stateDirectory 'authority.hmac'
            ApiRevertRoot = Join-Path $stateDirectory 'api-proxy-reverts'
            SocketName = 'guard'
        }
        Mock Set-ExactFileSystemAcl { return }

        { Restore-SnapshotPrivateServiceAcls -StatePaths $statePaths -GuardSid $script:TestGuardSid -AuthorityKeyPresent $false } | Should -Not -Throw
        { Restore-SnapshotPrivateServiceAcls -StatePaths $statePaths -GuardSid $script:TestGuardSid -AuthorityKeyPresent $true } | Should -Throw '*no longer matches*'
        Set-Content -LiteralPath $statePaths.AuthorityKey -Value 'generated-fixture' -NoNewline
        { Restore-SnapshotPrivateServiceAcls -StatePaths $statePaths -GuardSid $script:TestGuardSid -AuthorityKeyPresent $false } | Should -Throw '*no longer matches*'
        { Restore-SnapshotPrivateServiceAcls -StatePaths $statePaths -GuardSid $script:TestGuardSid -AuthorityKeyPresent $true } | Should -Not -Throw
        Should -Invoke Set-ExactFileSystemAcl -Times 1 -Exactly -ParameterFilter { $Path -eq $statePaths.AuthorityKey }
    }

    It 'recovers the completed rollback state instead of the pre-rollback snapshot' {
        $initialPathName = ('"' + $DeployedExe + '" "server" "start" "--socket" "guard" "--state-db" "C:\ProgramData\Guard\state.db"')
        $initialStatePaths = Get-GuardStatePaths -ServicePathName $initialPathName
        $initial = [pscustomobject]@{
            PathName = $initialPathName
            StatePaths = $initialStatePaths
            BinaryHash = New-GuardTestDigest
            BinaryVersion = '1.2.3'
            StartMode = 'Auto'
            WasRunning = $true
            AuthorityKeyPresent = $true
        }
        $completedPathName = ('"' + $DeployedExe + '" "server" "start" "--socket" "guard-rollback" "--state-db" "C:\ProgramData\GuardRollback\state.db"')
        $completedStatePaths = Get-GuardStatePaths -ServicePathName $completedPathName
        $completed = [pscustomobject]@{
            PathName = $completedPathName
            StatePaths = $completedStatePaths
            BinaryHash = New-GuardTestDigest
            BinaryVersion = '1.1.0'
            StartMode = 'Disabled'
            WasRunning = $false
            AuthorityKeyPresent = $false
        }
        $transaction = New-GuardTransactionJournal -Operation rollback -Snapshot $initial
        $transaction.phase = 'mutating'
        $transaction.backup_name = New-GuardTestBackupName
        Mock Write-GuardTransactionJournal { return }
        Mark-GuardTransactionVerified -Transaction $transaction -CompletedSnapshot $completed
        $record = [pscustomobject]@{
            Document = [pscustomobject]$transaction
            StatePaths = $initialStatePaths
            CompletedStatePaths = $completedStatePaths
        }
        Mock Read-GuardTransactionJournal { return $record }
        Mock Get-ServiceSnapshot { return $completed }
        Mock Wait-ServiceStopped { return }
        Mock Set-GuardServiceConfiguration { return }
        Mock Start-GuardService { return }
        Mock Verify-GuardService { return }
        Mock Assert-DeploymentAcls { return }
        Mock Get-GuardSid { return $script:TestGuardSid }
        Mock Complete-GuardTransaction { return }

        Recover-GuardTransaction

        Should -Invoke Wait-ServiceStopped -Times 1 -Exactly
        Should -Invoke Start-GuardService -Times 0 -Exactly
        Should -Invoke Set-GuardServiceConfiguration -Times 1 -Exactly -ParameterFilter {
            $PathName -eq $completed.PathName -and $StartMode -eq 'Disabled'
        }
        Should -Invoke Assert-DeploymentAcls -Times 1 -Exactly -ParameterFilter {
            $StatePaths.StateDb -eq $completedStatePaths.StateDb -and $AuthorityKeyPresent -eq $false
        }
    }

    It 'recovers immediately when rollback backup creation fails after service stop' {
        $savedBackup = $Backup
        try {
            $Backup = New-GuardTestBackupName
            $statePaths = [pscustomobject]@{
                StateDb = 'C:\ProgramData\Guard\state.db'
                AuthorityKey = 'C:\ProgramData\Guard\authority.hmac'
                ApiRevertRoot = 'C:\ProgramData\Guard\api-proxy-reverts'
                SocketName = 'guard'
            }
            $snapshot = [pscustomobject]@{
                StatePaths = $statePaths
                PathName = '"C:\Program Files\Guard\guard.exe" "server" "start" "--socket" "guard" "--state-db" "C:\ProgramData\Guard\state.db"'
                BinaryHash = New-GuardTestDigest
                BinaryVersion = '1.2.3'
                StartMode = 'Auto'
                WasRunning = $true
                AuthorityKeyPresent = $false
            }
            $target = [pscustomobject]@{ Metadata = [pscustomobject]@{ binary_version = '1.2.3' } }
            Mock Assert-Admin { return }
            Mock Recover-GuardTransaction { return }
            Mock Read-ValidatedGuardBackup { return $target }
            Mock Get-ServiceSnapshot { return $snapshot }
            Mock Get-GuardSid { return $script:TestGuardSid }
            Mock Write-GuardTransactionJournal { return }
            Mock Wait-ServiceStopped { return }
            Mock New-GuardBackup { throw 'fixture backup failure' }

            { Invoke-Rollback } | Should -Throw '*pre-rollback installation was restored*'

            Should -Invoke Wait-ServiceStopped -Times 1 -Exactly
            Should -Invoke New-GuardBackup -Times 1 -Exactly
            Should -Invoke Recover-GuardTransaction -Times 2 -Exactly
        }
        finally { $Backup = $savedBackup }
    }

    It 'recovers a pending transaction before uninstalling' {
        $saved = @($Purge, $InstallRoot)
        try {
            $Purge = $false
            $InstallRoot = Join-Path $TestDrive 'absent-program-root'
            Mock Assert-Admin { return }
            Mock Recover-GuardTransaction { return }
            Mock Wait-ServiceStopped { return }
            Mock sc.exe { $global:LASTEXITCODE = 0 }

            Invoke-Uninstall

            Should -Invoke Recover-GuardTransaction -Times 1 -Exactly
            Should -Invoke Wait-ServiceStopped -Times 1 -Exactly
        }
        finally {
            $Purge = $saved[0]
            $InstallRoot = $saved[1]
        }
    }

    It 'rejects a staged candidate that cannot simulate the preserved state database' {
        Mock Get-GuardStateCompatibilityReport {
            [pscustomobject]@{
                type = 'state_db_compatibility'
                compatible = $false
                simulated_open = $false
                simulated_startup = [pscustomobject]@{ succeeded = $false }
            }
        }
        { Assert-CandidateStateCompatibility -GuardExe 'C:\staging\guard.exe' -StateDb 'D:\Guard State\primary.sqlite' } | Should -Throw '*incompatible*'
        Should -Invoke Get-GuardStateCompatibilityReport -Times 1 -Exactly -ParameterFilter {
            $GuardExe -eq 'C:\staging\guard.exe' -and $StateDb -eq 'D:\Guard State\primary.sqlite'
        }
    }

    It 'rejects a candidate that opens state but reports incompatible failed startup' {
        Mock Get-GuardStateCompatibilityReport {
            [pscustomobject]@{
                type = 'state_db_compatibility'
                compatible = $false
                simulated_open = $true
                simulated_startup = [pscustomobject]@{ succeeded = $false }
            }
        }
        { Assert-CandidateStateCompatibility -GuardExe 'C:\staging\guard.exe' -StateDb 'D:\Guard State\primary.sqlite' } | Should -Throw '*incompatible*'
    }

    It 'rejects a candidate that opens state but cannot complete simulated startup' {
        Mock Get-GuardStateCompatibilityReport {
            [pscustomobject]@{
                type = 'state_db_compatibility'
                compatible = $true
                simulated_open = $true
                simulated_startup = [pscustomobject]@{ succeeded = $false }
            }
        }
        { Assert-CandidateStateCompatibility -GuardExe 'C:\staging\guard.exe' -StateDb 'D:\Guard State\primary.sqlite' } | Should -Throw '*incompatible*'
    }

    It 'atomically replaces an existing file without retaining replacement artifacts' {
        $oldStagingDir = $StagingDir
        $StagingDir = Join-Path $TestDrive 'atomic-staging'
        New-Item -ItemType Directory -Path $StagingDir | Out-Null
        $source = Join-Path $TestDrive 'candidate.bin'
        $destination = Join-Path $TestDrive 'installed.bin'
        [IO.File]::WriteAllText($source, 'candidate', [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($destination, 'installed', [Text.UTF8Encoding]::new($false))
        try {
            $expectedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash
            Install-FileAtomically -Source $source -Destination $destination -ExpectedHash $expectedHash
            [IO.File]::ReadAllText($destination) | Should -Be 'candidate'
            @(Get-ChildItem -LiteralPath $StagingDir -Force).Count | Should -Be 0
        }
        finally { $StagingDir = $oldStagingDir }
    }

    It 'uses destination-local temporary files through the atomic replacement seam for custom state' {
        $source = Join-Path $TestDrive 'candidate-authority.hmac'
        $stateDirectory = Join-Path $TestDrive "custom-state-$(New-GuardTestIdentifier)"
        $destination = Join-Path $stateDirectory 'authority.hmac'
        New-Item -ItemType Directory -Path $stateDirectory | Out-Null
        [IO.File]::WriteAllText($source, 'replacement', [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($destination, 'original', [Text.UTF8Encoding]::new($false))
        $script:replacementPaths = $null
        Mock Get-AtomicReplacementPaths {
            param($Destination)
            $directory = Split-Path -Parent $Destination
            $script:replacementPaths = [pscustomobject]@{
                Staged = Join-Path $directory '.guard-replace-fixture.tmp'
                Replaced = Join-Path $directory '.guard-replaced-fixture.tmp'
            }
            return $script:replacementPaths
        }

        Install-FileAtomically -Source $source -Destination $destination -ExpectedHash (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash

        Should -Invoke Get-AtomicReplacementPaths -Times 1 -Exactly -ParameterFilter { $Destination -eq $destination }
        [IO.Path]::GetDirectoryName($script:replacementPaths.Staged) | Should -Be ([IO.Path]::GetDirectoryName($destination))
        [IO.Path]::GetDirectoryName($script:replacementPaths.Replaced) | Should -Be ([IO.Path]::GetDirectoryName($destination))
        [IO.Path]::GetPathRoot($script:replacementPaths.Staged) | Should -Be ([IO.Path]::GetPathRoot($destination))
        [IO.Path]::GetPathRoot($script:replacementPaths.Replaced) | Should -Be ([IO.Path]::GetPathRoot($destination))
        Test-Path -LiteralPath $script:replacementPaths.Staged | Should -BeFalse
        Test-Path -LiteralPath $script:replacementPaths.Replaced | Should -BeFalse
        [IO.File]::ReadAllText($destination) | Should -Be 'replacement'
    }

    It 'round-trips API revert bodies and reapplies the daemon-only ACL' {
        $oldDataDir = $DataDir
        $oldStagingDir = $StagingDir
        $DataDir = Join-Path $TestDrive 'default-data-decoy'
        $StagingDir = Join-Path $TestDrive 'staging-api'
        New-Item -ItemType Directory -Path $StagingDir | Out-Null
        $customDb = Join-Path (Join-Path $TestDrive "custom-state-$(New-GuardTestIdentifier)") 'primary.sqlite'
        $statePaths = Get-GuardStatePaths -ServicePathName ('"' + $DeployedExe + '" "server" "start" "--socket" "guard" "--state-db" "' + $customDb + '"')
        $apiRoot = Get-ApiRevertRoot -StatePaths $statePaths
        $defaultDecoy = Join-Path $DataDir 'api-proxy-reverts\decoy.body'
        New-Item -ItemType Directory -Path (Split-Path -Parent $defaultDecoy) -Force | Out-Null
        [IO.File]::WriteAllBytes($defaultDecoy, [byte[]](9, 9, 9))
        New-Item -ItemType Directory -Path (Join-Path $apiRoot 'nested') -Force | Out-Null
        $body = Join-Path $apiRoot 'nested\body.bin'
        [IO.File]::WriteAllBytes($body, [byte[]](1, 2, 3, 4))
        $backupPath = Join-Path $TestDrive 'backup'
        New-Item -ItemType Directory -Path $backupPath | Out-Null
        Mock Reset-TreeForAdministrativeMaintenance { return }
        Mock Protect-PrivateServiceTree { return }
        try {
            $files = @(Copy-ApiRevertBackup -BackupPath $backupPath -GuardSid $script:TestGuardSid -StatePaths $statePaths)
            $files.Count | Should -Be 1
            [IO.File]::WriteAllBytes($body, [byte[]](9, 9))
            $record = [pscustomobject]@{
                Path = $backupPath
                Metadata = [pscustomobject]@{ api_reverts_present = $true; files = $files }
            }
            Restore-ApiRevertBackup -BackupRecord $record -GuardSid $script:TestGuardSid -StatePaths $statePaths
            ([BitConverter]::ToString([IO.File]::ReadAllBytes($body)) -replace '-', '') | Should -Be '01020304'
            ([BitConverter]::ToString([IO.File]::ReadAllBytes($defaultDecoy)) -replace '-', '') | Should -Be '090909'
            Should -Invoke Protect-PrivateServiceTree -Times 2 -Exactly
        }
        finally {
            $DataDir = $oldDataDir
            $StagingDir = $oldStagingDir
        }
    }

    It 'backs up and restores only the custom state authority family' {
        $saved = @($DataDir, $ConfigRoot, $KubeDir, $KubeConfig, $BackupRoot, $StagingDir, $DeployedExe, $DeployedOperatorScript, $VerbsPath)
        $DataDir = Join-Path $TestDrive 'default-data-decoy'
        $ConfigRoot = Join-Path $TestDrive 'authority-backup'
        $KubeDir = Join-Path $ConfigRoot 'kube'
        $KubeConfig = Join-Path $KubeDir 'config'
        $BackupRoot = Join-Path $TestDrive 'backups'
        $StagingDir = Join-Path $TestDrive 'staging'
        $DeployedExe = Join-Path $TestDrive 'program\guard.exe'
        $DeployedOperatorScript = Join-Path $TestDrive 'program\guard-operator.ps1'
        $VerbsPath = Join-Path $TestDrive 'config\verbs.yaml'
        New-Item -ItemType Directory -Force -Path $BackupRoot, $StagingDir, $KubeDir, (Split-Path -Parent $DeployedExe) | Out-Null
        [IO.File]::WriteAllText($DeployedExe, 'baseline-binary', [Text.UTF8Encoding]::new($false))
        $customDb = Join-Path (Join-Path $TestDrive "custom-state-$(New-GuardTestIdentifier)") 'primary.sqlite'
        $servicePath = '"' + $DeployedExe + '" "server" "start" "--socket" "guard-custom" "--state-db" "' + $customDb + '"'
        $statePaths = Get-GuardStatePaths -ServicePathName $servicePath
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $statePaths.StateDb) | Out-Null
        [IO.File]::WriteAllText($statePaths.StateDb, 'custom-db', [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText("$($statePaths.StateDb)-wal", 'custom-wal', [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($statePaths.AuthorityKey, 'custom-key', [Text.UTF8Encoding]::new($false))
        $legacyKubeConfig = Join-Path (Split-Path -Parent $statePaths.StateDb) 'kube\config'
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $legacyKubeConfig) | Out-Null
        [IO.File]::WriteAllText($legacyKubeConfig, 'legacy-context', [Text.UTF8Encoding]::new($false))
        New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
        $defaultDb = Join-Path $DataDir 'state.db'
        $defaultKey = Join-Path $DataDir 'authority.hmac'
        [IO.File]::WriteAllText($defaultDb, 'default-decoy', [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($defaultKey, 'default-decoy-key', [Text.UTF8Encoding]::new($false))
        $snapshot = [pscustomobject]@{
            StatePaths = $statePaths
            CatalogPresent = $false
            Environment = @{ KUBECONFIG = $legacyKubeConfig }
            BinaryVersion = '1.2.3'
            BinaryHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $DeployedExe).Hash
            StartMode = 'Manual'
            WasRunning = $false
            AuthorityKeyPresent = $true
            PathName = $servicePath
        }
        Mock Set-MaintenanceAcl { return }
        Mock Protect-LocalMachineText {
            param($Value, $Path)
            [IO.File]::WriteAllText($Path, $Value, [Text.UTF8Encoding]::new($false))
        }
        Mock Wait-ServiceStopped { return }
        Mock Set-GuardServiceConfiguration { return }
        $script:lastRestoredServiceEnvironment = $null
        Mock Set-ServiceEnvironment {
            param($Environment)
            $script:lastRestoredServiceEnvironment = $Environment
        }
        Mock Set-DeploymentAcls { return }
        Mock Assert-ExactFileSystemAcl { return }
        Mock Set-ExactFileSystemAcl { return }
        Mock Reset-TreeForAdministrativeMaintenance { return }
        Mock Start-GuardService { return }
        Mock Verify-GuardService { return }
        Mock Assert-DeploymentAcls { return }
        try {
            $backupName = New-GuardBackup -Snapshot $snapshot -BeforeVersion '1.2.3' -GuardSid $script:TestGuardSid
            $backupPath = Join-Path $BackupRoot $backupName
            $metadata = Get-Content -LiteralPath (Join-Path $backupPath 'metadata.json') -Raw | ConvertFrom-Json
            $metadata.state_database | Should -Be $statePaths.StateDb
            $metadata.socket_name | Should -Be 'guard-custom'
            $metadata.authority_key | Should -Be $statePaths.AuthorityKey
            $metadata.api_revert_root | Should -Be $statePaths.ApiRevertRoot
            [IO.File]::ReadAllText((Join-Path $backupPath 'sqlite\state.db')) | Should -Be 'custom-db'
            [IO.File]::ReadAllText((Join-Path $backupPath 'sqlite\state.db-wal')) | Should -Be 'custom-wal'
            [IO.File]::ReadAllText((Join-Path $backupPath 'authority.hmac')) | Should -Be 'custom-key'
            $metadata.kube_authority_present | Should -BeTrue
            [IO.File]::ReadAllText((Join-Path $backupPath 'config\kube\config')) | Should -Be 'legacy-context'

            $metadataPath = Join-Path $backupPath 'metadata.json'
            $legacyMetadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
            $legacyMetadata.metadata_schema = 3
            $legacyMetadata.PSObject.Properties.Remove('socket_name')
            $legacyMetadata.PSObject.Properties.Remove('kube_authority_present')
            $legacyMetadata.files = @($legacyMetadata.files | Where-Object path -ne 'config/kube/config')
            $kubeAuthorityBackup = Join-Path $backupPath 'config\kube\config'
            $kubeAuthorityBytes = [IO.File]::ReadAllBytes($kubeAuthorityBackup)
            Remove-Item -LiteralPath $kubeAuthorityBackup
            [IO.File]::WriteAllText($metadataPath, ($legacyMetadata | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
            Mock Unprotect-LocalMachineText { return '{}' }
            $legacyRecord = Read-ValidatedGuardBackup -Name $backupName
            $legacyRecord.StatePaths.SocketName | Should -Be 'guard-custom'
            $legacyAuthorityPath = Join-Path $backupPath 'authority.hmac'
            $legacyAuthorityBytes = [IO.File]::ReadAllBytes($legacyAuthorityPath)
            Remove-Item -LiteralPath $legacyAuthorityPath
            { Read-ValidatedGuardBackup -Name $backupName } | Should -Throw '*authority.hmac*missing*'
            [IO.File]::WriteAllBytes($legacyAuthorityPath, $legacyAuthorityBytes)
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $kubeAuthorityBackup) | Out-Null
            [IO.File]::WriteAllBytes($kubeAuthorityBackup, $kubeAuthorityBytes)
            [IO.File]::WriteAllText($metadataPath, ($metadata | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))

            [IO.File]::WriteAllText($statePaths.StateDb, 'mutated-db', [Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText("$($statePaths.StateDb)-wal", 'mutated-wal', [Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText($statePaths.AuthorityKey, 'mutated-key', [Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText($KubeConfig, 'mutated-context', [Text.UTF8Encoding]::new($false))
            $backupRecord = [pscustomobject]@{
                Path = $backupPath
                Metadata = $metadata
                Environment = $snapshot.Environment
                StatePaths = $statePaths
            }
            Restore-GuardInstallation -BackupRecord $backupRecord -GuardSid $script:TestGuardSid
            [IO.File]::ReadAllText($statePaths.StateDb) | Should -Be 'custom-db'
            [IO.File]::ReadAllText("$($statePaths.StateDb)-wal") | Should -Be 'custom-wal'
            [IO.File]::ReadAllText($statePaths.AuthorityKey) | Should -Be 'custom-key'
            [IO.File]::ReadAllText($KubeConfig) | Should -Be 'legacy-context'
            [IO.File]::ReadAllText($defaultDb) | Should -Be 'default-decoy'
            [IO.File]::ReadAllText($defaultKey) | Should -Be 'default-decoy-key'
            Should -Invoke Set-ExactFileSystemAcl -Times 2 -Exactly -ParameterFilter {
                $Path -eq $statePaths.AuthorityKey -and $OwnerSid -eq $script:TestGuardSid
            }
            Should -Invoke Set-ServiceEnvironment -Times 1 -Exactly -ParameterFilter {
                $Environment['KUBECONFIG'] -eq $KubeConfig
            }

            [IO.File]::WriteAllText($legacyKubeConfig, 'stale-legacy-context', [Text.UTF8Encoding]::new($false))
            $snapshot.Environment = @{ KUBECONFIG = $KubeConfig }
            $activeBackupName = New-GuardBackup -Snapshot $snapshot -BeforeVersion '1.2.3' -GuardSid $script:TestGuardSid
            $activeBackupPath = Join-Path $BackupRoot $activeBackupName
            [IO.File]::ReadAllText((Join-Path $activeBackupPath 'config\kube\config')) | Should -Be 'legacy-context'

            Remove-Item -LiteralPath $statePaths.AuthorityKey
            Remove-Item -LiteralPath $KubeConfig
            Remove-Item -LiteralPath $legacyKubeConfig
            $snapshot.AuthorityKeyPresent = $false
            $snapshot.Environment = @{
                KUBECONFIG = $legacyKubeConfig
                GUARD_CHILD_ENV = 'KUBECONFIG'
            }
            $releasedLayoutBackupName = New-GuardBackup -Snapshot $snapshot -BeforeVersion '1.2.3' -GuardSid $script:TestGuardSid
            $releasedLayoutBackupPath = Join-Path $BackupRoot $releasedLayoutBackupName
            $releasedLayoutMetadataPath = Join-Path $releasedLayoutBackupPath 'metadata.json'
            $releasedLayoutMetadata = Get-Content -LiteralPath $releasedLayoutMetadataPath -Raw | ConvertFrom-Json
            $releasedLayoutMetadata.authority_key_present | Should -BeFalse
            $releasedLayoutMetadata.kube_authority_present | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $releasedLayoutBackupPath 'authority.hmac') | Should -BeFalse
            $releasedEnvironment = Get-Content -LiteralPath (Join-Path $releasedLayoutBackupPath 'service-environment.dpapi') -Raw | ConvertFrom-Json
            $releasedEnvironment.PSObject.Properties.Name | Should -Not -Contain 'KUBECONFIG'
            $releasedEnvironment.PSObject.Properties.Name | Should -Not -Contain 'GUARD_CHILD_ENV'

            $releasedLayoutMetadata.metadata_schema = 2
            foreach ($property in @('socket_name', 'authority_key', 'authority_key_present', 'api_revert_root', 'kube_authority_present')) {
                $releasedLayoutMetadata.PSObject.Properties.Remove($property)
            }
            [IO.File]::WriteAllText($releasedLayoutMetadataPath, ($releasedLayoutMetadata | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
            Mock Unprotect-LocalMachineText { return (@{ KUBECONFIG = 'C:\ProgramData\Guard\kube\config' } | ConvertTo-Json -Compress) }
            { Read-ValidatedGuardBackup -Name $releasedLayoutBackupName } | Should -Throw '*did not capture*'
            Mock Unprotect-LocalMachineText { return '{}' }
            $releasedLayoutRecord = Read-ValidatedGuardBackup -Name $releasedLayoutBackupName
            $releasedLayoutRecord.Metadata.authority_key_present | Should -BeFalse
            $releasedLayoutRecord.StatePaths.AuthorityKey | Should -Be $statePaths.AuthorityKey

            [IO.File]::WriteAllText($statePaths.AuthorityKey, 'replacement-key', [Text.UTF8Encoding]::new($false))
            Restore-GuardInstallation -BackupRecord $releasedLayoutRecord -GuardSid $script:TestGuardSid
            Test-Path -LiteralPath $statePaths.AuthorityKey | Should -BeFalse
            Test-Path -LiteralPath $KubeConfig | Should -BeFalse
            $script:lastRestoredServiceEnvironment.ContainsKey('KUBECONFIG') | Should -BeFalse
        }
        finally {
            $DataDir = $saved[0]
            $ConfigRoot = $saved[1]
            $KubeDir = $saved[2]
            $KubeConfig = $saved[3]
            $BackupRoot = $saved[4]
            $StagingDir = $saved[5]
            $DeployedExe = $saved[6]
            $DeployedOperatorScript = $saved[7]
            $VerbsPath = $saved[8]
        }
    }

    It 'retries and verifies operator artifact cleanup' {
        $script:cleanupAttempts = 0
        $taskName = New-GuardTestTaskName
        $script:operatorTaskFixture = [pscustomobject]@{ TaskName = $taskName; State = 'Ready' }
        Mock Get-ScheduledTask {
            if ($script:cleanupAttempts -ge 3) { return $null }
            return $script:operatorTaskFixture
        }
        Mock Unregister-ScheduledTask {
            $script:cleanupAttempts++
            if ($script:cleanupAttempts -lt 3) { throw 'fixture cleanup failure' }
        }
        Mock Start-Sleep { return }
        $output = Join-Path $TaskOutDir "$taskName.out"
        { Remove-GuardOperatorArtifacts -TaskName $taskName -OutputFile $output } | Should -Not -Throw
        Should -Invoke Unregister-ScheduledTask -Times 3 -Exactly
    }

    It 'surfaces operator artifact cleanup that remains incomplete' {
        $taskName = New-GuardTestTaskName
        $script:operatorTaskFixture = [pscustomobject]@{ TaskName = $taskName; State = 'Ready' }
        Mock Get-ScheduledTask { return $script:operatorTaskFixture }
        Mock Unregister-ScheduledTask { throw 'fixture cleanup failure' }
        Mock Start-Sleep { return }
        $output = Join-Path $TaskOutDir "$taskName.out"
        { Remove-GuardOperatorArtifacts -TaskName $taskName -OutputFile $output } | Should -Throw '*after 3 attempts*'
    }

    It 'retries output deletion and verifies absence' {
        $script:outputPresent = $true
        $script:outputDeleteAttempts = 0
        Mock Get-ScheduledTask { return $null }
        Mock Test-Path {
            param($LiteralPath)
            if ($LiteralPath -like '*.status') { return $false }
            return $script:outputPresent
        }
        Mock Remove-Item {
            $script:outputDeleteAttempts++
            if ($script:outputDeleteAttempts -lt 3) { throw 'fixture output deletion failure' }
            $script:outputPresent = $false
        }
        Mock Start-Sleep { return }
        $taskName = New-GuardTestTaskName
        $output = Join-Path $TaskOutDir "$taskName.out"
        { Remove-GuardOperatorArtifacts -TaskName $taskName -OutputFile $output } | Should -Not -Throw
        Should -Invoke Remove-Item -Times 3 -Exactly
    }

    It 'removes the SYSTEM task and output in normal mode' {
        $oldTaskOutDir = $TaskOutDir
        $TaskOutDir = Join-Path $TestDrive 'normal-output'
        New-Item -ItemType Directory -Path $TaskOutDir | Out-Null
        $taskName = New-GuardTestTaskName
        $output = Join-Path $TaskOutDir "$taskName.out"
        Set-Content -LiteralPath $output -Value 'diagnostic'
        Set-Content -LiteralPath "$output.status" -Value '125' -NoNewline
        $script:taskPresent = $true
        $script:operatorTaskFixture = [pscustomobject]@{ TaskName = $taskName; State = 'Ready' }
        Mock Get-ScheduledTask { if ($script:taskPresent) { return $script:operatorTaskFixture } }
        Mock Unregister-ScheduledTask { $script:taskPresent = $false }
        try {
            Remove-GuardOperatorArtifacts -TaskName $taskName -OutputFile $output
            $script:taskPresent | Should -BeFalse
            Test-Path -LiteralPath $output | Should -BeFalse
            Test-Path -LiteralPath "$output.status" | Should -BeFalse
            Should -Invoke Unregister-ScheduledTask -Times 1 -Exactly
        }
        finally { $TaskOutDir = $oldTaskOutDir }
    }

    It 'removes the SYSTEM task and retains only sanitized output in diagnostic mode' {
        $oldTaskOutDir = $TaskOutDir
        $TaskOutDir = Join-Path $TestDrive 'preserved-output'
        New-Item -ItemType Directory -Path $TaskOutDir | Out-Null
        $taskName = New-GuardTestTaskName
        $output = Join-Path $TaskOutDir "$taskName.out"
        Set-Content -LiteralPath $output -Value 'raw unsanitized output'
        Set-Content -LiteralPath "$output.status" -Value '1' -NoNewline
        $script:taskPresent = $true
        $script:operatorTaskFixture = [pscustomobject]@{ TaskName = $taskName; State = 'Ready' }
        Mock Get-ScheduledTask { if ($script:taskPresent) { return $script:operatorTaskFixture } }
        Mock Unregister-ScheduledTask { $script:taskPresent = $false }
        $token = New-GuardTestIdentifier
        try {
            Remove-GuardOperatorArtifacts -TaskName $taskName -OutputFile $output -PreserveOutput -DiagnosticOutput "token=$token`ncontrol`0value"
            $preserved = Get-Content -LiteralPath $output -Raw
            $script:taskPresent | Should -BeFalse
            Test-Path -LiteralPath "$output.status" | Should -BeFalse
            $preserved | Should -Match 'token=\[redacted\]'
            $preserved | Should -Match 'control\?value'
            $preserved | Should -Not -Match ([regex]::Escape($token))
            Should -Invoke Unregister-ScheduledTask -Times 1 -Exactly
        }
        finally { $TaskOutDir = $oldTaskOutDir }
    }

    It 'bounds preserved diagnostic output including its truncation marker' {
        $sanitized = ConvertTo-SanitizedDiagnosticOutput -Value ('x' * 20000)
        $sanitized.Length | Should -Be 16384
        $sanitized | Should -Match '\[output truncated\]$'
    }

    It 'classifies service startup logs without returning free-form content' {
        $savedDataDir = $DataDir
        try {
            $DataDir = Join-Path $TestDrive "service-log-$(New-GuardTestIdentifier)"
            New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
            [IO.File]::WriteAllText(
                (Join-Path $DataDir 'guard.log'),
                'ERROR guard service: daemon terminated with error: failed to load verb catalog credential=fixture'
            )

            (Get-GuardServiceStartupDiagnostic) | Should -Be 'verb-catalog'
        }
        finally { $DataDir = $savedDataDir }
    }

    It 'classifies service dispatcher startup failures without returning free-form content' {
        $savedDataDir = $DataDir
        try {
            $DataDir = Join-Path $TestDrive "service-dispatcher-log-$(New-GuardTestIdentifier)"
            New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
            [IO.File]::WriteAllText(
                (Join-Path $DataDir 'guard.log'),
                'ERROR guard service: service dispatcher error: fixture detail'
            )

            (Get-GuardServiceStartupDiagnostic) | Should -Be 'service-dispatcher'
        }
        finally { $DataDir = $savedDataDir }
    }

    It 'classifies service-controller failures when no daemon log is available' {
        $savedDataDir = $DataDir
        try {
            $DataDir = Join-Path $TestDrive "missing-service-log-$(New-GuardTestIdentifier)"
            Mock Get-CimInstance { return [pscustomobject]@{ Win32ExitCode = 1069 } }

            (Get-GuardServiceStartupDiagnostic) | Should -Be 'service-account-logon'
        }
        finally { $DataDir = $savedDataDir }
    }

    It 'classifies service-controller event messages without returning free-form content' {
        $savedDataDir = $DataDir
        try {
            $DataDir = Join-Path $TestDrive "missing-service-event-log-$(New-GuardTestIdentifier)"
            Mock Get-CimInstance { return [pscustomobject]@{ Win32ExitCode = 0 } }
            Mock Get-WinEvent {
                return [pscustomobject]@{
                    Id = 7000
                    Message = 'The Guard consequence gate service failed to start because the executable is not a valid Win32 application. credential=fixture'
                }
            }

            (Get-GuardServiceStartupDiagnostic) | Should -Be 'service-binary-invalid'
            Should -Invoke Get-WinEvent -Times 1 -Exactly
        }
        finally { $DataDir = $savedDataDir }
    }

    It 'classifies numeric service-controller event codes without returning free-form content' {
        $savedDataDir = $DataDir
        try {
            $DataDir = Join-Path $TestDrive "missing-service-code-log-$(New-GuardTestIdentifier)"
            Mock Get-CimInstance { return [pscustomobject]@{ Win32ExitCode = 0 } }
            Mock Get-WinEvent {
                return [pscustomobject]@{
                    Id = 7000
                    Message = 'The Guard consequence gate service failed to start.'
                    Properties = @(
                        [pscustomobject]@{ Value = 'Guard consequence gate' },
                        [pscustomobject]@{ Value = '%%1053' }
                    )
                }
            }

            (Get-GuardServiceStartupDiagnostic) | Should -Be 'service-handshake-timeout'
            Should -Invoke Get-WinEvent -Times 1 -Exactly
        }
        finally { $DataDir = $savedDataDir }
    }

    It 'creates the service log without truncating existing diagnostics' {
        $savedDataDir = $DataDir
        try {
            $DataDir = Join-Path $TestDrive "service-log-initialization-$(New-GuardTestIdentifier)"
            Initialize-GuardServiceLog
            $serviceLog = Join-Path $DataDir 'guard.log'
            Test-Path -LiteralPath $serviceLog -PathType Leaf | Should -BeTrue
            [IO.File]::WriteAllText($serviceLog, 'retained diagnostic')

            Initialize-GuardServiceLog

            [IO.File]::ReadAllText($serviceLog) | Should -Be 'retained diagnostic'
        }
        finally { $DataDir = $savedDataDir }
    }

    It 'waits through a transient service-controller start transition' {
        $service = New-GuardTestServiceController -Status 'Stopped' -StatusAfterWait 'Running'
        $name = "guard-$(New-GuardTestIdentifier)"
        Mock Get-Service { return $service }
        Mock Start-Service { $service.Status = 'StartPending' }

        Start-GuardService -Name $name

        $service.Status | Should -Be 'Running'
        $service.WaitCalls | Should -Be 1
        Should -Invoke Start-Service -Times 1 -Exactly
    }

    It 're-queries and waits when Start-Service reports a pending transition as an error' {
        $service = New-GuardTestServiceController -Status 'Stopped' -StatusAfterWait 'Running'
        $name = "guard-$(New-GuardTestIdentifier)"
        $diagnostic = "start-pending-$(New-GuardTestIdentifier)"
        Mock Get-Service { return $service }
        Mock Start-Service {
            $service.Status = 'StartPending'
            throw $diagnostic
        }
        Mock Start-Sleep { return }

        Start-GuardService -Name $name

        $service.Status | Should -Be 'Running'
        $service.WaitCalls | Should -Be 1
        Should -Invoke Get-Service -Times 2 -Exactly
        Should -Invoke Start-Service -Times 1 -Exactly
        Should -Invoke Start-Sleep -Times 0 -Exactly
    }

    It 'bounds failed service starts and reports the final status and error' {
        $service = New-GuardTestServiceController -Status 'Stopped' -StatusAfterWait 'Stopped'
        $name = "guard-$(New-GuardTestIdentifier)"
        $diagnostic = "start-failed-$(New-GuardTestIdentifier)"
        Mock Get-Service { return $service }
        Mock Start-Service { throw $diagnostic }
        Mock Get-GuardServiceStartupDiagnostic { return 'verb-catalog' }
        Mock Start-Sleep { return }
        $caught = $null

        try {
            Start-GuardService -Name $name
        }
        catch {
            $caught = $_.Exception.Message
        }

        $caught | Should -Be "Guard service '$name' did not reach Running after 3 bounded state-transition attempts. Last observed status: 'Stopped'. Last transition error: $diagnostic; daemon diagnostic: verb-catalog"
        $service.WaitCalls | Should -Be 0
        Should -Invoke Get-Service -Times 6 -Exactly
        Should -Invoke Start-Service -Times 3 -Exactly
        Should -Invoke Get-GuardServiceStartupDiagnostic -Times 1 -Exactly
        Should -Invoke Start-Sleep -Times 2 -Exactly
    }

    It 'temporarily enables a disabled service for verification and restores disabled stopped state' {
        $metadata = [pscustomobject]@{
            service_path_name = '"C:\Program Files\Guard\guard.exe" "server" "start" "--socket" "guard" "--state-db" "C:\ProgramData\Guard\state.db"'
            start_mode = 'Disabled'
            was_running = $false
            binary_sha256 = New-GuardTestDigest
            binary_version = '1.2.3'
        }
        Mock Set-GuardServiceConfiguration { return }
        Mock Set-ServiceEnvironment { return }
        Mock Set-DeploymentAcls { return }
        Mock Start-GuardService { return }
        Mock Verify-GuardService { return }
        Mock Assert-DeploymentAcls { return }
        Mock Wait-ServiceStopped { return }
        Complete-RestoredServiceVerification -Metadata $metadata -Environment @{} -GuardSid $script:TestGuardSid -AuthorityKeyPresent $false
        Should -Invoke Set-GuardServiceConfiguration -Times 1 -Exactly -ParameterFilter { $StartMode -eq 'Manual' }
        Should -Invoke Start-GuardService -Times 1 -Exactly
        Should -Invoke Verify-GuardService -Times 1 -Exactly
        Should -Invoke Wait-ServiceStopped -Times 1 -Exactly
        Should -Invoke Set-GuardServiceConfiguration -Times 1 -Exactly -ParameterFilter { $StartMode -eq 'Disabled' }
    }

    It 'excludes the service from staging, backups, and task output' {
        $entries = Get-AdministrativeAclEntries
        @($entries).Count | Should -Be 2
        @($entries | ForEach-Object Sid) | Should -Contain $SidSystem
        @($entries | ForEach-Object Sid) | Should -Contain $SidAdmins
        @($entries | Where-Object Sid -like 'S-1-5-80-*').Count | Should -Be 0
    }

    It 'uses SYSTEM for operator tasks and provides validated post-success rollback' {
        $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'install-guard.ps1') -Raw
        $source | Should -Match '\$OperatorAccount = ''SYSTEM'''
        $source | Should -Match 'New-ScheduledTaskPrincipal -UserId \$OperatorAccount -LogonType ServiceAccount'
        $source | Should -Match 'Read-ValidatedGuardBackup'
        $source | Should -Match 'service-environment\.dpapi'
        $source | Should -Match "'sqlite/state\.db'"
        $source | Should -Match 'Verify-GuardService'
        $source | Should -Match 'Assert-DeploymentAcls'
        $source | Should -Match 'Set-ServiceRegistryAcl'
        $source | Should -Match '\[IO\.File\]::Move\(\$temporary, \$TransactionJournal, \$true\)'
        $source | Should -Match '\$DeployedOperatorScript = Join-Path \$InstallRoot ''guard-operator\.ps1'''
        $source | Should -Match "RelativePath 'guard-operator\.ps1'"
        $source | Should -Match 'Install-FileAtomically -Source \$operatorScriptSource -Destination \$DeployedOperatorScript'
        $source | Should -Match 'operator_script_present'
        $source | Should -Not -Match 'cmd\.exe\s+/c'
        $source | Should -Not -Match 'New-ScheduledTaskPrincipal -UserId \$ServiceAccount'
    }

    It 'persists absent-install recovery state before staging and service creation' {
        $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'install-guard.ps1') -Raw
        $installSource = ($source -split '(?m)^function Invoke-Install\s*\{\s*', 2)[1] -split '(?m)^function Invoke-Rollback\s*\{\s*', 2 | Select-Object -First 1
        $startIndex = $installSource.IndexOf('$transaction = Start-NewInstallationTransaction')
        $stageIndex = $installSource.IndexOf('$candidate = Stage-VerifiedGuardCandidate')
        $mutatingIndex = $installSource.IndexOf('Set-NewInstallationTransactionMutating')
        $createIndex = $installSource.IndexOf('& sc.exe create')

        $startIndex | Should -BeGreaterThan -1
        $startIndex | Should -BeLessThan $stageIndex
        $stageIndex | Should -BeLessThan $mutatingIndex
        $mutatingIndex | Should -BeLessThan $createIndex
    }

    It 'journals a complete backup before deployment authority changes' {
        $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'install-guard.ps1') -Raw
        $installSource = ($source -split '(?m)^function Invoke-Install\s*\{\s*', 2)[1] -split '(?m)^function Invoke-Rollback\s*\{\s*', 2 | Select-Object -First 1
        $backupIndex = $installSource.IndexOf('$backupName = New-GuardBackup')
        $mutatingIndex = $installSource.IndexOf('Set-GuardTransactionPhase -Transaction $transaction -Phase mutating')
        $aclIndex = $installSource.IndexOf('Set-DeploymentAcls -GuardSid $guardSid')
        $registryAclIndex = $installSource.IndexOf('Set-ServiceRegistryAcl -GuardSid $guardSid')

        $backupIndex | Should -BeGreaterThan -1
        $backupIndex | Should -BeLessThan $mutatingIndex
        $mutatingIndex | Should -BeLessThan $aclIndex
        $mutatingIndex | Should -BeLessThan $registryAclIndex
    }

    It 'discovers active kube authority before completing the managed environment' {
        $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'install-guard.ps1') -Raw
        $installSource = ($source -split '(?m)^function Invoke-Install\s*\{\s*', 2)[1] -split '(?m)^function Invoke-Rollback\s*\{\s*', 2 | Select-Object -First 1
        $mergeIndex = $installSource.IndexOf('$serviceEnvironment = Merge-ServiceEnvironment')
        $copyIndex = $installSource.IndexOf('Copy-KubeConfigToAuthorityRoot')
        $convertIndex = $installSource.IndexOf('$serviceEnvironment = Convert-LegacyKubeEnvironment')
        $completeIndex = $installSource.IndexOf('$serviceEnvironment = Complete-ManagedKubeEnvironment')

        $mergeIndex | Should -BeGreaterThan -1
        $mergeIndex | Should -BeLessThan $copyIndex
        $copyIndex | Should -BeLessThan $convertIndex
        $convertIndex | Should -BeLessThan $completeIndex
    }

    It 'repairs private service ACLs before restarting an unmutated transaction' {
        $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'install-guard.ps1') -Raw
        $recoverySource = ($source -split 'function Recover-UnmutatedGuardTransaction', 2)[1] -split 'function Recover-GuardTransaction', 2 | Select-Object -First 1
        $repairIndex = $recoverySource.IndexOf('Restore-SnapshotPrivateServiceAcls')
        $startIndex = $recoverySource.IndexOf('Start-GuardService -Name $ServiceName')
        $helperSource = ($source -split 'function Restore-SnapshotPrivateServiceAcls', 2)[1] -split 'function Recover-UnmutatedGuardTransaction', 2 | Select-Object -First 1

        $repairIndex | Should -BeGreaterThan -1
        $repairIndex | Should -BeLessThan $startIndex
        $helperSource | Should -Match 'Set-ExactFileSystemAcl -Path \$StatePaths\.AuthorityKey'
        $helperSource | Should -Match 'Protect-PrivateServiceTree -Path \$privateRoot'
    }

    It 'uses release-version backup names and deployment metadata independent of the state schema' {
        $BackupMetadataSchema | Should -Be 5
        (New-GuardTestBackupName) | Should -Match '^before-v[0-9]+\.[0-9]+\.[0-9]+-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{32}$'
    }

    It 'requires release smoke helpers to pass explicit state paths and expected state values' {
        $workflow = Join-Path $PSScriptRoot '..\..\.github\workflows\release.yml'
        if (Test-Path -LiteralPath $workflow -PathType Leaf) {
            $workflowSource = Get-Content -LiteralPath $workflow -Raw
            $workflowSource | Should -Match 'function Get-DatabaseHashes\(\[Parameter\(Mandatory\)\]\$StatePaths\)'
            $workflowSource | Should -Match 'Assert-DeploymentAcls -GuardSid \$guardSid -StatePaths \$statePaths'
            $workflowSource | Should -Match 'Verify-GuardService .* -ExpectedStateDb \$statePaths\.StateDb -ExpectedSocket \$statePaths\.SocketName'
        }
    }

    It 'resolves repository assets only for installation actions' {
        $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'install-guard.ps1') -Raw
        $parameterBlock = ($source -split '\)\s*\r?\n\r?\n\$ErrorActionPreference', 2)[0]
        $parameterBlock | Should -Not -Match 'Resolve-Path'
        $DeployedOperatorScript | Should -Be 'C:\Program Files\Guard\guard-operator.ps1'
    }
}
