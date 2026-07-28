BeforeAll {
    $InstallerTestModeBeforeTests = $env:GUARD_INSTALLER_TEST_MODE
    $env:GUARD_INSTALLER_TEST_MODE = '1'
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
    }

    It 'maps ordinary, once, N-use, and batch approvals' {
        $Action = 'access-approve'
        $Reference = @('gr-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'gr-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')
        (Get-GuardActionArguments) -join ' ' | Should -Be 'access approve gr-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa gr-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --socket guard'

        $ApprovalMode = 'once'
        (Get-GuardActionArguments) -join ' ' | Should -Be 'access approve gr-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa gr-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --once --socket guard'

        $ApprovalMode = 'uses'
        $Uses = 3
        (Get-GuardActionArguments) -join ' ' | Should -Be 'access approve gr-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa gr-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --uses 3 --socket guard'
    }

    It 'maps deny, extend, revoke, list, show, confirm, and revert' {
        $Action = 'access-deny'
        $Reference = @('gr-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
        $Reason = 'outside the approved task'
        (Get-GuardActionArguments) -join ' ' | Should -Be 'access deny gr-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --reason outside the approved task --socket guard'

        $Action = 'access-extend'
        $Reference = @('session:0123456789abcdef')
        $Intent = 'Inspect service health.'
        $ApprovalMode = 'once'
        (Get-GuardActionArguments) -join ' ' | Should -Be 'access extend session:0123456789abcdef Inspect service health. --once --socket guard'

        $Action = 'access-revoke'
        $Reference = @('agent:S-1-5-21-1000')
        $ApprovalMode = 'ordinary'
        (Get-GuardActionArguments) -join ' ' | Should -Be 'access revoke agent:S-1-5-21-1000 --socket guard'

        $Action = 'access-list'
        $Reference = @()
        (Get-GuardActionArguments) -join ' ' | Should -Be 'access list --socket guard'

        $Action = 'access-show'
        foreach ($inspectable in @('gr-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'session:0123456789abcdef')) {
            $Reference = @($inspectable)
            (Get-GuardActionArguments) -join ' ' | Should -Be "access show $inspectable --socket guard"
        }

        foreach ($operatorAction in @('confirm', 'revert')) {
            $Action = $operatorAction
            $Reference = @('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
            (Get-GuardActionArguments) -join ' ' | Should -Be "$operatorAction aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --socket guard"
        }
    }

    It 'maps held execution references through access approve and deny' {
        foreach ($operatorAction in @('access-approve', 'access-deny')) {
            $Action = $operatorAction
            $Reference = @('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
            (Get-GuardActionArguments) -join ' ' | Should -Be (($operatorAction -replace '-', ' ') + ' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --socket guard')
        }
    }

    It 'rejects malformed references, control characters, and invalid use counts' {
        $Action = 'access-approve'
        $Reference = @('request & whoami')
        { Get-GuardActionArguments } | Should -Throw

        $Action = 'access-extend'
        $Reference = @('session:0123456789abcdef')
        $Intent = "inspect`nwhoami"
        { Get-GuardActionArguments } | Should -Throw

        $Action = 'access-approve'
        $Reference = @('gr-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
        $ApprovalMode = 'uses'
        $Uses = 0
        { Get-GuardActionArguments } | Should -Throw

        $Action = 'confirm'
        $Reference = @('gr-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
        { Get-GuardActionArguments } | Should -Throw

        $Action = 'access-revoke'
        $Reference = @('session:0123456789abcdef', 'agent:S-1-5-21-1000')
        { Get-GuardActionArguments } | Should -Throw
    }

    It 'keeps untrusted prose out of executable task syntax' {
        $Action = 'access-deny'
        $Reference = @('gr-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
        $Reason = 'maintenance & whoami | calc.exe > output'
        $arguments = Get-GuardActionArguments
        $output = Join-Path $TaskOutDir 'guard-op-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.out'
        $payload = New-GuardOperatorPayload -GuardExe $DeployedExe -Arguments $arguments -OutputFile $output
        $decodedPayload = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($payload))

        $decodedPayload | Should -Not -Match ([regex]::Escape($Reason))
        $decodedPayload | Should -Not -Match 'cmd\.exe'
        $decodedPayload | Should -Match ([regex]::Escape((ConvertTo-Base64Utf8 $Reason)))
    }

    It 'rejects task executable and output paths outside installer-owned roots' {
        $Action = 'access-list'
        $arguments = Get-GuardActionArguments
        { New-GuardOperatorPayload -GuardExe 'C:\Windows\System32\whoami.exe' -Arguments $arguments -OutputFile (Join-Path $TaskOutDir 'guard-op-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.out') } | Should -Throw
        { New-GuardOperatorPayload -GuardExe $DeployedExe -Arguments $arguments -OutputFile 'C:\Temp\guard-op-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.out' } | Should -Throw
    }

    It 'preserves valid JSON for mixed decisions and propagates its native status' {
        $body = '{"schema_version":1,"items":[{"success":true},{"success":false}],"message":"token=synthetic-fixture"}'
        $result = Resolve-GuardOperatorResult -RawOutput $body -NativeStatus 1 -JsonOutput
        $result.Output | Should -Be $body
        $result.ExitCode | Should -Be 1
        ($result.Output | ConvertFrom-Json).items.Count | Should -Be 2
    }

    It 'does not truncate large structured output' {
        $body = '{"schema_version":1,"body":"' + ('x' * 20000) + '"}'
        $result = Resolve-GuardOperatorResult -RawOutput $body -NativeStatus 0 -JsonOutput
        $result.Output.Length | Should -Be $body.Length
        $result.Output | Should -Not -Match 'output truncated'
    }

    It 'rejects malformed structured output without echoing it' {
        { Resolve-GuardOperatorResult -RawOutput '{fixture-token=do-not-echo' -NativeStatus 1 -JsonOutput } |
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
        $ExpectedSha256 = 'ab' * 32
        Assert-ExpectedCandidateHash | Should -Be ('ab' * 32)
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
        $merged['GUARD_CHILD_ENV'] | Should -Be 'EXISTING_PATH,KUBECONFIG'
        $merged['KUBECONFIG'] | Should -Be $KubeConfig
    }

    It 'lets an allowlisted input replace only its matching value' {
        $merged = Merge-ServiceEnvironment -Existing @{ GUARD_LLM_API_KEY = 'old-placeholder'; KEEP = 'yes' } -Imported @{ GUARD_LLM_API_KEY = 'new-placeholder' }
        $merged['GUARD_LLM_API_KEY'] | Should -Be 'new-placeholder'
        $merged['KEEP'] | Should -Be 'yes'
    }

    It 'enumerates the complete SQLite file set' {
        (Get-DatabasePaths -Database 'C:\ProgramData\Guard\state.db') -join '|' | Should -Be 'C:\ProgramData\Guard\state.db|C:\ProgramData\Guard\state.db-wal|C:\ProgramData\Guard\state.db-shm|C:\ProgramData\Guard\state.db-journal'
    }

    It 'gives the service read-execute without write in program and config ACLs' {
        $guardSid = 'S-1-5-80-12345'
        $entries = Get-ServiceReadAclEntries -GuardSid $guardSid
        $guardEntry = @($entries | Where-Object Sid -eq $guardSid)
        $guardEntry.Count | Should -Be 1
        (([int64]$guardEntry[0].Rights) -band ([int64][Security.AccessControl.FileSystemRights]::Write)) | Should -Be 0
        (([int64]$guardEntry[0].Rights) -band ([int64][Security.AccessControl.FileSystemRights]::ReadAndExecute)) | Should -Be ([int64][Security.AccessControl.FileSystemRights]::ReadAndExecute)
    }

    It 'constructs protected directory ACLs with only explicit inheritable rules' {
        $guardSid = 'S-1-5-80-12345'
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
        $ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
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

        $custom = '"C:\Program Files\Guard\guard.exe" "server" "start" "--audit-log" "D:\custom\audit.log"'
        Test-InstallerManagedServicePath -PathName $custom | Should -BeFalse
        Resolve-InstallServicePath -ExistingPath $custom -DesiredPath $withKey | Should -Be $custom
    }

    It 'round-trips API revert bodies and reapplies the daemon-only ACL' {
        $oldDataDir = $DataDir
        $oldStagingDir = $StagingDir
        $DataDir = Join-Path $TestDrive 'data'
        $StagingDir = Join-Path $TestDrive 'staging-api'
        New-Item -ItemType Directory -Path $StagingDir | Out-Null
        $apiRoot = Get-ApiRevertRoot
        New-Item -ItemType Directory -Path (Join-Path $apiRoot 'nested') -Force | Out-Null
        $body = Join-Path $apiRoot 'nested\body.bin'
        [IO.File]::WriteAllBytes($body, [byte[]](1, 2, 3, 4))
        $backupPath = Join-Path $TestDrive 'backup'
        New-Item -ItemType Directory -Path $backupPath | Out-Null
        Mock Reset-TreeForAdministrativeMaintenance { return }
        Mock Protect-PrivateServiceTree { return }
        try {
            $files = @(Copy-ApiRevertBackup -BackupPath $backupPath -GuardSid 'S-1-5-80-12345')
            $files.Count | Should -Be 1
            [IO.File]::WriteAllBytes($body, [byte[]](9, 9))
            $record = [pscustomobject]@{
                Path = $backupPath
                Metadata = [pscustomobject]@{ api_reverts_present = $true; files = $files }
            }
            Restore-ApiRevertBackup -BackupRecord $record -GuardSid 'S-1-5-80-12345'
            ([BitConverter]::ToString([IO.File]::ReadAllBytes($body)) -replace '-', '') | Should -Be '01020304'
            Should -Invoke Protect-PrivateServiceTree -Times 2 -Exactly
        }
        finally {
            $DataDir = $oldDataDir
            $StagingDir = $oldStagingDir
        }
    }

    It 'retries and verifies operator artifact cleanup' {
        $script:cleanupAttempts = 0
        Mock Get-ScheduledTask {
            if ($script:cleanupAttempts -ge 3) { return $null }
            return [pscustomobject]@{ TaskName = 'guard-op-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; State = 'Ready' }
        }
        Mock Unregister-ScheduledTask {
            $script:cleanupAttempts++
            if ($script:cleanupAttempts -lt 3) { throw 'fixture cleanup failure' }
        }
        Mock Start-Sleep { return }
        $output = Join-Path $TaskOutDir 'guard-op-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.out'
        { Remove-GuardOperatorArtifacts -TaskName 'guard-op-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' -OutputFile $output } | Should -Not -Throw
        Should -Invoke Unregister-ScheduledTask -Times 3 -Exactly
    }

    It 'surfaces operator artifact cleanup that remains incomplete' {
        Mock Get-ScheduledTask { [pscustomobject]@{ TaskName = 'guard-op-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'; State = 'Ready' } }
        Mock Unregister-ScheduledTask { throw 'fixture cleanup failure' }
        Mock Start-Sleep { return }
        $output = Join-Path $TaskOutDir 'guard-op-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.out'
        { Remove-GuardOperatorArtifacts -TaskName 'guard-op-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' -OutputFile $output } | Should -Throw '*after 3 attempts*'
    }

    It 'retries output deletion and verifies absence' {
        $script:outputPresent = $true
        $script:outputDeleteAttempts = 0
        Mock Get-ScheduledTask { return $null }
        Mock Test-Path { return $script:outputPresent }
        Mock Remove-Item {
            $script:outputDeleteAttempts++
            if ($script:outputDeleteAttempts -lt 3) { throw 'fixture output deletion failure' }
            $script:outputPresent = $false
        }
        Mock Start-Sleep { return }
        $output = Join-Path $TaskOutDir 'guard-op-cccccccccccccccccccccccccccccccc.out'
        { Remove-GuardOperatorArtifacts -TaskName 'guard-op-cccccccccccccccccccccccccccccccc' -OutputFile $output } | Should -Not -Throw
        Should -Invoke Remove-Item -Times 3 -Exactly
    }

    It 'removes the SYSTEM task and output in normal mode' {
        $oldTaskOutDir = $TaskOutDir
        $TaskOutDir = Join-Path $TestDrive 'normal-output'
        New-Item -ItemType Directory -Path $TaskOutDir | Out-Null
        $output = Join-Path $TaskOutDir 'guard-op-dddddddddddddddddddddddddddddddd.out'
        Set-Content -LiteralPath $output -Value 'diagnostic'
        $script:taskPresent = $true
        Mock Get-ScheduledTask { if ($script:taskPresent) { return [pscustomobject]@{ TaskName = 'guard-op-dddddddddddddddddddddddddddddddd'; State = 'Ready' } } }
        Mock Unregister-ScheduledTask { $script:taskPresent = $false }
        try {
            Remove-GuardOperatorArtifacts -TaskName 'guard-op-dddddddddddddddddddddddddddddddd' -OutputFile $output
            $script:taskPresent | Should -BeFalse
            Test-Path -LiteralPath $output | Should -BeFalse
            Should -Invoke Unregister-ScheduledTask -Times 1 -Exactly
        }
        finally { $TaskOutDir = $oldTaskOutDir }
    }

    It 'removes the SYSTEM task and retains only sanitized output in diagnostic mode' {
        $oldTaskOutDir = $TaskOutDir
        $TaskOutDir = Join-Path $TestDrive 'preserved-output'
        New-Item -ItemType Directory -Path $TaskOutDir | Out-Null
        $output = Join-Path $TaskOutDir 'guard-op-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.out'
        Set-Content -LiteralPath $output -Value 'raw unsanitized output'
        $script:taskPresent = $true
        Mock Get-ScheduledTask { if ($script:taskPresent) { return [pscustomobject]@{ TaskName = 'guard-op-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'; State = 'Ready' } } }
        Mock Unregister-ScheduledTask { $script:taskPresent = $false }
        try {
            Remove-GuardOperatorArtifacts -TaskName 'guard-op-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' -OutputFile $output -PreserveOutput -DiagnosticOutput "token=visible`ncontrol`0value"
            $preserved = Get-Content -LiteralPath $output -Raw
            $script:taskPresent | Should -BeFalse
            $preserved | Should -Match 'token=\[redacted\]'
            $preserved | Should -Match 'control\?value'
            $preserved | Should -Not -Match 'visible'
            Should -Invoke Unregister-ScheduledTask -Times 1 -Exactly
        }
        finally { $TaskOutDir = $oldTaskOutDir }
    }

    It 'bounds preserved diagnostic output including its truncation marker' {
        $sanitized = ConvertTo-SanitizedDiagnosticOutput -Value ('x' * 20000)
        $sanitized.Length | Should -Be 16384
        $sanitized | Should -Match '\[output truncated\]$'
    }

    It 'temporarily enables a disabled service for verification and restores disabled stopped state' {
        $metadata = [pscustomobject]@{
            service_path_name = '"C:\Program Files\Guard\guard.exe" "server" "start"'
            start_mode = 'Disabled'
            was_running = $false
            binary_sha256 = 'ab' * 32
            binary_version = '1.2.3'
        }
        Mock Set-GuardServiceConfiguration { return }
        Mock Set-ServiceEnvironment { return }
        Mock Set-DeploymentAcls { return }
        Mock Start-Service { return }
        Mock Verify-GuardService { return }
        Mock Assert-DeploymentAcls { return }
        Mock Wait-ServiceStopped { return }
        Complete-RestoredServiceVerification -Metadata $metadata -Environment @{} -GuardSid 'S-1-5-80-12345'
        Should -Invoke Set-GuardServiceConfiguration -Times 1 -Exactly -ParameterFilter { $StartMode -eq 'Manual' }
        Should -Invoke Start-Service -Times 1 -Exactly
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
        $source | Should -Match '\[IO\.File\]::Replace'
        $source | Should -Not -Match 'cmd\.exe\s+/c'
        $source | Should -Not -Match 'New-ScheduledTaskPrincipal -UserId \$ServiceAccount'
    }

    It 'uses release-version backup names and deployment metadata independent of the state schema' {
        $BackupMetadataSchema | Should -Be 2
        'before-v1.2.3-20260727T010203Z-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' | Should -Match '^before-v[0-9]+\.[0-9]+\.[0-9]+-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{32}$'
    }
}
