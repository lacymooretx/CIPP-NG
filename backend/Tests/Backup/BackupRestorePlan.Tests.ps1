# Aspendora fork (Vikunja CIPP-23): restore preview plan and the safe restore-as-new payload rewrite.

BeforeAll {
    . (Join-Path $PSScriptRoot 'BackupFixtures.ps1')
    function Items { param([string]$Json) Get-CIPPBackupItemList -Backup (ConvertFrom-TestBackupJson $Json) }

    $script:BackupJson = New-TestScheduledBackupJson -Ca @(
        (New-TestCAPolicyJson -Name 'Same'),
        (New-TestCAPolicyJson -Name 'Drifted' -State 'enabled'),
        (New-TestCAPolicyJson -Name 'Deleted')
    ) -Intune @(
        (New-TestIntuneRow -Name 'Win - Same'),
        (New-TestIntuneRow -Name 'Win - Deleted')
    )
    # The tenant now: 'Same' unchanged, 'Drifted' switched to report-only, 'Deleted' gone, plus an unrelated policy
    # and a copy restored earlier today that the new suffix must not collide with.
    $script:LiveJson = New-TestScheduledBackupJson -Ca @(
        (New-TestCAPolicyJson -Name 'Same'),
        (New-TestCAPolicyJson -Name 'Drifted' -State 'enabledForReportingButNotEnforced'),
        (New-TestCAPolicyJson -Name 'Unrelated'),
        (New-TestCAPolicyJson -Name 'Deleted (restored 2026-10-31)')
    ) -Intune @(
        (New-TestIntuneRow -Name 'Win - Same')
    )
    $script:BackupItems = Items $script:BackupJson
    $script:LiveItems = Items $script:LiveJson
}

Describe 'Get-CIPPBackupRestorePlan (default restore)' {
    BeforeAll {
        $script:Plan = Get-CIPPBackupRestorePlan -BackupItems $script:BackupItems -LiveItems $script:LiveItems -SafeMode $false -Overwrite $false -RestoreDate '2026-10-31'
    }

    It 'classifies each backed-up object against the tenant' {
        ($script:Plan | Where-Object Key -EQ 'same').Classification | Should -Be 'Identical'
        ($script:Plan | Where-Object Key -EQ 'drifted').Classification | Should -Be 'Conflict'
        ($script:Plan | Where-Object Key -EQ 'deleted').Classification | Should -Be 'Create'
        ($script:Plan | Where-Object Key -EQ 'device|win - deleted').Classification | Should -Be 'Create'
        ($script:Plan | Where-Object Key -EQ 'device|win - same').Classification | Should -Be 'Identical'
    }

    It 'does not list objects that are only in the tenant' {
        $script:Plan | Where-Object Key -EQ 'unrelated' | Should -BeNullOrEmpty
    }

    It 'shows the conflicting properties with the tenant value as Before and the backup value as After' {
        $Drift = $script:Plan | Where-Object Key -EQ 'drifted'
        $Drift.Changes.Path | Should -Be 'state'
        $Drift.Changes.Before | Should -Be 'enabledForReportingButNotEnforced'
        $Drift.Changes.After | Should -Be 'enabled'
    }

    It 'describes what the existing restore does, including that Intune overwrites same-name policies' {
        ($script:Plan | Where-Object Key -EQ 'drifted').Action | Should -BeLike 'Fail*overwrite is off*'
        ($script:Plan | Where-Object Key -EQ 'device|win - same').Action | Should -BeLike 'Overwrite the existing policy*'
        $WithOverwrite = Get-CIPPBackupRestorePlan -BackupItems $script:BackupItems -LiveItems $script:LiveItems -SafeMode $false -Overwrite $true
        ($WithOverwrite | Where-Object Key -EQ 'drifted').Action | Should -BeLike 'Overwrite the existing policy*'
        ($WithOverwrite | Where-Object Key -EQ 'u1').Action | Should -BeLike 'Overwrite the existing user*'
    }

    It 'never proposes a new name outside safe mode' {
        $script:Plan | Where-Object NewName | Should -BeNullOrEmpty
    }
}

Describe 'Get-CIPPBackupRestorePlan (safe restore-as-new)' {
    BeforeAll {
        $script:Safe = Get-CIPPBackupRestorePlan -BackupItems $script:BackupItems -LiveItems $script:LiveItems -SafeMode $true -RestoreDate '2026-10-31'
    }

    It 'creates every non-identical policy under a suffixed name and skips identical ones' {
        ($script:Safe | Where-Object Key -EQ 'drifted').NewName | Should -Be 'Drifted (restored 2026-10-31)'
        ($script:Safe | Where-Object Key -EQ 'device|win - deleted').NewName | Should -Be 'Win - Deleted (restored 2026-10-31)'
        ($script:Safe | Where-Object Key -EQ 'same').NewName | Should -BeNullOrEmpty
        ($script:Safe | Where-Object Key -EQ 'same').Action | Should -BeLike 'Skip*identical*'
    }

    It 'adds a counter when the suffixed name is already taken' {
        ($script:Safe | Where-Object Key -EQ 'deleted').NewName | Should -Be 'Deleted (restored 2026-10-31 #2)'
    }

    It 'says CA copies are disabled and Intune copies unassigned' {
        ($script:Safe | Where-Object Key -EQ 'drifted').Action | Should -BeLike '*disabled*targeting removed*'
        ($script:Safe | Where-Object Key -EQ 'device|win - deleted').Action | Should -BeLike '*without assignments*'
    }

    It 'does not restore users, groups or mail settings' {
        ($script:Safe | Where-Object Type -EQ 'users').Action | ForEach-Object { $_ | Should -BeLike 'Not restored*' }
        ($script:Safe | Where-Object Type -EQ 'antispam').NewName | Should -BeNullOrEmpty
    }
}

Describe 'ConvertTo-CIPPSafeRestorePayload' {
    It 'renames a CA policy, disables it and removes all user, group and workload targeting' {
        $Item = $script:BackupItems | Where-Object Key -EQ 'drifted'
        $Out = ConvertTo-CIPPSafeRestorePayload -Item $Item -NewName 'Drifted (restored 2026-10-31)' | ConvertFrom-Json
        $Out.displayName | Should -Be 'Drifted (restored 2026-10-31)'
        $Out.state | Should -Be 'disabled'
        @($Out.conditions.users.includeUsers) | Should -Be @('None')
        $Out.conditions.users.PSObject.Properties.Name | Should -Be @('includeUsers')
        $Out.conditions.PSObject.Properties.Name | Should -Not -Contain 'clientApplications'
        $Out.conditions.applications.includeApplications | Should -Be 'All'
        $Out.grantControls.builtInControls | Should -Be 'mfa'
        # the plan's item is not mutated
        $Item.Content.state | Should -Be 'enabled'
    }

    It 'renames a Settings Catalog policy inside the payload and strips assignments' {
        $Item = Items (New-TestScheduledBackupJson -Intune @((New-TestCatalogRow -Name 'Cat'))) | Where-Object Type -EQ 'intuneconfig'
        $Out = ConvertTo-CIPPSafeRestorePayload -Item $Item -NewName 'Cat (restored 2026-10-31)'
        $Out.Type | Should -Be 'Catalog'
        $Out.DisplayName | Should -Be 'Cat (restored 2026-10-31)'
        $Template = $Out.TemplateJson | ConvertFrom-Json
        $Template.name | Should -Be 'Cat (restored 2026-10-31)'
        $Template.PSObject.Properties.Name | Should -Not -Contain 'assignments'
        # Set-CIPPIntunePolicy derives the Catalog name from the payload - it must resolve to the new name
        Get-CIPPIntunePolicyName -TemplateType 'Catalog' -RawJSON $Out.TemplateJson -DisplayName $Out.DisplayName | Should -Be 'Cat (restored 2026-10-31)'
    }

    It 'renames a device configuration both on the row and in the payload' {
        $Item = $script:BackupItems | Where-Object Key -EQ 'device|win - deleted'
        $Out = ConvertTo-CIPPSafeRestorePayload -Item $Item -NewName 'Win - Deleted (restored 2026-10-31)'
        $Out.DisplayName | Should -Be 'Win - Deleted (restored 2026-10-31)'
        ($Out.TemplateJson | ConvertFrom-Json).displayName | Should -Be 'Win - Deleted (restored 2026-10-31)'
    }

    It 'refuses component types it does not support' {
        $User = $script:BackupItems | Where-Object Type -EQ 'users' | Select-Object -First 1
        { ConvertTo-CIPPSafeRestorePayload -Item $User -NewName 'x' } | Should -Throw
    }
}
