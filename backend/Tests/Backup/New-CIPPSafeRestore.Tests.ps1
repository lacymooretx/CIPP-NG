# Aspendora fork (Vikunja CIPP-23): safe restore-as-new creates disabled, unassigned copies and never overwrites.

BeforeAll {
    . (Join-Path $PSScriptRoot 'BackupFixtures.ps1')
    function Write-LogMessage { param($headers, $API, $message, $Sev, $tenant, $LogData) }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
    function New-CIPPCAPolicy { param($RawJSON, $TenantFilter, $State, $Overwrite, $ReplacePattern, $DisableSD, $CreateGroups, $APIName, $Headers) }
    function Set-CIPPIntunePolicy { param($TemplateType, $Description, $DisplayName, $RawJSON, $AssignTo, $ExcludeGroup, $Headers, $APIName, $TenantFilter) }
    function New-CIPPBackupTask { param($Task, $TenantFilter) }
    function New-CIPPRestoreTask { param($Task) throw 'the default restore must not run in safe mode' }

    $script:BackupJson = New-TestScheduledBackupJson -Ca @(
        (New-TestCAPolicyJson -Name 'Same'),
        (New-TestCAPolicyJson -Name 'Gone')
    ) -Intune @(
        (New-TestCatalogRow -Name 'Cat'),
        (New-TestIntuneRow -Name 'Win - Same')
    )
    $script:Live = ConvertFrom-TestBackupJson (New-TestScheduledBackupJson -Ca @((New-TestCAPolicyJson -Name 'Same')) -Intune @((New-TestIntuneRow -Name 'Win - Same')))
}

Describe 'New-CIPPSafeRestore' {
    BeforeEach {
        Mock -CommandName Get-CIPPBackupContent -MockWith {
            [pscustomobject]@{ Entity = [pscustomobject]@{ RowKey = 'contoso.com_2026-10-31-0100' }; Json = $script:BackupJson; Readable = $true; TenantFilter = 'contoso.com' }
        }
        Mock -CommandName Get-CIPPBackupIntegrityReport -MockWith { [pscustomobject]@{ Status = 'Verified'; Detail = 'ok' } }
        Mock -CommandName Get-CIPPBackupLiveSnapshot -MockWith {
            [pscustomobject]@{ Backup = [pscustomobject]@{ ca = $script:Live.ca; intuneconfig = $script:Live.intuneconfig }; Errors = @(); FailedTypes = @() }
        }
        Mock -CommandName Get-CIPPBackupRestoreDate -MockWith { '2026-10-31' }
        Mock -CommandName New-CIPPCAPolicy -MockWith { 'Created' }
        Mock -CommandName Set-CIPPIntunePolicy -MockWith { 'Created' }
    }

    It 'creates the missing CA policy as a disabled, untargeted copy and never overwrites' {
        $null = New-CIPPSafeRestore -TenantFilter 'contoso.com' -BackupName 'contoso.com_2026-10-31-0100' -Types @('ca')
        Should -Invoke New-CIPPCAPolicy -Times 1 -Exactly
        Should -Invoke New-CIPPCAPolicy -Times 1 -Exactly -ParameterFilter {
            $P = $RawJSON | ConvertFrom-Json
            $State -eq 'disabled' -and $Overwrite -eq $false -and $ReplacePattern -eq 'none' -and $CreateGroups -eq $false -and
            $P.displayName -eq 'Gone (restored 2026-10-31)' -and $P.state -eq 'disabled' -and
            (@($P.conditions.users.includeUsers) -join ',') -eq 'None' -and -not $P.conditions.users.includeGroups
        }
    }

    It 'creates Intune copies under the new name with no assignment target, skipping identical ones' {
        $null = New-CIPPSafeRestore -TenantFilter 'contoso.com' -BackupName 'contoso.com_2026-10-31-0100' -Types @('intuneconfig')
        Should -Invoke Set-CIPPIntunePolicy -Times 1 -Exactly
        Should -Invoke Set-CIPPIntunePolicy -Times 1 -Exactly -ParameterFilter {
            $TemplateType -eq 'Catalog' -and $DisplayName -eq 'Cat (restored 2026-10-31)' -and -not $AssignTo -and
            ($RawJSON | ConvertFrom-Json).name -eq 'Cat (restored 2026-10-31)' -and
            -not (($RawJSON | ConvertFrom-Json).PSObject.Properties.Name -contains 'assignments')
        }
    }

    It 'reports unsupported components instead of restoring them' {
        $Out = New-CIPPSafeRestore -TenantFilter 'contoso.com' -BackupName 'contoso.com_2026-10-31-0100' -Types @('users', 'ca')
        $Out | Where-Object { $_ -like 'Skipped users*' } | Should -Not -BeNullOrEmpty
        Should -Invoke New-CIPPCAPolicy -Times 1 -Exactly
    }

    It 'aborts without writing when the backup fails verification' {
        Mock -CommandName Get-CIPPBackupIntegrityReport -MockWith { [pscustomobject]@{ Status = 'Corrupt'; Detail = 'item hash mismatch' } }
        $Out = New-CIPPSafeRestore -TenantFilter 'contoso.com' -BackupName 'contoso.com_2026-10-31-0100' -Types @('ca', 'intuneconfig')
        ($Out -join ' ') | Should -BeLike '*aborted*Corrupt*'
        Should -Invoke New-CIPPCAPolicy -Times 0 -Exactly
        Should -Invoke Set-CIPPIntunePolicy -Times 0 -Exactly
        Should -Invoke Get-CIPPBackupLiveSnapshot -Times 0 -Exactly
    }

    It 'restores nothing for a component whose current state could not be read' {
        Mock -CommandName Get-CIPPBackupLiveSnapshot -MockWith {
            [pscustomobject]@{ Backup = [pscustomobject]@{}; Errors = @('Could not read current ca from the tenant: 403'); FailedTypes = @('ca') }
        }
        $null = New-CIPPSafeRestore -TenantFilter 'contoso.com' -BackupName 'contoso.com_2026-10-31-0100' -Types @('ca')
        Should -Invoke New-CIPPCAPolicy -Times 0 -Exactly
    }

    It 'keeps going when one policy fails and reports it' {
        Mock -CommandName Set-CIPPIntunePolicy -MockWith { throw 'Graph said no' }
        $Out = New-CIPPSafeRestore -TenantFilter 'contoso.com' -BackupName 'contoso.com_2026-10-31-0100' -Types @('ca', 'intuneconfig')
        Should -Invoke New-CIPPCAPolicy -Times 1 -Exactly
        $Out[-1] | Should -BeLike '*1 created*1 failed*'
    }
}
