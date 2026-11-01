# Aspendora fork (Vikunja CIPP-23): ExecBackupVerify / ExecBackupDiff / ExecBackupRestorePreview request handling.

BeforeAll {
    . (Join-Path $PSScriptRoot 'BackupFixtures.ps1')
    ([PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')).GetMethod('Add').Invoke($null, @('HttpStatusCode', [System.Net.HttpStatusCode]))
    class HttpResponseContext { [int]$StatusCode; [object]$Body }
    function Write-LogMessage { param($headers, $API, $message, $Sev, $tenant, $LogData) }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
    function Get-CIPPBackup { param($Type, $Name, $TenantFilter, [switch]$NameOnly) }
    function New-CIPPAzStorageRequest { param($Service, $Resource, $Method, $ConnectionString) }
    function New-CIPPBackupTask { param($Task, $TenantFilter) }
    $Core = Join-Path $BackendRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/CIPP/Core'
    . (Join-Path $Core 'Invoke-ExecBackupVerify.ps1')
    . (Join-Path $Core 'Invoke-ExecBackupDiff.ps1')
    . (Join-Path $Core 'Invoke-ExecBackupRestorePreview.ps1')
    function Call { param([string]$Fn, $Body) & $Fn -Request ([pscustomobject]@{ Headers = @{}; Query = @{}; Body = [pscustomobject]$Body }) }

    $script:Old = New-TestScheduledBackupJson -Ca @((New-TestCAPolicyJson -Name 'A' -State 'enabled'))
    $script:New = New-TestScheduledBackupJson -Ca @((New-TestCAPolicyJson -Name 'A' -State 'disabled'), (New-TestCAPolicyJson -Name 'B'))
}

Describe 'Backup endpoints' {
    BeforeEach {
        Mock -CommandName Get-CIPPBackup -MockWith {
            $Json = switch ($Name) { 'contoso.com_2026-10-30-0100' { $script:Old } 'contoso.com_2026-10-31-0100' { $script:New } default { $null } }
            if ($null -eq $Json) { return }
            [pscustomobject]@{ RowKey = $Name; TenantFilter = 'contoso.com'; Backup = $Json; BackupIsBlob = $true; BackupIsBlobLink = $true }
        }
    }

    It 'verify: validates input, enforces the backup tenant and 404s unknown backups' {
        (Call 'Invoke-ExecBackupVerify' @{ tenantFilter = 'contoso.com' }).StatusCode | Should -Be 400
        (Call 'Invoke-ExecBackupVerify' @{ BackupName = 'contoso.com_2026-10-31-0100' }).StatusCode | Should -Be 400
        (Call 'Invoke-ExecBackupVerify' @{ BackupName = 'contoso.com_2026-10-31-0100'; tenantFilter = 'fabrikam.com' }).StatusCode | Should -Be 403
        (Call 'Invoke-ExecBackupVerify' @{ BackupName = 'nope'; tenantFilter = 'contoso.com' }).StatusCode | Should -Be 404
    }

    It 'verify: reports a backup without hashes as unverified (pre-hash)' {
        $R = Call 'Invoke-ExecBackupVerify' @{ BackupName = 'contoso.com_2026-10-31-0100'; tenantFilter = 'contoso.com' }
        $R.StatusCode | Should -Be 200
        $R.Body.Results.Status | Should -Be 'Unverified (pre-hash)'
        $R.Body.Results.BackupName | Should -Be 'contoso.com_2026-10-31-0100'
    }

    It 'diff: returns per-object Added/Changed with property changes, omitting unchanged objects' {
        $R = Call 'Invoke-ExecBackupDiff' @{ BackupA = 'contoso.com_2026-10-30-0100'; BackupB = 'contoso.com_2026-10-31-0100'; tenantFilter = 'contoso.com' }
        $R.StatusCode | Should -Be 200
        $R.Body.Results.Summary.Added | Should -Be 1
        $R.Body.Results.Summary.Changed | Should -Be 1
        ($R.Body.Results.Objects | Where-Object Key -EQ 'a').Changes.Path | Should -Be 'state'
        $R.Body.Results.Objects | Where-Object Status -EQ 'Unchanged' | Should -BeNullOrEmpty
        ($R.Body.Results.Types | Where-Object Type -EQ 'users').Unchanged | Should -Be 2
    }

    It 'diff: filters by component type and refuses another tenant' {
        $R = Call 'Invoke-ExecBackupDiff' @{ BackupA = 'contoso.com_2026-10-30-0100'; BackupB = 'contoso.com_2026-10-31-0100'; tenantFilter = 'contoso.com'; Types = 'users' }
        @($R.Body.Results.Types).Type | Should -Be 'users'
        (Call 'Invoke-ExecBackupDiff' @{ BackupA = 'contoso.com_2026-10-30-0100'; BackupB = 'contoso.com_2026-10-31-0100'; tenantFilter = 'fabrikam.com' }).StatusCode | Should -Be 403
    }

    It 'preview: reads the tenant only through the backup capture and writes nothing' {
        Mock -CommandName New-CIPPBackupTask -MockWith {
            switch ($Task) { 'ca' { @((New-TestCAPolicyJson -Name 'A' -State 'enabled')) } default { @() } }
        }
        $R = Call 'Invoke-ExecBackupRestorePreview' @{ BackupName = 'contoso.com_2026-10-31-0100'; tenantFilter = 'contoso.com'; Types = @('ca'); SafeMode = 'true' }
        $R.StatusCode | Should -Be 200
        $R.Body.Results.SafeMode | Should -BeTrue
        ($R.Body.Results.Objects | Where-Object Key -EQ 'a').Classification | Should -Be 'Conflict'
        ($R.Body.Results.Objects | Where-Object Key -EQ 'b').Classification | Should -Be 'Create'
        ($R.Body.Results.Objects | Where-Object Key -EQ 'b').NewName | Should -BeLike 'B (restored *)'
        Should -Invoke New-CIPPBackupTask -Times 1 -Exactly -ParameterFilter { $Task -eq 'ca' -and $TenantFilter -eq 'contoso.com' }
    }

    It 'preview: requires a concrete tenant' {
        (Call 'Invoke-ExecBackupRestorePreview' @{ BackupName = 'contoso.com_2026-10-31-0100'; tenantFilter = 'AllTenants' }).StatusCode | Should -Be 400
    }
}
