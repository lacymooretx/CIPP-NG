# Aspendora fork (Vikunja CIPP-17): weekly CIPP backup coverage alert. Get-CIPPEntraRecoveryCoverage is stubbed (it has
# its own tests); Write-AlertTrace is stubbed to capture the rows handed to the lifecycle (state mode, one stable Id per
# tenant and gap code, so a stale backup stays one alert while its age changes).

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/IntuneOps/Format-CIPPCentralTime.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertBackupCoverage.ps1')

    function Get-CIPPEntraRecoveryCoverage { [CmdletBinding()] param($TenantFilter, $MaxBackupAgeDays, [switch]$SkipLive) }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData) }
    function Write-AlertTrace {
        param($cmdletName, $tenantFilter, $data, [switch]$Append)
        $script:Traced = @($data)
        $script:Appended = [bool]$Append
        $script:TraceCalls++
    }

    function script:New-CoverageRow {
        param([string]$Tenant = 'a.com', [string[]]$Codes = @(), [string[]]$Messages = @(), $LastBackup = $null, [string]$Components = '')
        [pscustomobject]@{
            tenant         = $Tenant
            gapCodes       = $Codes
            gapList        = $Messages
            cippLastBackup = $LastBackup
            cippComponents = $Components
        }
    }
}

Describe 'Get-CIPPAlertBackupCoverage' {
    BeforeEach {
        $script:Traced = $null; $script:Appended = $null; $script:TraceCalls = 0
        $script:Rows = @()
        Mock Write-LogMessage {}
        Mock Get-CIPPEntraRecoveryCoverage {
            $script:CalledWith = @{ TenantFilter = $TenantFilter; MaxBackupAgeDays = $MaxBackupAgeDays; SkipLive = [bool]$SkipLive }
            [pscustomobject]@{ Rows = $script:Rows }
        }
    }

    It 'raises one state-mode row per gap with a stable Id and never makes live Graph calls' {
        $script:Rows = @(New-CoverageRow -Codes @('Stale', 'NoCA') -Messages @('Last CIPP backup is 9 days old', 'Conditional Access (with its named locations) not in the backup') -LastBackup ([datetime]::UtcNow.AddDays(-9)) -Components 'groups, users')
        Get-CIPPAlertBackupCoverage -TenantFilter 'a.com'
        $script:CalledWith.SkipLive | Should -BeTrue
        $script:CalledWith.MaxBackupAgeDays | Should -Be 2
        $script:Appended | Should -BeFalse
        @($script:Traced).Count | Should -Be 2
        $script:Traced[0].Id | Should -Be 'BackupCoverage|a.com|Stale'
        $script:Traced[1].Id | Should -Be 'BackupCoverage|a.com|NoCA'
        $script:Traced[0].Gap | Should -Be 'Last CIPP backup is 9 days old'
        $script:Traced[0].Message | Should -BeLike 'a.com: Last CIPP backup is 9 days old.*5 days*'
        $script:Traced[0].LastBackup | Should -Match '(CST|CDT|UTC)'
        $script:Traced[0].Components | Should -Be 'groups, users'
    }

    It 'shows Never and None when the tenant has no backup at all' {
        $script:Rows = @(New-CoverageRow -Codes @('NoTask') -Messages @('No scheduled CIPP backup'))
        Get-CIPPAlertBackupCoverage -TenantFilter 'a.com'
        $script:Traced[0].Id | Should -Be 'BackupCoverage|a.com|NoTask'
        $script:Traced[0].LastBackup | Should -Be 'Never'
        $script:Traced[0].Components | Should -Be 'None'
    }

    It 'traces an empty set when the tenant is covered, so open alerts resolve' {
        $script:Rows = @(New-CoverageRow)
        Get-CIPPAlertBackupCoverage -TenantFilter 'a.com'
        $script:TraceCalls | Should -Be 1
        @($script:Traced).Count | Should -Be 0
    }

    It 'reads the stale threshold from an input object or a bare number, and ignores nonsense' {
        Get-CIPPAlertBackupCoverage -TenantFilter 'a.com' -InputValue ([pscustomobject]@{ BackupCoverageMaxAgeDays = '7' })
        $script:CalledWith.MaxBackupAgeDays | Should -Be 7
        Get-CIPPAlertBackupCoverage -TenantFilter 'a.com' -InputValue 5
        $script:CalledWith.MaxBackupAgeDays | Should -Be 5
        Get-CIPPAlertBackupCoverage -TenantFilter 'a.com' -InputValue ([pscustomobject]@{ BackupCoverageMaxAgeDays = '0' })
        $script:CalledWith.MaxBackupAgeDays | Should -Be 2
        Get-CIPPAlertBackupCoverage -TenantFilter 'a.com' -InputValue ([pscustomobject]@{ BackupCoverageMaxAgeDays = 'abc' })
        $script:CalledWith.MaxBackupAgeDays | Should -Be 2
    }

    It 'logs and raises nothing when the report cannot be built' {
        Mock Get-CIPPEntraRecoveryCoverage { throw 'storage down' }
        Get-CIPPAlertBackupCoverage -TenantFilter 'a.com'
        $script:TraceCalls | Should -Be 0
        Should -Invoke Write-LogMessage -Times 1 -Exactly
    }
}
