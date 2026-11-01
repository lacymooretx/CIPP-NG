# Pester tests for Get-CIPPAlertExoProvisioning (Vikunja CIPP-36). Get-CIPPExoProvisioningHealth is stubbed;
# Write-AlertTrace is stubbed to capture what the alert hands the lifecycle (rows, stable Ids, state vs -Append).

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertExoProvisioning.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Alerts/Get-CIPPAlertFailureSeverity.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/GraphHelper/Get-AlertContentHash.ps1')

    function Get-CIPPExoProvisioningHealth { [CmdletBinding()] param($TenantFilter, $GraceHours) }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData) }
    function Write-AlertTrace {
        param($cmdletName, $tenantFilter, $data, [switch]$Append)
        $script:Traced = @($data)
        $script:Appended = [bool]$Append
        $script:TraceCalls++
        @($data)
    }

    function script:Chk([string]$Check, [string]$Status, [string]$Detail = 'detail', [bool]$Errored = $false) {
        [pscustomobject]@{ Check = $Check; Status = $Status; Detail = $Detail; Fix = "fix $Check"; Errored = $Errored }
    }
    function script:New-Report {
        param($Checks, $MissingDomains = @(), $UsersWithoutMailbox = @(), $Errors = @())
        [pscustomobject]@{
            Tenant              = 'contoso.com'
            Summary             = [ordered]@{ Overall = 'Pass' }
            Checks              = @($Checks)
            MissingDomains      = @($MissingDomains)
            UsersWithoutMailbox = @($UsersWithoutMailbox)
            Errors              = @($Errors)
        }
    }
}

Describe 'Get-CIPPAlertExoProvisioning' {
    BeforeEach {
        $script:Traced = $null; $script:Appended = $null; $script:TraceCalls = 0
        Mock Write-LogMessage {}
    }

    It 'reconciles with no rows when everything passes or only Info rows exist' {
        Mock Get-CIPPExoProvisioningHealth { New-Report -Checks @((Chk 'ExchangeLicence' 'Info'), (Chk 'OrganizationConfig' 'Info'), (Chk 'RoleGroups' 'Pass')) }
        Get-CIPPAlertExoProvisioning -TenantFilter 'contoso.com' | Out-Null
        $script:TraceCalls | Should -Be 1
        $script:Appended | Should -BeFalse
        @($script:Traced).Count | Should -Be 0
    }

    It 'raises check-level findings with stable Ids in state mode' {
        Mock Get-CIPPExoProvisioningHealth { New-Report -Checks @((Chk 'OrgManagementRoles' 'Fail' 'missing 7 roles'), (Chk 'RoleGroups' 'Warn' 'Help Desk missing'), (Chk 'ManagementRoles' 'Pass')) }
        Get-CIPPAlertExoProvisioning -TenantFilter 'contoso.com' | Out-Null
        $script:Appended | Should -BeFalse
        @($script:Traced.Id) | Should -Be @('ExoProvisioning|OrgManagementRoles', 'ExoProvisioning|RoleGroups')
        $script:Traced[0].Severity | Should -Be 'Fail'
        $script:Traced[0].Fix | Should -Be 'fix OrgManagementRoles'
    }

    It 'does not alert a Warn on OrgManagementRoles (a few optional roles missing fleet-wide), only a Fail' {
        Mock Get-CIPPExoProvisioningHealth { New-Report -Checks @((Chk 'OrgManagementRoles' 'Warn' 'missing 1 role'), (Chk 'ManagementRoles' 'Pass')) }
        Get-CIPPAlertExoProvisioning -TenantFilter 'contoso.com' | Out-Null
        @($script:Traced | Where-Object { $_ }).Count | Should -Be 0
    }

    It 'raises one finding per missing domain and per user without a mailbox, without a UserPrincipalName key' {
        $script:Users = @([pscustomobject]@{ id = 'u1'; userPrincipalName = 'a@contoso.com'; licensedSince = '2026-10-01T00:00:00Z' }, [pscustomobject]@{ id = 'u2'; userPrincipalName = 'b@contoso.com'; licensedSince = '2026-10-02T00:00:00Z' })
        Mock Get-CIPPExoProvisioningHealth { New-Report -Checks @((Chk 'AcceptedDomains' 'Warn'), (Chk 'LicensedUserMailboxes' 'Warn')) -MissingDomains @('fabrikam.com') -UsersWithoutMailbox $script:Users }
        Get-CIPPAlertExoProvisioning -TenantFilter 'contoso.com' | Out-Null
        @($script:Traced.Id) | Should -Be @('ExoProvisioning|Domain|fabrikam.com', 'ExoProvisioning|NoMailbox|u1', 'ExoProvisioning|NoMailbox|u2')
        $script:Traced[1].User | Should -Be 'a@contoso.com'
        $script:Traced[1].PSObject.Properties.Name | Should -Not -Contain 'UserPrincipalName'
    }

    It 'hashes a finding the same when its detail changes' {
        Mock Get-CIPPExoProvisioningHealth { New-Report -Checks @((Chk 'OrgManagementRoles' 'Fail' 'missing 7 roles')) }
        Get-CIPPAlertExoProvisioning -TenantFilter 'contoso.com' | Out-Null
        $A = (Get-AlertContentHash -AlertItem $script:Traced[0]).ContentHash
        $script:Traced[0].Message = 'missing 9 roles'
        (Get-AlertContentHash -AlertItem $script:Traced[0]).ContentHash | Should -Be $A
    }

    It 'raises one tenant-level finding, not one per user, when no licensed user has a mailbox' {
        $script:Users = @(1..50 | ForEach-Object { [pscustomobject]@{ id = "u$_"; userPrincipalName = "u$_@contoso.com" } })
        Mock Get-CIPPExoProvisioningHealth { New-Report -Checks @((Chk 'LicensedUserMailboxes' 'Fail' 'none of 50')) -UsersWithoutMailbox $script:Users }
        Get-CIPPAlertExoProvisioning -TenantFilter 'contoso.com' | Out-Null
        @($script:Traced.Id) | Should -Be @('ExoProvisioning|LicensedUserMailboxes')
    }

    It 'logs a check that could not run instead of raising it, and does not resolve open findings that run' {
        Mock Get-CIPPExoProvisioningHealth { New-Report -Checks @((Chk 'RoleGroups' 'Warn' 'Could not read role groups: Throttled' $true), (Chk 'AcceptedDomains' 'Warn')) -MissingDomains @('fabrikam.com') -Errors @('Get-RoleGroup: Throttled') }
        Get-CIPPAlertExoProvisioning -TenantFilter 'contoso.com' | Out-Null
        $script:Appended | Should -BeTrue
        @($script:Traced.Id) | Should -Be @('ExoProvisioning|Domain|fabrikam.com')
        Should -Invoke Write-LogMessage -Times 1 -ParameterFilter { $message -like '*Throttled*' }
    }

    It 'still raises Exchange not answering, which is itself an errored check' {
        Mock Get-CIPPExoProvisioningHealth { New-Report -Checks @((Chk 'OrganizationConfig' 'Fail' 'did not answer' $true), (Chk 'RoleGroups' 'Info' 'Skipped')) }
        Get-CIPPAlertExoProvisioning -TenantFilter 'contoso.com' | Out-Null
        $script:Appended | Should -BeTrue
        @($script:Traced.Id) | Should -Be @('ExoProvisioning|OrganizationConfig')
    }

    It 'passes the grace-hours input through and ignores invalid values' {
        Mock Get-CIPPExoProvisioningHealth { $script:Grace = $GraceHours; New-Report -Checks @() }
        Get-CIPPAlertExoProvisioning -TenantFilter 'contoso.com' -InputValue @{ ExoProvisioningGraceHours = '48' } | Out-Null
        $script:Grace | Should -Be 48
        Get-CIPPAlertExoProvisioning -TenantFilter 'contoso.com' -InputValue @{ ExoProvisioningGraceHours = 'soon' } | Out-Null
        $script:Grace | Should -Be 24
    }

    It 'logs a licence-shaped failure at Info and does not reconcile' {
        Mock Get-CIPPExoProvisioningHealth { throw 'Tenant does not have a valid license for this feature' }
        Get-CIPPAlertExoProvisioning -TenantFilter 'contoso.com' | Out-Null
        $script:TraceCalls | Should -Be 0
        Should -Invoke Write-LogMessage -Times 1 -ParameterFilter { $sev -eq 'Info' }
    }

    It 'logs any other failure at Error' {
        Mock Get-CIPPExoProvisioningHealth { throw 'Internal server error' }
        Get-CIPPAlertExoProvisioning -TenantFilter 'contoso.com' | Out-Null
        Should -Invoke Write-LogMessage -Times 1 -ParameterFilter { $sev -eq 'Error' }
    }
}
