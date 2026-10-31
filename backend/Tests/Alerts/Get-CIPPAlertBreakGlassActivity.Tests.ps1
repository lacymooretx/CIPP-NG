# Aspendora fork (Vikunja CIPP-3): every sign-in by, or change to, a registered break-glass account is High.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertBreakGlassActivity.ps1')

    function Get-CIPPBreakGlassAccounts { param($TenantFilter) $script:Accounts }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
    function Write-LogMessage { param($API, $tenant, $message, $sev) $script:Logs.Add($message) }
    function Write-AlertTrace { param($cmdletName, $tenantFilter, $data, [switch]$Append) $script:Traced = $data; $data }
    function New-GraphGetRequest {
        param($uri, $tenantid)
        $script:Uris.Add($uri)
        if ($uri -match '/users/') {
            if ($script:UserMode -eq 'missing') { throw 'Request_ResourceNotFound: does not exist' }
            return [pscustomobject]@{ id = 'bg1'; userPrincipalName = 'bg@contoso.com'; accountEnabled = ($script:UserMode -ne 'disabled') }
        }
        if ($uri -match 'signIns') {
            if ($script:SignInMode -eq 'nop1') { throw 'Authentication_RequestFromNonPremiumTenantOrB2CTenant' }
            return $script:SignIns
        }
        if ($uri -match 'targetResources') { return $script:AuditsTarget }
        if ($uri -match 'initiatedBy') { return $script:AuditsBy }
    }
}

Describe 'Get-CIPPAlertBreakGlassActivity' {
    BeforeEach {
        $script:Accounts = @([pscustomobject]@{ PartitionKey = 't1'; RowKey = 'bg1'; UserPrincipalName = 'bg@contoso.com' })
        $script:Uris = [System.Collections.Generic.List[string]]::new()
        $script:Logs = [System.Collections.Generic.List[string]]::new()
        $script:UserMode = 'ok'; $script:SignInMode = 'ok'
        $script:SignIns = @(); $script:AuditsTarget = @(); $script:AuditsBy = @()
        $script:Traced = $null
    }

    It 'does nothing for a tenant with no registered accounts' {
        $script:Accounts = @()
        Get-CIPPAlertBreakGlassActivity -TenantFilter 'contoso.com' | Should -BeNullOrEmpty
        $script:Uris.Count | Should -Be 0
    }

    It 'stays quiet when the account is healthy and unused' {
        Get-CIPPAlertBreakGlassActivity -TenantFilter 'contoso.com' | Should -BeNullOrEmpty
    }

    It 'raises successful and failed sign-ins, interactive and non-interactive' {
        $script:SignIns = @(
            [pscustomobject]@{ id = 's1'; createdDateTime = '2026-10-31T17:00:00Z'; ipAddress = '1.2.3.4'; appDisplayName = 'Azure Portal'; location = @{ city = 'Houston'; countryOrRegion = 'US' }; status = @{ errorCode = 0 } }
            [pscustomobject]@{ id = 's2'; createdDateTime = '2026-10-31T17:05:00Z'; ipAddress = '5.6.7.8'; appDisplayName = 'Office'; location = @{}; status = @{ errorCode = 50126; failureReason = 'Invalid password' } }
        )
        $R = @(Get-CIPPAlertBreakGlassActivity -TenantFilter 'contoso.com')
        $R.Type | Should -Be @('SignIn', 'SignInFailed')
        $R.Severity | Should -Be @('High', 'High')
        $R[0].When | Should -Match '12:00 CDT \(17:00 UTC\)'
        ($script:Uris | Where-Object { $_ -match 'signIns' }) | Should -Match "nonInteractiveUser"
    }

    It 'raises directory changes to and by the account once each' {
        $Self = [pscustomobject]@{ id = 'a2'; activityDateTime = '2026-10-31T17:00:00Z'; activityDisplayName = 'Update user'; result = 'success'; initiatedBy = @{ user = @{ id = 'bg1'; userPrincipalName = 'bg@contoso.com' } } }
        $script:AuditsTarget = @(
            [pscustomobject]@{ id = 'a1'; activityDateTime = '2026-10-31T17:00:00Z'; activityDisplayName = 'Reset user password'; result = 'success'; initiatedBy = @{ user = @{ id = 'x'; userPrincipalName = 'admin@contoso.com' } } }
            $Self
        )
        $script:AuditsBy = @($Self)
        $R = @(Get-CIPPAlertBreakGlassActivity -TenantFilter 'contoso.com')
        $R.Id | Should -Be @('Audit|a1', 'Audit|a2')
        $R[0].Message | Should -Match 'admin@contoso.com'
        $R[1].Message | Should -Match 'performed'
    }

    It 'raises a disabled or deleted account' {
        $script:UserMode = 'disabled'
        (Get-CIPPAlertBreakGlassActivity -TenantFilter 'contoso.com').Type | Should -Be 'AccountDisabled'
        $script:UserMode = 'missing'
        $script:Uris.Clear()
        $R = @(Get-CIPPAlertBreakGlassActivity -TenantFilter 'contoso.com')
        $R.Type | Should -Be 'AccountMissing'
        ($script:Uris | Where-Object { $_ -match 'signIns' }) | Should -BeNullOrEmpty
    }

    It 'still checks directory changes when sign-in logs need P1' {
        $script:SignInMode = 'nop1'
        $script:AuditsTarget = @([pscustomobject]@{ id = 'a1'; activityDateTime = '2026-10-31T17:00:00Z'; activityDisplayName = 'Update user'; result = 'success'; initiatedBy = @{ app = @{ displayName = 'Some app' } } })
        $R = @(Get-CIPPAlertBreakGlassActivity -TenantFilter 'contoso.com')
        $R.Type | Should -Be 'DirectoryChange'
        $script:Logs | Should -Match 'Entra ID P1'
    }
}
