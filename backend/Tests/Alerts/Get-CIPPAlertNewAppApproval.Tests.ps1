# Pending app consent requests, surfaced as a ticket with both ways to act on them.
#
# Microsoft provides NO API to approve or deny an admin consent request. The documented mechanism is
# a rebuilt consent URL, and the bf_id parameter is what ties the grant back to the request so Entra
# marks it approved - without bf_id the grant succeeds but the request stays InProgress until it
# expires. That is asserted here because it is silent when wrong.
#
# The guards are the ones this alert previously lacked: it re-fired every run for as long as a
# request stayed pending, and swallowed every error in an empty catch{}.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertNewAppApproval.ps1')

    function New-GraphGetRequest {
        param($Uri, $tenantid)
        if ($script:TopThrows) { throw 'graph exploded' }
        if ($Uri -match '/userConsentRequests$') {
            $ParentId = ([regex]::Match($Uri, 'appConsentRequests/([^/]+)/userConsentRequests')).Groups[1].Value
            if ($script:ChildThrows) { throw 'child blew up' }
            return $script:Children[$ParentId]
        }
        return $script:Approvals
    }
    function Get-Tenants { param($TenantFilter, [switch]$SkipDomains) [pscustomobject]@{ customerId = 'cust-0001' } }
    function Get-CIPPTable { param($Table, $tablename) @{ Context = 'stub' } }
    function Get-CIPPAzDataTableEntity {
        param($Context, $Filter)
        if ($Filter -match 'CIPPURL') { return [pscustomobject]@{ Value = 'cipp.aspendora.com' } }
        return $script:PreviousRow
    }
    function Add-CIPPAzDataTableEntity { param($Context, $Entity, [switch]$Force) $script:Written = $Entity }
    function Write-AlertTrace { param($cmdletName, $tenantFilter, $data) $script:Alerted = @($data) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData) $script:Logs += @([pscustomobject]@{ Message = $message; Sev = $sev }) }
    function Get-CippException { param($Exception) @{ NormalizedError = $Exception.Exception.Message } }

    function New-Approval {
        param($Id, $AppId = 'app-1', $AppName = 'Granola', $ConsentType = 'Dynamic', $Scopes = @('Calendars.Read'))
        [pscustomobject]@{ id = $Id; appId = $AppId; appDisplayName = $AppName; consentType = $ConsentType
            pendingScopes = @($Scopes | ForEach-Object { [pscustomobject]@{ displayName = $_ } }) }
    }
    function New-UserRequest {
        param($Id, $Status = 'InProgress', $Upn = 'amber@contoso.com', $Reason = 'Need it')
        [pscustomobject]@{ id = $Id; reason = $Reason; status = $Status; createdDateTime = '2026-09-17T18:44:00Z'
            createdBy = [pscustomobject]@{ user = [pscustomobject]@{ userPrincipalName = $Upn } } }
    }
    function Set-Baseline { param([string[]]$Ids) $script:PreviousRow = [pscustomobject]@{ delta = (ConvertTo-Json -InputObject $Ids -Compress) } }
}

Describe 'Get-CIPPAlertNewAppApproval' {
    BeforeEach {
        $script:Approvals = @()
        $script:Children = @{}
        $script:PreviousRow = $null
        $script:Written = $null
        $script:Alerted = $null
        $script:Logs = @()
        $script:ChildThrows = $false
        $script:TopThrows = $false
    }

    It 'surfaces a pending request with requester, justification and scopes' {
        Set-Baseline -Ids @()
        $script:Approvals = @(New-Approval -Id 'r1')
        $script:Children['r1'] = @(New-UserRequest -Id 'u1')

        Get-CIPPAlertNewAppApproval -TenantFilter 'contoso.com'

        $script:Alerted | Should -HaveCount 1
        $script:Alerted[0].AppName | Should -Be 'Granola'
        $script:Alerted[0].RequestUser | Should -Be 'amber@contoso.com'
        $script:Alerted[0].Reason | Should -Be 'Need it'
        $script:Alerted[0].Scopes | Should -Be 'Calendars.Read'
    }

    It 'carries a consent URL with bf_id so approving RESOLVES the request' {
        Set-Baseline -Ids @()
        $script:Approvals = @(New-Approval -Id 'r1')
        $script:Children['r1'] = @(New-UserRequest -Id 'u1')

        Get-CIPPAlertNewAppApproval -TenantFilter 'contoso.com'

        # Without bf_id the consent is granted but the request dangles until it expires.
        $script:Alerted[0].ConsentURL | Should -Match 'bf_id=r1'
        $script:Alerted[0].ConsentURL | Should -Match 'client_id=app-1'
        $script:Alerted[0].ConsentURL | Should -Match 'redirect_uri=https://entra\.microsoft\.com/TokenAuthorize'
    }

    It 'carries a CIPP deep link to the approval queue' {
        Set-Baseline -Ids @()
        $script:Approvals = @(New-Approval -Id 'r1')
        $script:Children['r1'] = @(New-UserRequest -Id 'u1')

        Get-CIPPAlertNewAppApproval -TenantFilter 'contoso.com'

        $script:Alerted[0].CippURL | Should -Be 'https://cipp.aspendora.com/tenant/administration/app-consent-requests?tenantFilter=contoso.com'
    }

    It 'uses the Static consent URL shape when consentType is Static' {
        Set-Baseline -Ids @()
        $script:Approvals = @(New-Approval -Id 'r1' -ConsentType 'Static')
        $script:Children['r1'] = @(New-UserRequest -Id 'u1')

        Get-CIPPAlertNewAppApproval -TenantFilter 'contoso.com'

        $script:Alerted[0].ConsentURL | Should -Match '/adminConsent\?'
        $script:Alerted[0].ConsentURL | Should -Not -Match '/v2\.0/'
    }

    It 'ignores requests that are no longer actionable' -ForEach @('Expired', 'Completed', 'Denied') {
        Set-Baseline -Ids @()
        $script:Approvals = @(New-Approval -Id 'r1')
        $script:Children['r1'] = @(New-UserRequest -Id 'u1' -Status $_)

        Get-CIPPAlertNewAppApproval -TenantFilter 'contoso.com'

        $script:Alerted | Should -BeNullOrEmpty
    }

    It 'establishes a baseline silently on first run' {
        $script:Approvals = @(New-Approval -Id 'r1')
        $script:Children['r1'] = @(New-UserRequest -Id 'u1')

        Get-CIPPAlertNewAppApproval -TenantFilter 'contoso.com'

        $script:Alerted | Should -BeNullOrEmpty
        ($script:Written.delta | ConvertFrom-Json) | Should -Contain 'u1'
        ($script:Logs.Message -join ' ') | Should -Match 'baseline established'
    }

    It 'does not re-alert while a request stays pending' {
        # The behaviour this alert previously had: it re-fired every single run.
        Set-Baseline -Ids @('u1')
        $script:Approvals = @(New-Approval -Id 'r1')
        $script:Children['r1'] = @(New-UserRequest -Id 'u1')

        Get-CIPPAlertNewAppApproval -TenantFilter 'contoso.com'

        $script:Alerted | Should -BeNullOrEmpty
    }

    It 'reports a second person requesting the same app' {
        Set-Baseline -Ids @('u1')
        $script:Approvals = @(New-Approval -Id 'r1')
        $script:Children['r1'] = @((New-UserRequest -Id 'u1'), (New-UserRequest -Id 'u2' -Upn 'blair@contoso.com'))

        Get-CIPPAlertNewAppApproval -TenantFilter 'contoso.com'

        $script:Alerted | Should -HaveCount 1
        $script:Alerted[0].RequestUser | Should -Be 'blair@contoso.com'
    }

    It 'caps a burst, records the rest as seen, and warns' {
        Set-Baseline -Ids @()
        $script:Approvals = 1..25 | ForEach-Object { New-Approval -Id "r$_" -AppId "app-$_" }
        1..25 | ForEach-Object { $script:Children["r$_"] = @(New-UserRequest -Id "u$_") }

        Get-CIPPAlertNewAppApproval -TenantFilter 'contoso.com' -InputValue ([pscustomobject]@{ AppApprovalMaxPerCycle = 10 })

        $script:Alerted | Should -HaveCount 10
        ($script:Written.delta | ConvertFrom-Json) | Should -HaveCount 25
        ($script:Logs | Where-Object { $_.Sev -eq 'Warning' }).Message | Should -Match 'exceeded the per-cycle cap'
    }

    It 'keeps going when one request cannot be read' {
        Set-Baseline -Ids @()
        $script:Approvals = @(New-Approval -Id 'r1')
        $script:ChildThrows = $true

        { Get-CIPPAlertNewAppApproval -TenantFilter 'contoso.com' } | Should -Not -Throw
        ($script:Logs.Message -join ' ') | Should -Match 'could not read user requests'
    }

    It 'logs a failure instead of swallowing it' {
        # Previously an empty catch{} - a broken query looked identical to a quiet tenant.
        $script:TopThrows = $true

        { Get-CIPPAlertNewAppApproval -TenantFilter 'contoso.com' } | Should -Not -Throw
        ($script:Logs | Where-Object { $_.Sev -eq 'Error' }).Message | Should -Match 'Could not check pending app consent requests'
    }
}
