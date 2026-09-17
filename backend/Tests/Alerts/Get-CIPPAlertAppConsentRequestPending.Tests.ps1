# Pending app consent requests, surfaced as a ticket instead of sitting in a portal queue nobody
# watches. The motivating evidence: on aspendora.com - the ONE tenant with the request workflow
# enabled - a real request ("Need it", from lacy@) sat unreviewed until status reached 'Expired'.
#
# Only 'InProgress' is actionable, so only that is surfaced. The same back-fill and cap guards as
# the blocked-consent alert apply, for the same reason (ControlR flood, #57308-#57357).

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertAppConsentRequestPending.ps1'

    function New-GraphGetRequest {
        param($uri, $tenantid, $ErrorAction)
        if ($uri -match '/userConsentRequests$') {
            if ($script:ChildThrows) { throw 'child blew up' }
            $ParentId = ([regex]::Match($uri, "appConsentRequests/([^/]+)/userConsentRequests")).Groups[1].Value
            return $script:Children[$ParentId]
        }
        return $script:Requests
    }
    function Get-Tenants { param($TenantFilter) [pscustomobject]@{ customerId = 'cust-guid-0001' } }
    function Get-CIPPTable { param($Table, $TableName) @{ Context = 'stub' } }
    function Get-CIPPAzDataTableEntity { param($Context, $Filter) return $script:PreviousRow }
    function Add-CIPPAzDataTableEntity { param($Context, $Entity, [switch]$Force) $script:Written = $Entity }
    function Write-AlertTrace { param($cmdletName, $tenantFilter, $data) $script:Alerted = @($data) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData) $script:Logs += @([pscustomobject]@{ Message = $message; Sev = $sev }) }
    function Get-CippException { param($Exception) @{ NormalizedError = $Exception.Exception.Message } }

    . $FunctionPath

    function New-Request {
        param($Id, $AppId = 'app-1', $AppName = 'Summary AI', $Scopes = @('calendars.read', 'openid'))
        [pscustomobject]@{ id = $Id; appId = $AppId; appDisplayName = $AppName; pendingScopes = @($Scopes | ForEach-Object { [pscustomobject]@{ displayName = $_ } }) }
    }
    function New-UserRequest {
        param($Id, $Status = 'InProgress', $Upn = 'lacy@aspendora.com', $Reason = 'Need it')
        [pscustomobject]@{
            id = $Id; reason = $Reason; status = $Status
            createdDateTime = '2026-08-09T22:26:39Z'
            createdBy = [pscustomobject]@{ user = [pscustomobject]@{ userPrincipalName = $Upn } }
        }
    }
    function Set-Baseline { param([string[]]$Ids) $script:PreviousRow = [pscustomobject]@{ delta = (ConvertTo-Json -InputObject $Ids -Compress) } }
}

Describe 'Get-CIPPAlertAppConsentRequestPending' {
    BeforeEach {
        $script:Requests = @()
        $script:Children = @{}
        $script:PreviousRow = $null
        $script:Written = $null
        $script:Alerted = $null
        $script:Logs = @()
        $script:ChildThrows = $false
    }

    It 'stays silent on a tenant with the workflow disabled (no requests at all)' {
        Get-CIPPAlertAppConsentRequestPending -TenantFilter 'contoso.com'

        $script:Alerted | Should -BeNullOrEmpty
        # The normal case for ~7 of 8 tenants - it must not log noise every cycle.
        $script:Logs | Should -BeNullOrEmpty
    }

    It 'surfaces a pending request with its justification and requester' {
        Set-Baseline -Ids @()
        $script:Requests = @(New-Request -Id 'r1')
        $script:Children['r1'] = @(New-UserRequest -Id 'u1')

        Get-CIPPAlertAppConsentRequestPending -TenantFilter 'contoso.com'

        $script:Alerted | Should -HaveCount 1
        $script:Alerted[0].'Application' | Should -Be 'Summary AI'
        $script:Alerted[0].'Requested By' | Should -Be 'lacy@aspendora.com'
        $script:Alerted[0].'Justification' | Should -Be 'Need it'
        $script:Alerted[0].'Permissions' | Should -Be 'calendars.read, openid'
        $script:Alerted[0].'Admin Consent URL' | Should -Be 'https://login.microsoftonline.com/cust-guid-0001/adminconsent?client_id=app-1'
    }

    It 'ignores requests that are no longer actionable' -ForEach @('Expired', 'Completed', 'Denied') {
        Set-Baseline -Ids @()
        $script:Requests = @(New-Request -Id 'r1')
        $script:Children['r1'] = @(New-UserRequest -Id 'u1' -Status $_)

        Get-CIPPAlertAppConsentRequestPending -TenantFilter 'contoso.com'

        $script:Alerted | Should -BeNullOrEmpty
    }

    It 'establishes a baseline silently on first run' {
        $script:Requests = @(New-Request -Id 'r1')
        $script:Children['r1'] = @(New-UserRequest -Id 'u1')

        Get-CIPPAlertAppConsentRequestPending -TenantFilter 'contoso.com'

        $script:Alerted | Should -BeNullOrEmpty
        ($script:Written.delta | ConvertFrom-Json) | Should -Contain 'u1'
        ($script:Logs.Message -join ' ') | Should -Match 'baseline established'
    }

    It 'does not re-alert on a request already surfaced' {
        Set-Baseline -Ids @('u1')
        $script:Requests = @(New-Request -Id 'r1')
        $script:Children['r1'] = @(New-UserRequest -Id 'u1')

        Get-CIPPAlertAppConsentRequestPending -TenantFilter 'contoso.com'

        $script:Alerted | Should -BeNullOrEmpty
    }

    It 'reports a second person requesting the same app' {
        # Keyed on request id, not app id - otherwise the second requester is invisible.
        Set-Baseline -Ids @('u1')
        $script:Requests = @(New-Request -Id 'r1')
        $script:Children['r1'] = @((New-UserRequest -Id 'u1'), (New-UserRequest -Id 'u2' -Upn 'amber@contoso.com'))

        Get-CIPPAlertAppConsentRequestPending -TenantFilter 'contoso.com'

        $script:Alerted | Should -HaveCount 1
        $script:Alerted[0].'Requested By' | Should -Be 'amber@contoso.com'
    }

    It 'caps a burst, records the rest as seen, and warns' {
        Set-Baseline -Ids @()
        $script:Requests = 1..25 | ForEach-Object { New-Request -Id "r$_" -AppId "app-$_" }
        1..25 | ForEach-Object { $script:Children["r$_"] = @(New-UserRequest -Id "u$_") }

        Get-CIPPAlertAppConsentRequestPending -TenantFilter 'contoso.com' -InputValue ([pscustomobject]@{ AppConsentRequestMaxPerCycle = 10 })

        $script:Alerted | Should -HaveCount 10
        ($script:Written.delta | ConvertFrom-Json) | Should -HaveCount 25
        ($script:Logs | Where-Object { $_.Sev -eq 'Warning' }).Message | Should -Match 'exceeded the per-cycle cap'
    }

    It 'keeps going when one request cannot be read' {
        Set-Baseline -Ids @()
        $script:Requests = @(New-Request -Id 'r1')
        $script:ChildThrows = $true

        { Get-CIPPAlertAppConsentRequestPending -TenantFilter 'contoso.com' } | Should -Not -Throw
        $script:Alerted | Should -BeNullOrEmpty
        ($script:Logs.Message -join ' ') | Should -Match 'could not read user requests'
    }
}
