# Pending app consent requests, surfaced as a ticket with both ways to act on them.
#
# Microsoft provides NO API to approve or deny an admin consent request. The documented mechanism is
# a rebuilt consent URL, and the bf_id parameter is what ties the grant back to the request so Entra
# marks it approved - without bf_id the grant succeeds but the request stays InProgress until it
# expires. That is asserted here because it is silent when wrong.
#
# Dedup runs on the REAL AlertLifecycle (see AlertLifecycleHarness.ps1), so these tests assert on
# what is notified across consecutive runs - including the one-time hand-over from the fork's old
# DeltaCompare baseline, which must not re-ticket requests that were already known.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Tests/Alerts/AlertLifecycleHarness.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertNewAppApproval.ps1')

    function New-GraphGetRequest {
        param($Uri, $tenantid)
        if ($script:TopThrows) { throw 'graph exploded' }
        if ($Uri -match '/userConsentRequests$') {
            $ParentId = ([regex]::Match($Uri, 'appConsentRequests/([^/]+)/userConsentRequests')).Groups[1].Value
            if ($script:ChildThrows -contains $ParentId) { throw 'child blew up' }
            return $script:Children[$ParentId]
        }
        return $script:Approvals
    }
    function Get-Tenants { param($TenantFilter, [switch]$SkipDomains) [pscustomobject]@{ customerId = 'cust-0001' } }

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
    function Set-Pending {
        param([string[]]$UserRequestIds)
        $script:Approvals = @(New-Approval -Id 'r1')
        $script:Children['r1'] = @($UserRequestIds | ForEach-Object { New-UserRequest -Id $_ -Upn "$_@contoso.com" })
    }
    function Invoke-Alert { param($InputValue) @(Get-CIPPAlertNewAppApproval -TenantFilter 'contoso.com' -InputValue $InputValue) }
    # An already-migrated tenant: old baseline handed over with nothing in it.
    function Set-Migrated { Set-OldBaseline -Partition 'AppApprovalDelta' -Tenant 'contoso.com' -Ids @(); $null = Invoke-Alert }
}

Describe 'Get-CIPPAlertNewAppApproval' {
    BeforeEach {
        Reset-AlertStore
        $script:Approvals = @()
        $script:Children = @{}
        $script:ChildThrows = @()
        $script:TopThrows = $false
        Add-CIPPAzDataTableEntity -TableName 'Config' -Entity @{ PartitionKey = 'InstanceProperties'; RowKey = 'CIPPURL'; Value = 'cipp.aspendora.com' }
    }

    Context 'ticket content' {
        BeforeEach { Set-Migrated }

        It 'surfaces a pending request with requester, justification and scopes' {
            $script:Approvals = @(New-Approval -Id 'r1')
            $script:Children['r1'] = @(New-UserRequest -Id 'u1')

            $Alerted = Invoke-Alert

            $Alerted | Should -HaveCount 1
            $Alerted[0].AppName | Should -Be 'Granola'
            $Alerted[0].RequestUser | Should -Be 'amber@contoso.com'
            $Alerted[0].Reason | Should -Be 'Need it'
            $Alerted[0].Scopes | Should -Be 'Calendars.Read'
        }

        It 'carries a consent URL with bf_id so approving RESOLVES the request' {
            $script:Approvals = @(New-Approval -Id 'r1')
            $script:Children['r1'] = @(New-UserRequest -Id 'u1')

            $Alerted = Invoke-Alert

            # Without bf_id the consent is granted but the request dangles until it expires.
            $Alerted[0].ConsentURL | Should -Match 'bf_id=r1'
            $Alerted[0].ConsentURL | Should -Match 'client_id=app-1'
            $Alerted[0].ConsentURL | Should -Match 'redirect_uri=https://entra\.microsoft\.com/TokenAuthorize'
        }

        It 'carries a CIPP deep link to the approval queue' {
            $script:Approvals = @(New-Approval -Id 'r1')
            $script:Children['r1'] = @(New-UserRequest -Id 'u1')

            (Invoke-Alert)[0].CippURL | Should -Be 'https://cipp.aspendora.com/tenant/administration/app-consent-requests?tenantFilter=contoso.com'
        }

        It 'uses the Static consent URL shape when consentType is Static' {
            $script:Approvals = @(New-Approval -Id 'r1' -ConsentType 'Static')
            $script:Children['r1'] = @(New-UserRequest -Id 'u1')

            $Url = (Invoke-Alert)[0].ConsentURL
            $Url | Should -Match '/adminConsent\?'
            $Url | Should -Not -Match '/v2\.0/'
        }

        It 'ignores requests that are no longer actionable' -ForEach @('Expired', 'Completed', 'Denied') {
            $script:Approvals = @(New-Approval -Id 'r1')
            $script:Children['r1'] = @(New-UserRequest -Id 'u1' -Status $_)

            Invoke-Alert | Should -BeNullOrEmpty
        }
    }

    Context 'lifecycle across runs' {
        BeforeEach { Set-Migrated }

        It 'notifies once and does not re-alert while a request stays pending' {
            Set-Pending 'u1'
            Invoke-Alert | Should -HaveCount 1
            Invoke-Alert | Should -BeNullOrEmpty
            Invoke-Alert | Should -BeNullOrEmpty
        }

        It 'reports a second person requesting the same app' {
            Set-Pending 'u1'
            $null = Invoke-Alert
            Set-Pending 'u1', 'u2'

            $Alerted = Invoke-Alert
            $Alerted | Should -HaveCount 1
            $Alerted[0].RequestId | Should -Be 'u2'
        }

        It 'resolves a request once it is no longer pending, including on an empty run' {
            Set-Pending 'u1'
            $null = Invoke-Alert
            $script:Approvals = @()

            Invoke-Alert | Should -BeNullOrEmpty
            (Get-LifecycleState 'Get-CIPPAlertNewAppApproval')['u1'] | Should -Be 'Resolved'
        }

        It 'does not resolve requests it could not read, and does not re-notify them later' {
            $script:Approvals = @((New-Approval -Id 'r1'), (New-Approval -Id 'r2' -AppId 'app-2'))
            $script:Children['r1'] = @(New-UserRequest -Id 'u1')
            $script:Children['r2'] = @(New-UserRequest -Id 'u2')
            Invoke-Alert | Should -HaveCount 2

            $script:ChildThrows = @('r2')
            Invoke-Alert | Should -BeNullOrEmpty
            (Get-LifecycleState 'Get-CIPPAlertNewAppApproval')['u2'] | Should -Be 'Open'
            ($script:Logs.Message -join ' ') | Should -Match 'could not read user requests'

            $script:ChildThrows = @()
            Invoke-Alert | Should -BeNullOrEmpty
        }

        It 'caps a burst of new requests, keeps the rest open so they never arrive later, and warns' {
            $script:Approvals = 1..25 | ForEach-Object { New-Approval -Id "r$_" -AppId "app-$_" }
            1..25 | ForEach-Object { $script:Children["r$_"] = @(New-UserRequest -Id "u$_") }

            Invoke-Alert -InputValue ([pscustomobject]@{ AppApprovalMaxPerCycle = 10 }) | Should -HaveCount 10
            ($script:Logs | Where-Object { $_.Sev -eq 'Warning' }).Message | Should -Match 'exceeded the per-cycle cap'
            Invoke-Alert -InputValue ([pscustomobject]@{ AppApprovalMaxPerCycle = 10 }) | Should -BeNullOrEmpty
        }
    }

    Context 'hand-over from the old DeltaCompare baseline' {
        It 'does not re-ticket requests the old baseline already knew' {
            Set-OldBaseline -Partition 'AppApprovalDelta' -Tenant 'contoso.com' -Ids @('u1', 'u2')
            Set-Pending 'u1', 'u2', 'u3'

            $Alerted = Invoke-Alert
            $Alerted | Should -HaveCount 1
            $Alerted[0].RequestId | Should -Be 'u3'
        }

        It 'hands over exactly once' {
            Set-OldBaseline -Partition 'AppApprovalDelta' -Tenant 'contoso.com' -Ids @('u1')
            Set-Pending 'u1'
            $null = Invoke-Alert
            (Get-CIPPAzDataTableEntity -TableName 'DeltaCompare' -Filter "PartitionKey eq 'AppApprovalDelta'").LifecycleSeeded | Should -Be 'true'

            # A later empty lifecycle must not trigger a second silent seed that swallows a real request.
            $script:Store['AlertLifecycle'] = @{}
            Set-Pending 'u9'
            Invoke-Alert | Should -HaveCount 1
        }

        It 'surfaces nothing on the first run of a never-baselined tenant' {
            Set-Pending 'u1', 'u2'

            Invoke-Alert | Should -BeNullOrEmpty
            (Get-LifecycleState 'Get-CIPPAlertNewAppApproval')['u1'] | Should -Be 'Open'
            Set-Pending 'u1', 'u2', 'u3'
            (Invoke-Alert)[0].RequestId | Should -Be 'u3'
        }

        It 'does not swallow the first request on a tenant that has only ever been quiet' {
            $null = Invoke-Alert
            Set-Pending 'u1'
            Invoke-Alert | Should -HaveCount 1
        }
    }

    It 'logs a failure instead of swallowing it, and does not reconcile' {
        Set-Migrated
        Set-Pending 'u1'
        $null = Invoke-Alert
        $script:TopThrows = $true

        { Invoke-Alert } | Should -Not -Throw
        ($script:Logs | Where-Object { $_.Sev -eq 'Error' }).Message | Should -Match 'Could not check pending app consent requests'
        # "could not check" is not "clear": the open request must not have been resolved.
        (Get-LifecycleState 'Get-CIPPAlertNewAppApproval')['u1'] | Should -Be 'Open'
    }
}
