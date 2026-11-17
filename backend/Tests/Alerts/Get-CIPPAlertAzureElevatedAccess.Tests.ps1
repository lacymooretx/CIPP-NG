# Aspendora fork (Vikunja CIPP-45): "elevate access" by a Global Admin. Audit events notify once each (append);
# standing root-scope assignments notify once and resolve when removed; allowed actors are left out of both.
# Runs on the real AlertLifecycle.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Tests/Alerts/AlertLifecycleHarness.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertAzureElevatedAccess.ps1')

    function New-GraphGetRequest {
        [CmdletBinding()] param($uri, $tenantid, $scope, $AsApp, $NoAuthCheck)
        if ($uri -like '*directoryAudits*') { if ($script:AuditThrows) { throw 'Forbidden' }; return $script:Events }
        if ($uri -match '/subscriptions\?api') { if ($script:ArmThrows) { throw 'AADSTS boom' }; return $script:Subs }
        if ($uri -like '*roleAssignments*') { return $script:Assignments }
        if ($uri -like '*directoryObjects/*') { $Id = ($uri -split '/')[-1]; if ($script:Principals.ContainsKey($Id)) { return $script:Principals[$Id] }; throw 'NotFound' }
        throw "unexpected $uri"
    }
    function Ev { param($Id, $Upn, $Activity = 'User has elevated their access to User Access Administrator for their Azure Resources') [pscustomobject]@{ id = $Id; activityDisplayName = $Activity; result = 'success'; activityDateTime = '2026-11-17T18:10:00Z'; initiatedBy = [pscustomobject]@{ user = [pscustomobject]@{ id = "id-$Upn"; userPrincipalName = $Upn; ipAddress = '1.2.3.4' } } } }
    function Ra { param($Name, $PrincipalId, $Scope = '/') [pscustomobject]@{ name = $Name; properties = [pscustomobject]@{ scope = $Scope; principalId = $PrincipalId; principalType = 'User'; roleDefinitionId = '/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'; createdOn = '2026-02-02T18:55:24Z' } } }
    function Run { param($InputValue) @(Get-CIPPAlertAzureElevatedAccess -TenantFilter 'contoso.com' -InputValue $InputValue | Where-Object { $_ }) }
}

Describe 'Get-CIPPAlertAzureElevatedAccess' {
    BeforeEach {
        Reset-AlertStore
        $script:AuditThrows = $false; $script:ArmThrows = $false
        $script:Events = @()
        $script:Subs = @()
        $script:Assignments = @()
        $script:Principals = @{ 'u1' = [pscustomobject]@{ userPrincipalName = 'admin@contoso.onmicrosoft.com' }; 'u2' = [pscustomobject]@{ userPrincipalName = 'bob@contoso.com' } }
    }

    It 'is quiet with no events and no readable subscriptions' {
        Run | Should -BeNullOrEmpty
        $script:Logs | Should -BeNullOrEmpty
    }

    It 'raises an elevation once as a Warning and a removal as Info' {
        $script:Events = @(Ev 'a1' 'bob@contoso.com')
        $Out = Run
        $Out.Id | Should -Be @('ElevateAccess|a1')
        $Out[0].Severity | Should -Be 'Warning'
        $Out[0].Message | Should -Match 'bob@contoso.com used'
        Run | Should -BeNullOrEmpty

        $script:Events = @(Ev 'a1' 'bob@contoso.com'), (Ev 'a2' 'bob@contoso.com' 'User has removed elevated access')
        $Out = Run
        $Out.Id | Should -Be @('ElevateAccess|a2')
        $Out[0].Severity | Should -Be 'Info'
    }

    It 'leaves allowed actors out, by UPN or object id, case-insensitively' {
        $script:Events = @((Ev 'a1' 'Admin@Contoso.onmicrosoft.com'), (Ev 'a2' 'bob@contoso.com'))
        (Run -InputValue @{ AllowedElevationActors = 'admin@contoso.onmicrosoft.com' }).Id | Should -Be @('ElevateAccess|a2')
        Reset-AlertStore
        (Run -InputValue 'id-bob@contoso.com, admin@contoso.onmicrosoft.com') | Should -BeNullOrEmpty
    }

    It 'raises standing root-scope assignments once and resolves them when removed' {
        $script:Subs = @([pscustomobject]@{ subscriptionId = 's1' })
        $script:Assignments = @((Ra 'r1' 'u1'), (Ra 'r2' 'u2'), (Ra 'r3' 'u2' '/subscriptions/s1'))
        $Out = Run -InputValue @{ AllowedElevationActors = 'admin@contoso.onmicrosoft.com' }
        $Out.Id | Should -Be @('RootScope|r2')
        $Out[0].Message | Should -Match "bob@contoso.com holds User Access Administrator at the Azure root scope"
        Run -InputValue @{ AllowedElevationActors = 'admin@contoso.onmicrosoft.com' } | Should -BeNullOrEmpty

        $script:Assignments = @((Ra 'r1' 'u1'))
        Run -InputValue @{ AllowedElevationActors = 'admin@contoso.onmicrosoft.com' } | Should -BeNullOrEmpty
        (Get-LifecycleState -CmdletName 'Get-CIPPAlertAzureElevatedAccessRootScope')['RootScope|r2'] | Should -Be 'Resolved'
    }

    It 'still reports the other signal when one read fails, and logs the failure' {
        $script:AuditThrows = $true
        $script:Subs = @([pscustomobject]@{ subscriptionId = 's1' })
        $script:Assignments = @((Ra 'r2' 'u2'))
        (Run).Id | Should -Be @('RootScope|r2')
        $script:Logs.Message | Should -Match 'audit log check failed'

        Reset-AlertStore
        $script:AuditThrows = $false; $script:ArmThrows = $true
        $script:Events = @(Ev 'a1' 'bob@contoso.com')
        (Run).Id | Should -Be @('ElevateAccess|a1')
        $script:Logs.Message | Should -Match 'root-scope check failed'
    }
}
