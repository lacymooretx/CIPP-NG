# Aspendora fork (Vikunja CIPP-56, CIPP-54): audit alert when a break-glass exclusion is weakened.
# Event fixtures follow real directoryAudits records from 3endt.com, read on 2026-11-03.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/BreakGlass/Get-CIPPBreakGlassExclusionAuditFinding.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertBreakGlassExclusionChange.ps1')

    function Get-CIPPBreakGlassAccounts { param($TenantFilter) $script:Registered }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
    function Write-LogMessage { param($API, $tenant, $message, $sev) $script:Logs.Add($message) }
    function Write-AlertTrace { param($cmdletName, $tenantFilter, $data, [switch]$Append) $script:AppendUsed = [bool]$Append; $script:Traced = $data; $data }
    function New-GraphGetRequest {
        param($uri, $tenantid)
        $script:Uris.Add($uri)
        if ($uri -match 'transitiveMemberOf') { if ($script:MemberOfThrows) { throw 'memberOf failed' }; return $script:Groups }
        if ($uri -match 'conditionalAccess/policies') { if ($script:PoliciesThrow) { throw 'policies failed' }; return $script:Policies }
        if ($uri -match "activityDisplayName eq 'Update conditional access policy'") { if ($script:AuditThrows) { throw 'audit failed' }; return $script:PolicyEvents }
        if ($uri -match 'targetResources/any') { return $script:GroupEvents }
    }

    function PolicyJson { param($ExUsers = @(), $ExGroups = @()) @{ id = 'pol'; state = 'enabled'; conditions = @{ users = @{ includeUsers = @('All'); excludeUsers = @($ExUsers); excludeGroups = @($ExGroups) } } } | ConvertTo-Json -Depth 6 -Compress }
    function PolicyEvent {
        param($Id = 'ev1', $OldUsers = @(), $OldGroups = @(), $NewUsers = @(), $NewGroups = @(), $Result = 'success')
        [pscustomobject]@{
            id = $Id; result = $Result; activityDisplayName = 'Update conditional access policy'; activityDateTime = '2026-10-31T19:58:48.3370529Z'
            initiatedBy = [pscustomobject]@{ user = [pscustomobject]@{ displayName = 'Aspendora CSP Technician'; userPrincipalName = 'user_142@aspendoracsp.com' }; app = [pscustomobject]@{ displayName = 'CIPP-SAM' } }
            targetResources = @([pscustomobject]@{ id = 'pol'; displayName = 'Require MFA'; type = 'Policy'; modifiedProperties = @([pscustomobject]@{ displayName = 'ConditionalAccessPolicy'; oldValue = (PolicyJson $OldUsers $OldGroups); newValue = (PolicyJson $NewUsers $NewGroups) }) })
        }
    }
    function MemberEvent {
        param($Id = 'ev2', $MemberId = 'ann', $Upn = 'ann@contoso.com', $GroupId = 'grp')
        [pscustomobject]@{
            id = $Id; result = 'success'; activityDisplayName = 'Add member to group'; activityDateTime = '2026-10-31T19:55:44.9930083Z'
            initiatedBy = [pscustomobject]@{ app = $null; user = [pscustomobject]@{ displayName = 'Rogue Admin'; userPrincipalName = 'rogue@contoso.com' } }
            targetResources = @(
                [pscustomobject]@{ id = $MemberId; type = 'User'; userPrincipalName = $Upn; displayName = $null; modifiedProperties = @() }
                [pscustomobject]@{ id = $GroupId; type = 'Group'; userPrincipalName = $null; displayName = $null; modifiedProperties = @() }
            )
        }
    }
    function Finding { param($AuditEvent) Get-CIPPBreakGlassExclusionAuditFinding -AuditEvent $AuditEvent -Accounts $script:Accts -GroupNames @{ grp = 'CA Exclusion' } -ExclusionGroupIds @('grp') }
}

Describe 'Get-CIPPBreakGlassExclusionAuditFinding' {
    BeforeEach {
        $script:Accts = @([pscustomobject]@{ Id = 'bg1'; UserPrincipalName = 'bg1@contoso.com'; GroupIds = @('grp') })
    }

    It 'names the actor, policy and group when the exclusion group is removed' {
        $F = Finding (PolicyEvent -OldGroups @('grp', 'keep') -NewGroups @('keep'))
        $F.Id | Should -Be 'Audit|ev1'
        $F.Type | Should -Be 'ExclusionRemoved'
        $F.Severity | Should -Be 'High'
        $F.Actor | Should -Be 'Aspendora CSP Technician (user_142@aspendoracsp.com) via CIPP-SAM'
        $F.Policy | Should -Be 'Require MFA'
        $F.Removed | Should -Be "group 'CA Exclusion'"
        $F.Exposed | Should -Be 'bg1@contoso.com'
        $F.Message | Should -Match 'NOT excluded'
    }

    It 'catches a registered account removed directly' {
        $F = Finding (PolicyEvent -OldUsers @('bg1') -OldGroups @() -NewUsers @())
        $F.Removed | Should -Be 'account bg1@contoso.com'
        $F.Exposed | Should -Be 'bg1@contoso.com'
    }

    It 'says the account is still covered when a user exclusion moves to the group' {
        $F = Finding (PolicyEvent -OldUsers @('bg1') -NewGroups @('grp'))
        $F.Exposed | Should -BeNullOrEmpty
        $F.Message | Should -Match 'still excluded another way'
    }

    It 'ignores the other direction, and unrelated exclusion changes' {
        Finding (PolicyEvent -NewGroups @('grp')) | Should -BeNullOrEmpty
        Finding (PolicyEvent -OldUsers @('someone') -OldGroups @('other')) | Should -BeNullOrEmpty
        Finding (PolicyEvent -OldGroups @('grp') -NewGroups @('grp')) | Should -BeNullOrEmpty
    }

    It 'ignores a failed update, which changed nothing' {
        Finding (PolicyEvent -OldGroups @('grp') -Result 'failure') | Should -BeNullOrEmpty
    }

    It 'names an app-only actor, and does not put a UserPrincipalName on the row' {
        $E = PolicyEvent -OldGroups @('grp')
        $E.initiatedBy = [pscustomobject]@{ user = $null; app = [pscustomobject]@{ displayName = 'Some Vendor App' } }
        $F = Finding $E
        $F.Actor | Should -Be 'Some Vendor App'
        $F.PSObject.Properties.Name | Should -Not -Contain 'UserPrincipalName'
    }

    It 'gives the time in Central with UTC beside it' {
        (Finding (PolicyEvent -OldGroups @('grp'))).When | Should -Be '2026-10-31 14:58 CDT (19:58 UTC)'
    }

    It 'flags a non-registered member joining the exclusion group' {
        $F = Finding (MemberEvent)
        $F.Type | Should -Be 'ExclusionGroupMemberAdded'
        $F.Member | Should -Be 'ann@contoso.com'
        $F.Group | Should -Be 'CA Exclusion'
        $F.Actor | Should -Be 'Rogue Admin (rogue@contoso.com)'
    }

    It 'allows a registered account joining, and ignores other groups' {
        Finding (MemberEvent -MemberId 'bg1' -Upn 'bg1@contoso.com') | Should -BeNullOrEmpty
        Finding (MemberEvent -GroupId 'other') | Should -BeNullOrEmpty
    }

    It 'ignores other activity on the group' {
        $E = MemberEvent; $E.activityDisplayName = 'Add group'
        Finding $E | Should -BeNullOrEmpty
    }
}

Describe 'Get-CIPPAlertBreakGlassExclusionChange' {
    BeforeEach {
        $script:Registered = @([pscustomobject]@{ RowKey = 'bg1'; UserPrincipalName = 'bg1@contoso.com' })
        $script:Groups = @([pscustomobject]@{ id = 'grp'; displayName = 'CA Exclusion' })
        $script:Policies = @([pscustomobject]@{ id = 'pol'; conditions = @{ users = @{ excludeGroups = @('grp') } } })
        $script:PolicyEvents = @(); $script:GroupEvents = @()
        $script:MemberOfThrows = $false; $script:PoliciesThrow = $false; $script:AuditThrows = $false
        $script:Uris = [System.Collections.Generic.List[string]]::new()
        $script:Logs = [System.Collections.Generic.List[string]]::new()
        $script:Traced = $null; $script:AppendUsed = $null
    }

    It 'does nothing for a tenant with no registered accounts' {
        $script:Registered = @()
        Get-CIPPAlertBreakGlassExclusionChange -TenantFilter 't' | Should -BeNullOrEmpty
        $script:Uris.Count | Should -Be 0
    }

    It 'stays quiet and leaves the trace alone when nothing changed' {
        Get-CIPPAlertBreakGlassExclusionChange -TenantFilter 't' | Should -BeNullOrEmpty
        $script:Traced | Should -BeNullOrEmpty
    }

    It 'raises each finding through the trace in append mode, so each event notifies once' {
        $script:PolicyEvents = @(PolicyEvent -OldGroups @('grp'))
        $script:GroupEvents = @(MemberEvent)
        $Out = @(Get-CIPPAlertBreakGlassExclusionChange -TenantFilter 't')
        @($Out.Id | Sort-Object) | Should -Be @('Audit|ev1', 'Audit|ev2')
        $script:AppendUsed | Should -BeTrue
    }

    It 'keeps checking the account exclusion when group membership cannot be read' {
        $script:MemberOfThrows = $true
        $script:PolicyEvents = @(PolicyEvent -OldUsers @('bg1'))
        (@(Get-CIPPAlertBreakGlassExclusionChange -TenantFilter 't'))[0].Removed | Should -Be 'account bg1@contoso.com'
        $script:Logs -join ';' | Should -Match 'could not read groups'
    }

    It 'logs and still checks policy updates when the policies cannot be read' {
        $script:PoliciesThrow = $true
        $script:PolicyEvents = @(PolicyEvent -OldGroups @('grp'))
        @(Get-CIPPAlertBreakGlassExclusionChange -TenantFilter 't').Count | Should -Be 1
        @($script:Uris | Where-Object { $_ -match 'targetResources/any' }).Count | Should -Be 0
        $script:Logs -join ';' | Should -Match 'could not read policies'
    }

    It 'logs a failed audit read rather than failing' {
        $script:AuditThrows = $true
        { Get-CIPPAlertBreakGlassExclusionChange -TenantFilter 't' } | Should -Not -Throw
        $script:Logs -join ';' | Should -Match 'could not read policy updates'
    }

    It 'skips one malformed event and still reports the good one' {
        $Bad = PolicyEvent -Id 'bad' -OldGroups @('grp')
        $Bad.targetResources[0].modifiedProperties[0].newValue = '{not json'
        $script:PolicyEvents = @($Bad, (PolicyEvent -Id 'good' -OldGroups @('grp')))
        (@(Get-CIPPAlertBreakGlassExclusionChange -TenantFilter 't')).Id | Should -Be 'Audit|good'
        $script:Logs -join ';' | Should -Match 'could not read audit event bad'
    }
}
