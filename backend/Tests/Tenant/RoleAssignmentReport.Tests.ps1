# Aspendora fork (Vikunja CIPP-15): standing-admin / least-privilege report - rules, collector, config and alert.
# Principal and PIM shapes copied from live reads (3endt.com has no P2, aspendora.com has P2; 2026-10-31).

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Tests/Alerts/AlertLifecycleHarness.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/RoleAssignments/Test-CIPPRoleAssignmentReport.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/RoleAssignments/Get-CIPPRoleAssignmentReport.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/RoleAssignments/Get-CIPPLeastPrivilegeRoles.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertStandingPrivilegedAccess.ps1')
    $env:CIPPRootPath = $RepoRoot
    $script:LP = Get-CIPPLeastPrivilegeRoles
    $script:GA = '62e90394-69f5-4237-9190-012177145e10'
    $script:AuthAdmin = 'c4e39bd9-1100-46d3-8c65-fb160da0071f'
    $script:Exchange = '29232cdf-9323-42fd-ade2-1d097af3e4de'
    $script:DirReaders = '88d8e3e3-8f55-4a1e-953a-9b9898b8876b'
    $script:Defs = @(
        [pscustomobject]@{ id = $script:GA; displayName = 'Global Administrator'; isBuiltIn = $true; isPrivileged = $true }
        [pscustomobject]@{ id = $script:AuthAdmin; displayName = 'Authentication Administrator'; isBuiltIn = $true; isPrivileged = $true }
        [pscustomobject]@{ id = $script:Exchange; displayName = 'Exchange Administrator'; isBuiltIn = $true; isPrivileged = $false }
        [pscustomobject]@{ id = $script:DirReaders; displayName = 'Directory Readers'; isBuiltIn = $true; isPrivileged = $false }
    )
    function Row {
        param($Id, $Role = $script:GA, $Kind = 'Active', $Permanent = $true, $Type = 'user', $UserType = 'Member', $Enabled = $true, $Owner = $null, $AppId = $null, $Name = $null, $End = $null)
        [pscustomobject]@{ PrincipalId = $Id; PrincipalType = $Type; PrincipalName = ($Name ?? $Id); UserPrincipalName = $(if ($Type -eq 'user') { "$Id@contoso.com" }); UserType = $UserType
            AccountEnabled = $Enabled; AppId = $AppId; AppOwnerOrganizationId = $Owner; RoleDefinitionId = $Role; Kind = $Kind; Permanent = $Permanent; EndDateTime = $End; Via = 'Direct' }
    }
    $script:Now = [datetime]'2026-10-31T12:00:00Z'
    function Check {
        param([hashtable]$P)
        $Base = @{ RoleDefinitions = $script:Defs; LeastPrivilege = $script:LP; Now = $script:Now; SignInKnown = $true; GdapKnown = $true }
        foreach ($K in $P.Keys) { $Base[$K] = $P[$K] }
        Test-CIPPRoleAssignmentReport @Base
    }
}

Describe 'LeastPrivilegeRoles.json' {
    It 'has a role id for every task and audit rule' {
        foreach ($T in $script:LP.tasks) { $script:LP.roles.($T.role) | Should -Not -BeNullOrEmpty -Because $T.task }
        foreach ($R in @($script:LP.auditRules.rules | Where-Object role)) { $script:LP.roles.($R.role) | Should -Not -BeNullOrEmpty -Because $R.role }
    }
    It 'uses well-formed role template ids' {
        foreach ($P in $script:LP.roles.PSObject.Properties) { $P.Value | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -Because $P.Name }
    }
    It 'answers the obvious tasks' {
        ($script:LP.tasks | Where-Object task -Match 'Reset MFA.*non-admin').role | Should -Be 'Authentication Administrator'
        ($script:LP.tasks | Where-Object task -Match '^Manage Intune').role | Should -Be 'Intune Administrator'
    }
}

Describe 'Test-CIPPRoleAssignmentReport' {
    It 'flags a permanent GA that is not break-glass, but not the break-glass account' {
        $R = Check @{ Assignments = @((Row 'bg'), (Row 'ga')); BreakGlassIds = @('bg'); SignIns = @{ bg = $script:Now; ga = $script:Now }; AdminActivity = @{ ga = @() } }
        $R.Findings.Key | Should -Be @('StandingGA|ga')
        $R.Findings[0].Message | Should -Match 'No Entra directory changes'
        $R.Summary.StandingGlobalAdmins | Should -Be 1
        $R.Summary.BreakGlassGlobalAdmins | Should -Be 1
    }

    It 'does not flag a PIM-activated (time-bound) GA' {
        $R = Check @{ Assignments = @((Row 'ga' -Permanent $false -End '2026-10-31T20:00:00Z')); SignIns = @{ ga = $script:Now } }
        @($R.Findings | Where-Object { $_.Key -like 'StandingGA*' }) | Should -BeNullOrEmpty
        $R.Assignments[0].Permanent | Should -Be 'No (ends 2026-10-31)'
    }

    It 'treats every active GA as standing without PIM and says so' {
        $R = Check @{ Assignments = @((Row 'ga' -Permanent $null)); PimKnown = $false; SignIns = @{ ga = $script:Now } }
        $R.Findings.Key | Should -Contain 'StandingGA|ga'
        $R.Findings.Key | Should -Contain 'PimUnavailable'
        ($R.Findings | Where-Object Key -EQ 'StandingGA|ga').Message | Should -Match 'without Entra ID P2'
        $R.Summary.PermanentActiveAssignments | Should -BeNullOrEmpty
    }

    It 'suggests smaller roles from the GA''s audit activity' {
        $Act = @(
            [pscustomobject]@{ activityDisplayName = 'Reset user password'; loggedByService = 'Core Directory'; category = 'UserManagement' }
            [pscustomobject]@{ activityDisplayName = 'Update conditional access policy'; loggedByService = 'Conditional Access'; category = 'Policy' }
            [pscustomobject]@{ activityDisplayName = 'Add member to group'; loggedByService = 'Core Directory'; category = 'GroupManagement' }
            [pscustomobject]@{ activityDisplayName = 'User registered security info'; loggedByService = 'Self-service Password Management'; category = 'UserManagement' }
        )
        $R = Check @{ Assignments = @((Row 'ga')); SignIns = @{ ga = $script:Now }; AdminActivity = @{ ga = $Act } }
        $R.Recommendations[0].SuggestedRoles | Should -Be 'Helpdesk Administrator, Conditional Access Administrator, Groups Administrator'
    }

    It 'says when the GA did something that needs GA' {
        $Act = @([pscustomobject]@{ activityDisplayName = 'Set Company Information'; loggedByService = 'Core Directory'; category = 'DirectoryManagement' })
        $R = Check @{ Assignments = @((Row 'ga')); SignIns = @{ ga = $script:Now }; AdminActivity = @{ ga = $Act } }
        ($R.Findings | Where-Object Key -EQ 'StandingGA|ga').Message | Should -Match 'need Global Administrator'
    }

    It 'never flags Microsoft first-party service principals, errors on a third-party GA app, and honours the allow-list' {
        $Rows = @(
            (Row 'ms' 'd65e02d2-0214-4674-8e5d-766fb330e2c0' -Type 'servicePrincipal' -Owner 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' -Name 'Microsoft Office 365 Portal')
            (Row 'evil' $script:GA -Type 'servicePrincipal' -Owner 'aaaa' -AppId 'app-evil' -Name 'Some App')
            (Row 'huntress' $script:Exchange -Type 'servicePrincipal' -Owner 'bbbb' -AppId 'app-h' -Name 'Huntress Security Platform')
            (Row 'reader' $script:DirReaders -Type 'servicePrincipal' -Owner 'cccc' -AppId 'app-r' -Name 'Reader App')
        )
        $R = Check @{ Assignments = $Rows; AllowedServicePrincipals = @('Huntress*') }
        @($R.Findings | Where-Object Account -EQ 'Microsoft Office 365 Portal') | Should -BeNullOrEmpty
        ($R.Findings | Where-Object Key -EQ 'SpGlobalAdmin|evil').Severity | Should -Be 'Error'
        ($R.Findings | Where-Object Key -EQ 'SpPrivilegedRole|huntress').Severity | Should -Be 'Info'
        ($R.Findings | Where-Object Key -EQ 'SpPrivilegedRole|reader').Severity | Should -Be 'Info'
        $R.Summary.ServicePrincipalsWithPrivilegedRoles | Should -Be 1
    }

    It 'flags guests with roles (Warning when privileged)' {
        $R = Check @{ Assignments = @((Row 'ian_aspendora.com#EXT#' $script:AuthAdmin -UserType 'Guest'), (Row 'g2' $script:DirReaders -UserType 'Guest')); SignIns = @{ 'ian_aspendora.com#EXT#' = $script:Now; g2 = $script:Now } }
        ($R.Findings | Where-Object Key -EQ 'GuestRole|ian_aspendora.com#EXT#').Severity | Should -Be 'Warning'
        ($R.Findings | Where-Object Key -EQ 'GuestRole|g2').Severity | Should -Be 'Info'
    }

    It 'flags privileged accounts with no recent or no sign-in, but not break-glass or unknown ones' {
        $Rows = @((Row 'old' $script:AuthAdmin), (Row 'never' $script:AuthAdmin), (Row 'fresh' $script:AuthAdmin), (Row 'bg' $script:GA), (Row 'new' $script:AuthAdmin), (Row 'ex-reader' $script:DirReaders))
        $SignIns = @{ old = $script:Now.AddDays(-100); never = $null; fresh = $script:Now.AddDays(-2); bg = $script:Now.AddDays(-300); 'ex-reader' = $null }
        $R = Check @{ Assignments = $Rows; SignIns = $SignIns; BreakGlassIds = @('bg') }
        @($R.Findings | Where-Object { $_.Key -like 'InactivePrivileged|*' }).Key | Sort-Object | Should -Be @('InactivePrivileged|never', 'InactivePrivileged|old')
        ($R.Assignments | Where-Object PrincipalId -EQ 'new').LastSignIn | Should -Be 'Unknown'
        ($R.Assignments | Where-Object PrincipalId -EQ 'never').LastSignIn | Should -Be 'Never'
    }

    It 'skips the inactivity check when sign-in activity is unknown' {
        $R = Check @{ Assignments = @((Row 'old' $script:AuthAdmin)); SignIns = @{ old = $null }; SignInKnown = $false }
        $R.Findings.Key | Should -Be @('SignInUnknown')
    }

    It 'reports disabled accounts that still hold roles as Info only' {
        $R = Check @{ Assignments = @((Row 'off' $script:GA -Enabled $false)) }
        $R.Findings.Key | Should -Be @('DisabledPrivileged|off')
        $R.Findings[0].Severity | Should -Be 'Info'
    }

    It 'flags active GDAP relationships that carry Global Administrator, naming the granting groups' {
        $Gdap = @(
            [pscustomobject]@{ Id = 'rel1'; DisplayName = 'Old GA relationship'; Status = 'active'; Roles = @($script:GA, $script:Exchange); Assignments = @([pscustomobject]@{ Id = 'as1'; Group = 'AdminAgents'; Roles = @($script:GA); Status = 'active' }) }
            [pscustomobject]@{ Id = 'rel2'; DisplayName = 'Least privilege'; Status = 'active'; Roles = @($script:Exchange); Assignments = @() }
            [pscustomobject]@{ Id = 'rel3'; DisplayName = 'Expired GA'; Status = 'expired'; Roles = @($script:GA); Assignments = @() }
        )
        $R = Check @{ GdapRelationships = $Gdap }
        $R.Findings.Key | Should -Be @('GdapGlobalAdmin|rel1')
        $R.Findings[0].Message | Should -Match 'AdminAgents'
        $R.Summary.GdapRelationshipsWithGlobalAdmin | Should -Be 1
    }

    It 'skips GDAP for the partner or a direct tenant' {
        $Gdap = @([pscustomobject]@{ Id = 'rel1'; DisplayName = 'x'; Status = 'active'; Roles = @($script:GA); Assignments = @() })
        $R = Check @{ GdapRelationships = $Gdap; GdapApplicable = $false }
        $R.Findings | Should -BeNullOrEmpty
        $R.Summary.GdapAvailable | Should -BeNullOrEmpty
    }
}

Describe 'Get-CIPPRoleAssignmentReport' {
    BeforeAll {
        function New-GraphGetRequest { [CmdletBinding()] param($uri, $tenantid, $noPagination, $NoAuthCheck, $AsApp) }
        function New-GraphBulkRequest { [CmdletBinding()] param($tenantid, $Requests, $NoAuthCheck, $asapp) }
        function Get-CIPPBreakGlassAccounts { param($TenantFilter) @([pscustomobject]@{ RowKey = 'bg' }) }
        function Get-Tenants { param($TenantFilter) [pscustomobject]@{ customerId = 'cust-1'; defaultDomainName = 'contoso.com'; delegatedPrivilegeStatus = 'granularDelegatedAdminPrivileges' } }
        $env:TenantID = 'partner-1'
        $script:User = { param($Id) [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = $Id; userPrincipalName = "$Id@contoso.com"; displayName = $Id; userType = 'Member'; accountEnabled = $true } }
    }

    It 'degrades to PIM-unknown on a tenant without P2 and reads sign-ins in a batch' {
        Mock New-GraphGetRequest {
            if ($uri -match 'roleAssignmentSchedules|roleEligibilitySchedules') { throw 'AadPremiumLicenseRequired: The tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID Governance license.' }
            if ($uri -match 'roleDefinitions') { return $script:Defs }
            if ($uri -match 'roleAssignments') { return @([pscustomobject]@{ principalId = 'ga'; roleDefinitionId = $script:GA; directoryScopeId = '/'; principal = (& $script:User 'ga') }, [pscustomobject]@{ principalId = 'bg'; roleDefinitionId = $script:GA; directoryScopeId = '/'; principal = (& $script:User 'bg') }) }
            if ($uri -match 'directoryAudits') { return @() }
            if ($uri -match 'delegatedAdminRelationships') { return @() }
            @()
        }
        Mock New-GraphBulkRequest { @($Requests | ForEach-Object { [pscustomobject]@{ id = $_.id; status = 200; body = [pscustomobject]@{ id = $_.id; createdDateTime = '2020-01-01T00:00:00Z'; signInActivity = [pscustomobject]@{ lastSuccessfulSignInDateTime = '2026-10-30T00:00:00Z' } } } }) }
        $R = Get-CIPPRoleAssignmentReport -TenantFilter 'contoso.com'
        $R.Errors | Should -BeNullOrEmpty
        $R.Summary.PimAvailable | Should -BeFalse
        $R.Findings.Key | Should -Contain 'StandingGA|ga'
        $R.Findings.Key | Should -Not -Contain 'StandingGA|bg'
        $R.Tasks.Count | Should -BeGreaterThan 10
        Should -Invoke New-GraphGetRequest -ParameterFilter { $uri -match 'directoryAudits' -and $uri -match "'ga'" } -Times 1
        Should -Invoke New-GraphGetRequest -ParameterFilter { $uri -match 'directoryAudits' -and $uri -match "'bg'" } -Times 0
    }

    It 'treats a missing signInActivity property as unknown, not never' {
        Mock New-GraphGetRequest {
            if ($uri -match 'roleDefinitions') { return $script:Defs }
            if ($uri -match 'roleAssignments\?') { return @([pscustomobject]@{ principalId = 'a'; roleDefinitionId = $script:AuthAdmin; directoryScopeId = '/'; principal = (& $script:User 'a') }) }
            @()
        }
        Mock New-GraphBulkRequest { @($Requests | ForEach-Object { [pscustomobject]@{ id = $_.id; status = 200; body = [pscustomobject]@{ id = $_.id } } }) }
        $R = Get-CIPPRoleAssignmentReport -TenantFilter 'contoso.com'
        $R.Summary.SignInActivityAvailable | Should -BeFalse
        $R.Findings.Key | Should -Contain 'SignInUnknown'
        $R.Findings.Key | Should -Not -Contain 'InactivePrivileged|a'
    }

    It 'marks PIM-activated assignments as time-bound and expands group-assigned roles' {
        Mock New-GraphGetRequest {
            if ($uri -match 'roleDefinitions') { return $script:Defs }
            if ($uri -match 'roleAssignmentSchedules') { return @([pscustomobject]@{ principalId = 'jit'; roleDefinitionId = $script:GA; directoryScopeId = '/'; assignmentType = 'Activated'; scheduleInfo = @{ expiration = @{ type = 'afterDateTime'; endDateTime = '2026-10-31T20:00:00Z' } } }) }
            if ($uri -match 'roleEligibilitySchedules') { return @() }
            if ($uri -match 'transitiveMembers') { return @([pscustomobject]@{ id = 'm1'; userPrincipalName = 'm1@contoso.com'; displayName = 'm1'; userType = 'Member'; accountEnabled = $true }) }
            if ($uri -match 'roleAssignments\?') {
                return @(
                    [pscustomobject]@{ principalId = 'jit'; roleDefinitionId = $script:GA; directoryScopeId = '/'; principal = (& $script:User 'jit') }
                    [pscustomobject]@{ principalId = 'grp'; roleDefinitionId = $script:Exchange; directoryScopeId = '/'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.group'; id = 'grp'; displayName = 'Exchange Admins' } }
                )
            }
            @()
        }
        Mock New-GraphBulkRequest { @() }
        $R = Get-CIPPRoleAssignmentReport -TenantFilter 'contoso.com'
        $R.Findings.Key | Should -Not -Contain 'StandingGA|jit'
        ($R.Assignments | Where-Object PrincipalId -EQ 'm1').Via | Should -Be 'Group: Exchange Admins'
    }

    It 'returns an error and no summary when role assignments cannot be read' {
        Mock New-GraphGetRequest { if ($uri -match 'roleAssignments\?') { throw 'Forbidden' } else { @() } }
        Mock New-GraphBulkRequest { @() }
        $R = Get-CIPPRoleAssignmentReport -TenantFilter 'contoso.com'
        $R.Summary | Should -BeNullOrEmpty
        $R.Errors | Should -Contain 'Active role assignments: Forbidden'
    }
}

Describe 'Get-CIPPAlertStandingPrivilegedAccess' {
    BeforeAll {
        function Get-CIPPTextReplacement { param($TenantFilter, $Text) $Text }
        function Get-CIPPRoleAssignmentReport { param($TenantFilter, $InactiveDays, $AllowedServicePrincipals) $script:LastArgs = @{ InactiveDays = $InactiveDays; Allowed = $AllowedServicePrincipals }; $script:Report }
        $script:F = { param($Key, $Sev = 'Warning', $Msg = 'm') [pscustomobject]@{ Key = $Key; Severity = $Sev; Check = 'c'; Account = 'ga@contoso.com'; Message = $Msg; Fix = 'f' } }
        function Run { param($InputValue) @(Get-CIPPAlertStandingPrivilegedAccess -TenantFilter 'contoso.com' -InputValue $InputValue | Where-Object { $_ }) }
    }
    BeforeEach { Reset-AlertStore }

    It 'notifies Error/Warning findings once each, keyed per principal, and passes the inputs through' {
        $script:Report = [pscustomobject]@{ Errors = @(); Summary = @{}; Findings = @((& $script:F 'StandingGA|ga'), (& $script:F 'InactivePrivileged|ga'), (& $script:F 'PimUnavailable' 'Info')) }
        $Out = Run -InputValue @{ StandingAccessInactiveDays = '60'; StandingAccessAllowedApps = 'CIPP-SAM, Huntress*' }
        $Out.Id | Sort-Object | Should -Be @('InactivePrivileged|ga', 'StandingGA|ga') # same account, two findings: not merged
        $script:LastArgs.InactiveDays | Should -Be 60
        $script:LastArgs.Allowed | Should -Be @('CIPP-SAM', 'Huntress*')
        $script:Report.Findings[0].Message = 'changed evidence'
        Run | Should -BeNullOrEmpty
    }

    It 'does not report when collection failed' {
        $script:Report = [pscustomobject]@{ Errors = @('Active role assignments: Forbidden'); Summary = $null; Findings = @() }
        Run | Should -BeNullOrEmpty
        $script:Logs.Message | Should -Match 'skipped reporting'
    }
}
