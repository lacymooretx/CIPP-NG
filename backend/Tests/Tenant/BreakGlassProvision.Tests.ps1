# Aspendora fork (onboarding Phase 3, 2026-11-12): break-glass provisioning helpers and admin inventory rendering.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $BG = Join-Path $RepoRoot 'Modules/CIPPCore/Public/BreakGlass'
    foreach ($F in 'New-CIPPBreakGlassAccountName', 'New-CIPPBreakGlassPassword', 'New-CIPPBreakGlassCAPatch', 'Test-CIPPBreakGlassCAReadback', 'ConvertTo-CIPPAdminInventoryHtml', 'Get-CIPPBreakGlassProvisionPlan') {
        . (Join-Path $BG "$F.ps1")
    }
    function Pol {
        param($Id = 'p1', $ExGroups = @(), $ExUsers = @('u9'), $State = 'enabled')
        [pscustomobject]@{ id = $Id; displayName = "Policy $Id"; state = $State
            grantControls = [pscustomobject]@{ operator = 'OR'; builtInControls = @('mfa') }; sessionControls = $null
            conditions = [pscustomobject]@{ clientAppTypes = @('all'); applications = [pscustomobject]@{ includeApplications = @('All') }
                users = [pscustomobject]@{ includeUsers = @('All'); excludeUsers = $ExUsers; includeGroups = @(); excludeGroups = $ExGroups; includeRoles = @(); excludeRoles = @(); excludeGuestsOrExternalUsers = $null } } }
    }
    # Stubs for the plan's dependencies; each test mocks what it needs.
    function Get-Tenants { param($TenantFilter, [switch]$SkipList, [switch]$IncludeAll) }
    function Test-CIPPTenantManaged { param($TenantFilter) }
    function Get-CIPPBreakGlassAccounts { param($TenantFilter) }
    function New-GraphGetRequest { param($uri, $tenantid, $ErrorAction) }
    function Get-CIPPCAPlanSummary { param($Plans) [pscustomobject]@{ PlanCount = 0 } }
    function Get-CIPPConditionalAccessPlans { param($TenantFilter) @() }
}

Describe 'New-CIPPBreakGlassAccountName' {
    It 'proposes distinct bg- names on the onmicrosoft domain' {
        $N = New-CIPPBreakGlassAccountName -InitialDomain 'Contoso.onmicrosoft.com' -Count 2
        $N.Count | Should -Be 2
        $N | ForEach-Object { $_ | Should -Match '^bg-[a-z0-9]{8}@contoso\.onmicrosoft\.com$' }
        $N[0] | Should -Not -Be $N[1]
    }
    It 'refuses a custom domain' {
        { New-CIPPBreakGlassAccountName -InitialDomain 'contoso.com' } | Should -Throw '*onmicrosoft.com*'
    }
}

Describe 'New-CIPPBreakGlassPassword' {
    It 'is 64 characters with every class and no percent, quote or backslash' {
        1..20 | ForEach-Object {
            $P = New-CIPPBreakGlassPassword
            $P.Length | Should -Be 64
            $P | Should -MatchExactly '[A-Z]'; $P | Should -MatchExactly '[a-z]'; $P | Should -Match '[0-9]'; $P | Should -Match '[!#$*+\-.:=?@^_~]'
            $P | Should -Not -Match '[%"\\'']'
        }
    }
}

Describe 'New-CIPPBreakGlassCAPatch' {
    It 'returns null when the group is already excluded' {
        New-CIPPBreakGlassCAPatch -Policy (Pol -ExGroups @('g1')) -GroupId 'g1' | Should -BeNullOrEmpty
    }
    It 're-sends the whole users block and only adds the group' {
        $B = New-CIPPBreakGlassCAPatch -Policy (Pol -ExGroups @('g0')) -GroupId 'g1'
        $U = $B.conditions.users
        $U.excludeGroups | Should -Be @('g0', 'g1')
        $U.includeUsers | Should -Be @('All')
        $U.excludeUsers | Should -Be @('u9')
        $U.PSObject.Properties.Name | Should -Contain 'includeRoles'
        $U.PSObject.Properties.Name | Should -Not -Contain 'excludeGuestsOrExternalUsers'
        $B.PSObject.Properties.Name | Should -Be @('conditions')
    }
}

Describe 'Test-CIPPBreakGlassCAReadback' {
    It 'passes when only the group was added' {
        $After = Pol -ExGroups @('g0', 'g1')
        (Test-CIPPBreakGlassCAReadback -Before (Pol -ExGroups @('g0')) -After $After -GroupId 'g1').Ok | Should -BeTrue
    }
    It 'fails when the group is missing, a list was wiped or the state changed' {
        (Test-CIPPBreakGlassCAReadback -Before (Pol) -After (Pol) -GroupId 'g1').Problems | Should -Contain 'the break-glass group is not in excludeGroups after the update'
        $R = Test-CIPPBreakGlassCAReadback -Before (Pol) -After (Pol -ExGroups @('g1') -ExUsers @() -State 'disabled') -GroupId 'g1'
        $R.Ok | Should -BeFalse
        $R.Problems | Should -Contain 'excludeUsers changed'
        ($R.Problems -join ' ') | Should -Match 'state changed'
    }
    It 'fails when grant controls changed' {
        $After = Pol -ExGroups @('g1'); $After.grantControls.builtInControls = @('block')
        (Test-CIPPBreakGlassCAReadback -Before (Pol) -After $After -GroupId 'g1').Problems | Should -Contain 'grantControls changed'
    }
}

Describe 'Get-CIPPBreakGlassProvisionPlan gates' {
    BeforeEach {
        $env:TenantID = 'partner-id'
        Mock Get-Tenants { if ($SkipList) { @() } else { [pscustomobject]@{ customerId = 'T1'; defaultDomainName = 'contoso.com'; displayName = 'Contoso' } } }
        Mock Test-CIPPTenantManaged { [pscustomobject]@{ Status = 'Managed'; IsManaged = $true } }
        Mock Get-CIPPBreakGlassAccounts { @() }
        Mock New-GraphGetRequest {
            switch -Wildcard ($uri) {
                '*domains*' { @([pscustomobject]@{ id = 'contoso.onmicrosoft.com'; isInitial = $true }) }
                '*/users?*' { @() }
                '*/groups?*' { @() }
                '*conditionalAccess/policies*' { @((Pol 'p1'), (Pol 'p2')) }
                '*authenticationMethodConfigurations*' { [pscustomobject]@{ state = 'enabled' } }
            }
        }
    }
    It 'is Ready with 2 accounts, a new group and every policy to edit' {
        $P = Get-CIPPBreakGlassProvisionPlan -TenantFilter 'contoso.com'
        $P.Status | Should -Be 'Ready'
        $P.AccountsToCreate.Count | Should -Be 2
        $P.GroupAction | Should -Be 'Create'
        $P.PolicyEdits.Id | Should -Be @('p1', 'p2')
    }
    It 'blocks an unmanaged tenant without reading Graph' {
        Mock Test-CIPPTenantManaged { [pscustomobject]@{ Status = 'Unmanaged'; IsManaged = $false } }
        (Get-CIPPBreakGlassProvisionPlan -TenantFilter 'contoso.com').Status | Should -Be 'Blocked'
        Should -Invoke New-GraphGetRequest -Times 0
    }
    It 'blocks a tenant on the CIPP exclusion list' {
        Mock Get-Tenants { [pscustomobject]@{ customerId = 'T1'; defaultDomainName = 'contoso.com'; displayName = 'Contoso' } }
        $P = Get-CIPPBreakGlassProvisionPlan -TenantFilter 'contoso.com'
        $P.Status | Should -Be 'Blocked'
        $P.Reasons | Should -Match 'exclusion list'
    }
    It 'is NotNeeded with 2 registered accounts' {
        Mock Get-CIPPBreakGlassAccounts { @([pscustomobject]@{ UserPrincipalName = 'a' }, [pscustomobject]@{ UserPrincipalName = 'b' }) }
        (Get-CIPPBreakGlassProvisionPlan -TenantFilter 'contoso.com').Status | Should -Be 'NotNeeded'
    }
    It 'plans only the missing account when one is registered' {
        Mock Get-CIPPBreakGlassAccounts { @([pscustomobject]@{ UserPrincipalName = 'a' }) }
        (Get-CIPPBreakGlassProvisionPlan -TenantFilter 'contoso.com').AccountsToCreate.Count | Should -Be 1
    }
    It 'blocks when a same-named group is not role-assignable' {
        Mock New-GraphGetRequest {
            switch -Wildcard ($uri) {
                '*domains*' { @([pscustomobject]@{ id = 'contoso.onmicrosoft.com'; isInitial = $true }) }
                '*/groups?*' { @([pscustomobject]@{ id = 'g9'; isAssignableToRole = $false; securityEnabled = $true }) }
                default { @() }
            }
        }
        $P = Get-CIPPBreakGlassProvisionPlan -TenantFilter 'contoso.com'
        $P.Status | Should -Be 'Blocked'
        $P.Reasons | Should -Match 'role-assignable'
    }
    It 'skips policies that already exclude an existing group' {
        Mock New-GraphGetRequest {
            switch -Wildcard ($uri) {
                '*domains*' { @([pscustomobject]@{ id = 'contoso.onmicrosoft.com'; isInitial = $true }) }
                '*/groups?*' { @([pscustomobject]@{ id = 'g1'; isAssignableToRole = $true; securityEnabled = $true }) }
                '*conditionalAccess/policies*' { @((Pol 'p1' -ExGroups @('g1')), (Pol 'p2')) }
                '*authenticationMethodConfigurations*' { [pscustomobject]@{ state = 'enabled' } }
                default { @() }
            }
        }
        $P = Get-CIPPBreakGlassProvisionPlan -TenantFilter 'contoso.com'
        $P.GroupAction | Should -Be 'UseExisting'
        $P.PolicyEdits.Id | Should -Be @('p2')
        $P.PoliciesAlreadyExcluded | Should -Be @('Policy p1')
    }
}

Describe 'ConvertTo-CIPPAdminInventoryHtml' {
    It 'renders flags, break-glass and Central time without secrets' {
        $Inv = [pscustomobject]@{ Tenant = 'contoso.com'; GeneratedUtc = '2026-11-12T18:00:00Z'; Notes = @()
            Admins = @(
                [pscustomobject]@{ Name = 'Admin <x>'; UserPrincipalName = 'a@contoso.com'; Type = 'user'; Enabled = $true; BreakGlass = $false; Roles = 'Global Administrator'; MFA = $true; PhishResistant = $false; Methods = 'microsoftAuthenticator, password'; Flags = @('PermanentGA', 'NotPhishResistant') },
                [pscustomobject]@{ Name = 'BG'; UserPrincipalName = 'bg-x@contoso.onmicrosoft.com'; Type = 'user'; Enabled = $true; BreakGlass = $true; Roles = 'Global Administrator'; MFA = $null; PhishResistant = $null; Methods = 'unreadable'; Flags = @() }) }
        $H = ConvertTo-CIPPAdminInventoryHtml -Inventory $Inv -ClientName 'Contoso'
        $H | Should -Match '2026-11-12 12:00 CST'
        $H | Should -Match 'Permanent Global Admin \(not break-glass\)'
        $H | Should -Match '<b>break-glass</b>'
        $H | Should -Match 'Admin &lt;x&gt;'
        $H | Should -Match '<b>1</b> registered break-glass'
    }
}
