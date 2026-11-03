# Aspendora fork (Vikunja CIPP-56, CIPP-54): plans CIPP cannot evaluate, and RMAU and exclusion-group posture.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/BreakGlass/Test-CIPPBreakGlassPosture.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/BreakGlass/Get-CIPPBreakGlassPosture.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/CAPreflight/Test-CIPPCAPolicyUserScope.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/CAPlans/Get-CIPPConditionalAccessPlans.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/CAPlans/Get-CIPPCAPlanSummary.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/CAPlans/Get-CIPPCAPlanWarning.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPDB/Public/DBCache/Set-CIPPDBCacheConditionalAccessPlans.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertConditionalAccessPlans.ps1')

    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData) $script:Logs.Add($message) }
    function Write-AlertTrace { param($cmdletName, $tenantFilter, $data, [switch]$Append) $script:TraceCalls++; $script:Traced = $data; $data }
    function Test-CIPPStandardLicense { param($StandardName, $TenantFilter, $Preset, [switch]$SkipLog) $script:Licensed }
    function Add-CIPPDbItem { param($TenantFilter, $Type, $Data, [switch]$AddCount, [switch]$ClearOnEmpty) $script:Stored.Add([pscustomobject]@{ Type = $Type; Data = @($Data); ClearOnEmpty = [bool]$ClearOnEmpty }) }
    function Get-CIPPSimulationCache { param($TenantFilter, $Type, $Fields) if ($script:CacheThrows) { throw 'table down' }; $script:Cached }
    function Get-CIPPBreakGlassAccounts { param($TenantFilter) $script:Registered }

    # Graph fake: maps a URI regex to rows, or to a thrown error. Records the calls and whether they ran as the app.
    function New-GraphGetRequest {
        param($uri, $tenantid, $AsApp)
        $script:Uris.Add("$(if ($AsApp) { 'app ' })$uri")
        foreach ($Pattern in $script:Fake.Keys) {
            if ($uri -match $Pattern) {
                $Value = $script:Fake[$Pattern]
                if ($Value -is [string] -and $Value -eq 'THROW-DELEGATED') {
                    if (-not $AsApp) { throw 'Delegated token refused' }
                    return $script:AppResult
                }
                if ($Value -is [string] -and $Value -like 'THROW*') { throw $Value }
                return $Value
            }
        }
    }

    function Plan { param($Id, $RuleCount = 2, $Complete = $true) [pscustomobject]@{ id = $Id; displayName = "Plan $Id"; ruleCount = $RuleCount; rulesComplete = $Complete } }
    function Account {
        param($Id = 'bg1', $Restricted = $true)
        [pscustomobject]@{ Id = $Id; UserPrincipalName = "$Id@contoso.onmicrosoft.com"; Exists = $true; AccountEnabled = $true; PasswordPolicies = 'DisablePasswordExpiration'
            ActiveGlobalAdmin = $true; EligibleGlobalAdmin = $false; GroupIds = @('grp'); RoleTemplateIds = @(); Methods = @('#microsoft.graph.fido2AuthenticationMethod'); SignInActivityKnown = $false; ManagementRestricted = $Restricted }
    }
    function PostureOf { param($Extra = @{}) Test-CIPPBreakGlassPosture -Accounts @((Account 'bg1'), (Account 'bg2')) @Extra }
}

Describe 'CA plans and break-glass posture' {
    BeforeEach {
        $script:Logs = [System.Collections.Generic.List[string]]::new()
        $script:Uris = [System.Collections.Generic.List[string]]::new()
        $script:Stored = [System.Collections.Generic.List[object]]::new()
        $script:Fake = [ordered]@{}
        $script:AppResult = $null
        $script:Cached = @()
        $script:CacheThrows = $false
        $script:Licensed = $true
        $script:Traced = $null
        $script:TraceCalls = 0
        $script:Registered = @()
    }

    Describe 'Get-CIPPConditionalAccessPlans' {
        It 'reads plans on beta only, with one rules call per plan' {
            $script:Fake['plans/p1/rules$'] = @([pscustomobject]@{ id = 'r1' }, [pscustomobject]@{ id = 'r2' })
            $script:Fake['conditionalAccess/plans$'] = @([pscustomobject]@{ id = 'p1'; displayName = 'One' })
            $Plans = @(Get-CIPPConditionalAccessPlans -TenantFilter 't')
            $Plans.Count | Should -Be 1
            $Plans[0].ruleCount | Should -Be 2
            $Plans[0].rulesComplete | Should -BeTrue
            $script:Uris | ForEach-Object { $_ | Should -Match 'graph.microsoft.com/beta/' }
        }

        It 'treats an empty list as no plans' {
            $script:Fake['conditionalAccess/plans$'] = @()
            @(Get-CIPPConditionalAccessPlans -TenantFilter 't').Count | Should -Be 0
        }

        It 'retries as the app when the delegated token is refused' {
            $script:Fake['conditionalAccess/plans$'] = 'THROW-DELEGATED'
            $script:AppResult = @()
            @(Get-CIPPConditionalAccessPlans -TenantFilter 't').Count | Should -Be 0
            $script:Uris[-1] | Should -Match '^app '
        }

        It 'throws when plans cannot be read, because that is not the same as none' {
            $script:Fake['conditionalAccess/plans$'] = 'THROW 400'
            { Get-CIPPConditionalAccessPlans -TenantFilter 't' } | Should -Throw
        }

        It 'keeps the plan and falls back to the OData count when its rules cannot be read' {
            $script:Fake['plans/p1/rules$'] = 'THROW 500'
            $script:Fake['conditionalAccess/plans$'] = @([pscustomobject]@{ id = 'p1'; 'rules@odata.count' = 3 })
            $Plans = @(Get-CIPPConditionalAccessPlans -TenantFilter 't')
            $Plans[0].ruleCount | Should -Be 3
            $Plans[0].rulesComplete | Should -BeFalse
        }
    }

    Describe 'Get-CIPPCAPlanSummary and warning' {
        It 'has no warning without plans' {
            $S = Get-CIPPCAPlanSummary -Plans @()
            $S.PlanCount | Should -Be 0
            $S.Warning | Should -BeNullOrEmpty
        }

        It 'gives N plans and M rules' {
            $S = Get-CIPPCAPlanSummary -Plans @((Plan 'a' 2), (Plan 'b' 3))
            $S.PlanCount | Should -Be 2
            $S.RuleCount | Should -Be 5
            $S.Warning | Should -Match '2 Conditional Access plans and 5 rules that CIPP does not evaluate'
        }

        It 'says at least when a rules read failed, and uses the singular' {
            (Get-CIPPCAPlanSummary -Plans @(Plan 'a' 1 $false)).Warning | Should -Match '1 Conditional Access plan and at least 1 rule that'
        }

        It 'warns from the cache, and never throws when the cache fails' {
            $script:Cached = @(Plan 'a' 1)
            Get-CIPPCAPlanWarning -TenantFilter 't' | Should -Match '1 Conditional Access plan'
            $script:CacheThrows = $true
            Get-CIPPCAPlanWarning -TenantFilter 't' | Should -BeNullOrEmpty
        }
    }

    Describe 'Set-CIPPDBCacheConditionalAccessPlans' {
        It 'stores plans as an authoritative set under ConditionalAccessPlans' {
            $script:Fake['plans/p1/rules$'] = @([pscustomobject]@{ id = 'r1' })
            $script:Fake['conditionalAccess/plans$'] = @([pscustomobject]@{ id = 'p1' })
            Set-CIPPDBCacheConditionalAccessPlans -TenantFilter 't'
            $script:Stored.Count | Should -Be 1
            $script:Stored[0].Type | Should -Be 'ConditionalAccessPlans'
            $script:Stored[0].ClearOnEmpty | Should -BeTrue
            $script:Stored[0].Data[0].rules[0].id | Should -Be 'r1'
        }

        It 'records an empty set for an unlicensed tenant without calling Graph' {
            $script:Licensed = $false
            Set-CIPPDBCacheConditionalAccessPlans -TenantFilter 't'
            $script:Uris.Count | Should -Be 0
            $script:Stored[0].ClearOnEmpty | Should -BeTrue
            @($script:Stored[0].Data).Count | Should -Be 0
        }

        It 'leaves the cache alone and logs when the read fails' {
            $script:Fake['conditionalAccess/plans$'] = 'THROW 400'
            Set-CIPPDBCacheConditionalAccessPlans -TenantFilter 't'
            $script:Stored.Count | Should -Be 0
            $script:Logs[0] | Should -Match 'Failed to cache'
        }
    }

    Describe 'Get-CIPPAlertConditionalAccessPlans' {
        It 'hands one row per plan to the state-mode trace, keyed on the plan id' {
            $script:Fake['plans/p1/rules$'] = @([pscustomobject]@{ id = 'r1' })
            $script:Fake['conditionalAccess/plans$'] = @([pscustomobject]@{ id = 'p1'; displayName = 'Baseline' })
            $Out = @(Get-CIPPAlertConditionalAccessPlans -TenantFilter 't')
            $Out.Count | Should -Be 1
            $Out[0].Id | Should -Be 'Plan|p1'
            $Out[0].PSObject.Properties.Name | Should -Not -Contain 'UserPrincipalName'
        }

        It 'does not change the row Id when the rule count changes, so it cannot notify twice' {
            $script:Fake['plans/p1/rules$'] = @([pscustomobject]@{ id = 'r1' })
            $script:Fake['conditionalAccess/plans$'] = @([pscustomobject]@{ id = 'p1' })
            $First = @(Get-CIPPAlertConditionalAccessPlans -TenantFilter 't')[0].Id
            $script:Fake['plans/p1/rules$'] = @([pscustomobject]@{ id = 'r1' }, [pscustomobject]@{ id = 'r2' })
            @(Get-CIPPAlertConditionalAccessPlans -TenantFilter 't')[0].Id | Should -Be $First
        }

        It 'reconciles an empty list so a deleted plan resolves' {
            $script:Fake['conditionalAccess/plans$'] = @()
            Get-CIPPAlertConditionalAccessPlans -TenantFilter 't' | Should -BeNullOrEmpty
            $script:TraceCalls | Should -Be 1
        }

        It 'does not reconcile when the read fails, so open items are not resolved' {
            $script:Fake['conditionalAccess/plans$'] = 'THROW 400'
            Get-CIPPAlertConditionalAccessPlans -TenantFilter 't' | Should -BeNullOrEmpty
            $script:TraceCalls | Should -Be 0
            $script:Logs[0] | Should -Match 'plan check failed'
        }

        It 'skips an unlicensed tenant' {
            $script:Licensed = $false
            Get-CIPPAlertConditionalAccessPlans -TenantFilter 't' | Should -BeNullOrEmpty
            $script:Uris.Count | Should -Be 0
        }
    }

    Describe 'Test-CIPPBreakGlassPosture: plans' {
        It 'reports Error, not clean, when plans exist' {
            $F = @(PostureOf @{ PlanSummary = (Get-CIPPCAPlanSummary -Plans @(Plan 'a' 2)) })
            $F.Count | Should -Be 1
            $F[0].Key | Should -Be 'Plans|present'
            $F[0].Severity | Should -Be 'Error'
            $F[0].Message | Should -Match 'does not evaluate'
        }

        It 'is clean when the tenant has no plans' {
            PostureOf @{ PlanSummary = (Get-CIPPCAPlanSummary -Plans @()) } | Should -BeNullOrEmpty
        }

        It 'reports only Info when the beta read failed, so it cannot page' {
            $F = @(PostureOf @{ PlansUnknown = $true })
            $F[0].Key | Should -Be 'PlansUnknown'
            $F[0].Severity | Should -Be 'Info'
        }
    }

    Describe 'Test-CIPPBreakGlassPosture: management restriction' {
        It 'is Info when the account is unprotected, and treats null as false' {
            $F = @(Test-CIPPBreakGlassPosture -Accounts @((Account 'bg1' $null), (Account 'bg2')))
            $F.Key | Should -Be @('NotRestricted|bg1')
            $F[0].Severity | Should -Be 'Info'
        }

        It 'warns on a standing scoped admin of a unit holding a break-glass account' {
            $U = [pscustomobject]@{ Id = 'u1'; DisplayName = 'Sealed'; Members = @([pscustomobject]@{ id = 'bg1' }); ScopedAdmins = @([pscustomobject]@{ id = 'sr1'; roleMemberInfo = @{ id = 'adm'; displayName = 'Some Admin' } }) }
            $F = @(PostureOf @{ RestrictedUnits = @($U) })
            $F.Key | Should -Be @('RmauAdmin|u1|sr1')
            $F[0].Severity | Should -Be 'Warning'
            $F[0].Account | Should -Be 'Some Admin'
        }

        It 'warns on an unexpected member, and accepts the accounts and the exclusion group' {
            $Group = [pscustomobject]@{ Id = 'grp'; DisplayName = 'G'; Members = @([pscustomobject]@{ id = 'bg1' }, [pscustomobject]@{ id = 'bg2' }) }
            $U = [pscustomobject]@{ Id = 'u1'; DisplayName = 'Sealed'; ScopedAdmins = @(); Members = @([pscustomobject]@{ id = 'bg1' }, [pscustomobject]@{ id = 'grp' }, [pscustomobject]@{ id = 'x'; userPrincipalName = 'x@contoso.com' }) }
            $F = @(PostureOf @{ RestrictedUnits = @($U); ExclusionGroups = @($Group) })
            $F.Key | Should -Be @('RmauMember|u1|x')
            $F[0].Severity | Should -Be 'Warning'
        }

        It 'ignores a restricted unit unrelated to break-glass' {
            $U = [pscustomobject]@{ Id = 'hr'; DisplayName = 'HR'; Members = @([pscustomobject]@{ id = 'x' }); ScopedAdmins = @([pscustomobject]@{ id = 'sr1'; roleMemberInfo = @{ id = 'adm' } }) }
            PostureOf @{ RestrictedUnits = @($U) } | Should -BeNullOrEmpty
        }

        It 'reports only Info when the units could not be read' {
            (@(PostureOf @{ RestrictedUnitsUnknown = $true })[0]).Key | Should -Be 'RmauUnknown'
            (@(PostureOf @{ RestrictedUnitsUnknown = $true })[0]).Severity | Should -Be 'Info'
        }
    }

    Describe 'Test-CIPPBreakGlassPosture: exclusion group membership' {
        It 'is clean when the group holds only registered accounts' {
            $Group = [pscustomobject]@{ Id = 'grp'; DisplayName = 'G'; Members = @([pscustomobject]@{ id = 'bg1' }, [pscustomobject]@{ id = 'bg2' }) }
            PostureOf @{ ExclusionGroups = @($Group) } | Should -BeNullOrEmpty
        }

        It 'errors once per extra member, with a stable key and the member named' {
            $Group = [pscustomobject]@{ Id = 'grp'; DisplayName = 'CA Exclusion'; Members = @([pscustomobject]@{ id = 'bg1' }, [pscustomobject]@{ id = 'ann'; userPrincipalName = 'ann@contoso.com' }, [pscustomobject]@{ id = 'svc'; displayName = 'Some App' }) }
            $F = @(PostureOf @{ ExclusionGroups = @($Group) })
            @($F.Key | Sort-Object) | Should -Be @('ExclusionGroupMember|grp|ann', 'ExclusionGroupMember|grp|svc')
            ($F | ForEach-Object Severity | Select-Object -Unique) | Should -Be 'Error'
            @($F.Account | Sort-Object) | Should -Be @('ann@contoso.com', 'Some App')
        }
    }

    Describe 'Get-CIPPBreakGlassPosture collection' {
        BeforeEach {
            $script:Registered = @([pscustomobject]@{ RowKey = 'bg1'; UserPrincipalName = 'bg1@contoso.onmicrosoft.com' })
            $script:Fake['/users/bg1/transitiveMemberOf'] = @([pscustomobject]@{ id = 'grp'; '@odata.type' = '#microsoft.graph.group' }, [pscustomobject]@{ id = 'other'; '@odata.type' = '#microsoft.graph.group' })
            $script:Fake['/users/bg1/authentication/methods'] = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.fido2AuthenticationMethod' })
            $script:Fake['/users/bg1\?'] = [pscustomobject]@{ id = 'bg1'; userPrincipalName = 'bg1@contoso.onmicrosoft.com'; accountEnabled = $true; passwordPolicies = 'DisablePasswordExpiration'; isManagementRestricted = $true }
            $script:Fake['roleAssignmentScheduleInstances'] = @([pscustomobject]@{ roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; directoryScopeId = '/'; assignmentType = 'Assigned' })
            $script:Fake['roleEligibilitySchedules'] = @()
            $script:Fake['/domains/'] = [pscustomobject]@{ passwordValidityPeriodInDays = 2147483647 }
            $script:Fake['conditionalAccess/policies'] = @([pscustomobject]@{ id = 'p1'; state = 'enabled'; displayName = 'P1'; conditions = @{ users = @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @('grp'); includeRoles = @(); excludeRoles = @() } } })
            $script:Fake['conditionalAccess/plans$'] = @()
            $script:Fake['/groups/grp/transitiveMembers'] = @([pscustomobject]@{ id = 'bg1' })
            $script:Fake['/groups/grp\?'] = [pscustomobject]@{ id = 'grp'; displayName = 'CA Exclusion' }
            $script:Fake['administrativeUnits/u1/members'] = @([pscustomobject]@{ id = 'bg1' })
            $script:Fake['administrativeUnits/u1/scopedRoleMembers'] = @()
            $script:Fake['directory/administrativeUnits\?'] = @([pscustomobject]@{ id = 'u1'; displayName = 'Sealed'; isMemberManagementRestricted = $true }, [pscustomobject]@{ id = 'u2'; displayName = 'Plain'; isMemberManagementRestricted = $null })
        }

        It 'only reads the group a policy excludes, and only the restricted unit' {
            $R = Get-CIPPBreakGlassPosture -TenantFilter 't'
            @($R.Errors).Count | Should -Be 0
            $script:Uris | Should -Not -Contain 'https://graph.microsoft.com/v1.0/groups/other/transitiveMembers?$select=id,displayName,userPrincipalName&$top=999'
            @($script:Uris | Where-Object { $_ -match 'administrativeUnits/u2' }).Count | Should -Be 0
            $R.Accounts[0].ManagementRestricted | Should -BeTrue
            @($R.Findings.Key) | Should -Not -Contain 'NotRestricted|bg1'
        }

        It 'asks for isManagementRestricted' {
            $null = Get-CIPPBreakGlassPosture -TenantFilter 't'
            @($script:Uris | Where-Object { $_ -match '/users/bg1\?.*isManagementRestricted' }).Count | Should -BeGreaterThan 0
        }

        It 'reports the plan error and warning when a plan exists' {
            $script:Fake.Insert(0, 'plans/p1/rules$', @([pscustomobject]@{ id = 'r1' }))
            $script:Fake['conditionalAccess/plans$'] = @([pscustomobject]@{ id = 'p1' })
            $R = Get-CIPPBreakGlassPosture -TenantFilter 't'
            @($R.Findings.Key) | Should -Contain 'Plans|present'
            $R.PlanWarning | Should -Match '1 Conditional Access plan and 1 rule'
        }

        It 'does not block the report when the beta plan read fails' {
            $script:Fake['conditionalAccess/plans$'] = 'THROW 400'
            $R = Get-CIPPBreakGlassPosture -TenantFilter 't'
            @($R.Errors).Count | Should -Be 0
            @($R.Findings.Key) | Should -Contain 'PlansUnknown'
        }

        It 'does not block the report when the units cannot be read' {
            $script:Fake['directory/administrativeUnits\?'] = 'THROW 403'
            $R = Get-CIPPBreakGlassPosture -TenantFilter 't'
            @($R.Errors).Count | Should -Be 0
            @($R.Findings.Key) | Should -Contain 'RmauUnknown'
        }

        It 'adds to Errors when the exclusion group cannot be read, because that blocks a false clear' {
            $script:Fake['/groups/grp/transitiveMembers'] = 'THROW 500'
            $R = Get-CIPPBreakGlassPosture -TenantFilter 't'
            @($R.Errors) -join ';' | Should -Match 'exclusion group grp'
        }
    }
}
