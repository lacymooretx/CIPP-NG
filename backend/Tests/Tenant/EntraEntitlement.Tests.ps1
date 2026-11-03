# Aspendora fork (Vikunja CIPP-47): Entra ID P1/P2 seats vs Conditional Access scope - rules, collector, alert and test.
# SKU, plan and policy shapes copied from live reads (3endt.com, imtecservices.com, 2026-11-02).

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Tests/Alerts/AlertLifecycleHarness.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/CAPreflight/Test-CIPPCAPolicyUserScope.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/EntraEntitlement/Test-CIPPEntraEntitlement.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/EntraEntitlement/Get-CIPPEntraEntitlement.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/EntraEntitlement/Save-CIPPEntraEntitlementSummary.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertEntraEntitlementGap.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPTests/Public/Tests/GenericTests/Identity/Invoke-CippTestGenericTestEntraEntitlement.ps1')

    $script:P1 = '41781fb2-bc02-4b7c-bd55-b576c07bb09d'
    $script:P2 = 'eec0eb4f-6444-4f95-aba0-50c24d67f998'

    function New-Sku {
        param($Name, [string[]]$Plans, [int]$Enabled, [int]$Suspended = 0, $Status = 'Enabled', $Provisioning = 'Success', $AppliesTo = 'User')
        [pscustomobject]@{
            skuPartNumber = $Name; appliesTo = $AppliesTo; capabilityStatus = $Status; consumedUnits = $Enabled
            prepaidUnits = [pscustomobject]@{ enabled = $Enabled; suspended = $Suspended; warning = 0; lockedOut = 0 }
            servicePlans = @($Plans | ForEach-Object { [pscustomobject]@{ servicePlanId = $_; provisioningStatus = $Provisioning } })
        }
    }
    function New-TestUser {
        param($Id, [string[]]$Plans = @(), $Enabled = $true, $Type = 'Member', $PlanStatus = 'Enabled')
        [pscustomobject]@{
            id = $Id; userPrincipalName = "$Id@contoso.com"; displayName = $Id; accountEnabled = $Enabled; userType = $Type
            assignedPlans = @($Plans | ForEach-Object { [pscustomobject]@{ servicePlanId = $_; capabilityStatus = $PlanStatus } })
        }
    }
    function New-CaPolicy {
        param($Name = 'p', $State = 'enabled', [string[]]$Include = @('All'), [string[]]$Exclude = @(), [string[]]$IncGroups = @(), [string[]]$ExcGroups = @(), [string[]]$IncRoles = @(), [string[]]$SignInRisk = @(), [string[]]$UserRisk = @())
        [pscustomobject]@{
            displayName = $Name; state = $State
            conditions = [pscustomobject]@{
                signInRiskLevels = $SignInRisk; userRiskLevels = $UserRisk
                users = [pscustomobject]@{ includeUsers = $Include; excludeUsers = $Exclude; includeGroups = $IncGroups; excludeGroups = $ExcGroups; includeRoles = $IncRoles; excludeRoles = @() }
            }
        }
    }
}

Describe 'Test-CIPPEntraEntitlement pools' {
    It 'counts by service plan across SKUs, and P2 seats count as P1' {
        $R = Test-CIPPEntraEntitlement -Skus @((New-Sku 'SPB' @($P1) 47), (New-Sku 'SPE_F1' @($P1) 1), (New-Sku 'E5' @($P1, $P2) 3))
        $R.Summary.P1Pool | Should -Be 51
        $R.Summary.P2Pool | Should -Be 3
    }

    It 'adds nothing for suspended SKUs, as with the 3E trials' {
        $R = Test-CIPPEntraEntitlement -Skus @((New-Sku 'IDENTITY_THREAT_PROTECTION' @($P2) 0 -Suspended 1 -Status 'Suspended' -Provisioning 'Disabled'), (New-Sku 'AAD_PREMIUM' @($P1) 0 -Suspended 1 -Status 'Suspended'))
        $R.Summary.P1Pool | Should -Be 0
        $R.Summary.P2Pool | Should -Be 0
    }

    It 'ignores SKUs without the plans and SKUs for companies' {
        $R = Test-CIPPEntraEntitlement -Skus @((New-Sku 'OTHER' @('11111111-1111-1111-1111-111111111111') 50), (New-Sku 'WORKLOAD' @($P1) 9 -AppliesTo 'Company'))
        $R.Summary.P1Pool | Should -Be 0
        @($R.Skus).Count | Should -Be 0
    }
}

Describe 'Test-CIPPEntraEntitlement scope' {
    It 'reports no shortfall when seats cover everyone, with no Warning' {
        $R = Test-CIPPEntraEntitlement -Skus @((New-Sku 'SPB' @($P1) 2)) -Users @((New-TestUser 'a' @($P1)), (New-TestUser 'b' @($P1))) -Policies @((New-CaPolicy))
        $R.Summary.P1InScope | Should -Be 2
        $R.Summary.CoveredP1 | Should -BeTrue
        @($R.Findings | Where-Object Severity -EQ 'Warning').Count | Should -Be 0
    }

    It 'raises P1Shortfall when the pool is smaller than the users in scope' {
        $R = Test-CIPPEntraEntitlement -Skus @((New-Sku 'SPB' @($P1) 1)) -Users @((New-TestUser 'a' @($P1)), (New-TestUser 'b')) -Policies @((New-CaPolicy))
        $R.Summary.P1Shortfall | Should -Be 1
        ($R.Findings | Where-Object Key -EQ 'P1Shortfall').Severity | Should -Be 'Warning'
    }

    It 'names the risk policy and the suspended SKU in P2Shortfall' {
        $Skus = @((New-Sku 'SPB' @($P1) 1), (New-Sku 'ITP' @($P2) 0 -Suspended 1 -Status 'Suspended' -Provisioning 'Disabled'))
        $R = Test-CIPPEntraEntitlement -Skus $Skus -Users @((New-TestUser 'a' @($P1))) -Policies @((New-CaPolicy -Name 'Sign-In Risk' -SignInRisk @('high')))
        $R.Summary.P2InScope | Should -Be 1
        $Finding = $R.Findings | Where-Object Key -EQ 'P2Shortfall'
        $Finding.Severity | Should -Be 'Warning'
        $Finding.Message | Should -Match 'Sign-In Risk'
        $Finding.Message | Should -Match 'ITP'
    }

    It 'treats a user-risk policy as P2 too' {
        $R = Test-CIPPEntraEntitlement -Users @((New-TestUser 'a')) -Policies @((New-CaPolicy -UserRisk @('high')))
        $R.Summary.P2InScope | Should -Be 1
    }

    It 'makes per-user gaps Info only when the pool is big enough' {
        $R = Test-CIPPEntraEntitlement -Skus @((New-Sku 'SPB' @($P1) 5)) -Users @((New-TestUser 'a'), (New-TestUser 'b' @($P1))) -Policies @((New-CaPolicy))
        $R.Summary.P1UserGaps | Should -Be 1
        $Finding = $R.Findings | Where-Object Key -EQ 'P1UserGaps'
        $Finding.Severity | Should -Be 'Info'
        $Finding.Message | Should -Match 'a@contoso.com'
    }

    It 'counts a user holding a P2 plan as holding P1' {
        $R = Test-CIPPEntraEntitlement -Skus @((New-Sku 'P2' @($P2) 1)) -Users @((New-TestUser 'a' @($P2))) -Policies @((New-CaPolicy))
        $R.Summary.P1UserGaps | Should -Be 0
    }

    It 'does not count a suspended plan on the user' {
        $R = Test-CIPPEntraEntitlement -Skus @((New-Sku 'SPB' @($P1) 1)) -Users @((New-TestUser 'a' @($P1) -PlanStatus 'Suspended')) -Policies @((New-CaPolicy))
        $R.Summary.P1UserGaps | Should -Be 1
    }

    It 'skips disabled accounts and honours direct exclusions' {
        $R = Test-CIPPEntraEntitlement -Users @((New-TestUser 'a'), (New-TestUser 'off' -Enabled $false), (New-TestUser 'bg')) -Policies @((New-CaPolicy -Exclude @('bg')))
        $R.Summary.P1InScope | Should -Be 1
        $R.Summary.EnabledMembers | Should -Be 2
    }

    It 'resolves included and excluded groups and roles' {
        $Policies = @((New-CaPolicy -Include @() -IncGroups @('g1')), (New-CaPolicy -Include @() -IncRoles @('r1')))
        $R = Test-CIPPEntraEntitlement -Users @((New-TestUser 'ingroup'), (New-TestUser 'inrole'), (New-TestUser 'neither')) -Policies $Policies -GroupMembers @{ g1 = @('ingroup') } -RoleMembers @{ r1 = @('inrole') }
        @($R.Users | Where-Object InP1Scope | ForEach-Object Id | Sort-Object) | Should -Be @('ingroup', 'inrole')

        $Excluded = Test-CIPPEntraEntitlement -Users @((New-TestUser 'a'), (New-TestUser 'b')) -Policies @((New-CaPolicy -ExcGroups @('g1'))) -GroupMembers @{ g1 = @('b') }
        $Excluded.Summary.P1InScope | Should -Be 1
    }

    It 'leaves report-only policies out of the shortfall and reports them separately' {
        $R = Test-CIPPEntraEntitlement -Skus @((New-Sku 'SPB' @($P1) 1)) -Users @((New-TestUser 'a'), (New-TestUser 'b')) -Policies @((New-CaPolicy -State 'enabledForReportingButNotEnforced'))
        $R.Summary.P1InScope | Should -Be 0
        $R.Summary.P1Shortfall | Should -Be 0
        $R.Summary.P1InScopeWithReportOnly | Should -Be 2
        ($R.Findings | Where-Object Key -EQ 'P1ReportOnlyShortfall').Severity | Should -Be 'Info'
    }

    It 'ignores disabled policies and workload-identity policies with no user assignment' {
        $Workload = [pscustomobject]@{ displayName = 'w'; state = 'enabled'; conditions = [pscustomobject]@{ users = $null; signInRiskLevels = @(); userRiskLevels = @() } }
        $R = Test-CIPPEntraEntitlement -Users @((New-TestUser 'a')) -Policies @((New-CaPolicy -State 'disabled'), $Workload)
        $R.Summary.P1InScope | Should -Be 0
        $R.Summary.P1InScopeWithReportOnly | Should -Be 0
    }

    It 'reports guests but never counts them against the pools' {
        $R = Test-CIPPEntraEntitlement -Users @((New-TestUser 'g' -Type 'Guest')) -Policies @((New-CaPolicy))
        $R.Summary.P1InScope | Should -Be 0
        $R.Summary.GuestsInScope | Should -Be 1
        ($R.Findings | Where-Object Key -EQ 'GuestsInScope').Severity | Should -Be 'Info'
    }

    It 'leaves shared and resource mailbox accounts out and reports them' {
        $R = Test-CIPPEntraEntitlement -Users @((New-TestUser 'a'), (New-TestUser 'shared')) -Policies @((New-CaPolicy)) -NonPersonIds @('shared')
        $R.Summary.P1InScope | Should -Be 1
        $R.Summary.NonPersonExcluded | Should -Be 1
    }

    It 'lists accounts up to the limit, then says how many more' {
        $R = Test-CIPPEntraEntitlement -Users @((New-TestUser 'a'), (New-TestUser 'b'), (New-TestUser 'c')) -Policies @((New-CaPolicy)) -ListLimit 1
        ($R.Findings | Where-Object Key -EQ 'P1UserGaps').Message | Should -Match 'and 2 more'
    }
}

Describe 'Get-CIPPEntraEntitlement' {
    BeforeAll {
        function Get-CippException { param($Exception) [pscustomobject]@{ NormalizedError = "$Exception" } }
        function New-CIPPDbRequest { param($TenantFilter, $Type) $script:Mailboxes }
        function New-GraphGetRequest {
            param($uri, $tenantid, $AsApp, [switch]$NoAuthCheck)
            $script:Calls += , $uri
            foreach ($Key in @($script:Graph.Keys)) {
                if ($uri -like "*$Key*") {
                    $Value = $script:Graph[$Key]
                    if ($Value -is [string] -and $Value -like 'THROW:*') { throw $Value.Substring(6) }
                    return $Value
                }
            }
            return @()
        }
    }
    BeforeEach {
        $script:Calls = @()
        $script:Mailboxes = @([pscustomobject]@{ recipientTypeDetails = 'SharedMailbox'; ExternalDirectoryObjectId = 'shared' })
        $script:Graph = [ordered]@{
            'subscribedSkus'             = @(New-Sku 'SPB' @($P1) 5)
            'v1.0/users'                 = @((New-TestUser 'a' @($P1)), (New-TestUser 'shared'))
            'conditionalAccess/policies' = @(New-CaPolicy)
        }
    }

    It 'collects, leaves shared mailboxes out and evaluates' {
        $R = Get-CIPPEntraEntitlement -TenantFilter 'contoso.com'
        $R.Errors | Should -BeNullOrEmpty
        $R.Summary.P1InScope | Should -Be 1
        $R.Summary.NonPersonExcluded | Should -Be 1
    }

    It 'returns Errors and no Summary when a read fails, rather than a clean result' {
        $script:Graph['conditionalAccess/policies'] = 'THROW:denied'
        $R = Get-CIPPEntraEntitlement -TenantFilter 'contoso.com'
        $R.Summary | Should -BeNullOrEmpty
        @($R.Errors).Count | Should -Be 1
        $R.Errors[0] | Should -Match 'Conditional Access'
    }

    It 'expands only referenced groups, and treats a deleted group as empty with a note' {
        $script:Graph['conditionalAccess/policies'] = @(New-CaPolicy -Include @() -IncGroups @('11111111-1111-1111-1111-111111111111'))
        $script:Graph['groups/11111111'] = 'THROW:Request_ResourceNotFound'
        $R = Get-CIPPEntraEntitlement -TenantFilter 'contoso.com'
        $R.Errors | Should -BeNullOrEmpty
        ($R.Notes -join ' ') | Should -Match 'no longer exists'
        $R.Summary.P1InScope | Should -Be 0
    }

    It 'expands role-assignable groups and never uses expand=principal' {
        $Role = '62e90394-69f5-4237-9190-012177145e10'
        $script:Graph['conditionalAccess/policies'] = @(New-CaPolicy -Include @() -IncRoles @($Role))
        $script:Graph['roleAssignments'] = @(
            [pscustomobject]@{ principalId = 'a'; roleDefinitionId = $Role; directoryScopeId = '/' }
            [pscustomobject]@{ principalId = 'rolegroup'; roleDefinitionId = $Role; directoryScopeId = '/' }
        )
        $script:Graph['groups/rolegroup'] = @([pscustomobject]@{ id = 'viagroup' })
        $script:Graph['v1.0/users'] = @((New-TestUser 'a' @($P1)), (New-TestUser 'viagroup' @($P1)))
        $R = Get-CIPPEntraEntitlement -TenantFilter 'contoso.com'
        $R.Summary.P1InScope | Should -Be 2
        (@($script:Calls) -join ' ') | Should -Not -Match 'expand'
    }

    It 'keeps working when PIM eligibility cannot be read (no P2)' {
        $Role = '62e90394-69f5-4237-9190-012177145e10'
        $script:Graph['conditionalAccess/policies'] = @(New-CaPolicy -Include @() -IncRoles @($Role))
        $script:Graph['roleAssignments'] = @([pscustomobject]@{ principalId = 'a'; roleDefinitionId = $Role; directoryScopeId = '/' })
        $script:Graph['roleEligibilitySchedules'] = 'THROW:needs P2'
        $R = Get-CIPPEntraEntitlement -TenantFilter 'contoso.com'
        $R.Errors | Should -BeNullOrEmpty
        $R.Summary.P1InScope | Should -Be 1
    }

    It 'notes when there is no mailbox cache' {
        $script:Mailboxes = @()
        $R = Get-CIPPEntraEntitlement -TenantFilter 'contoso.com'
        ($R.Notes -join ' ') | Should -Match 'counted as people'
        $R.Summary.P1InScope | Should -Be 2
    }
}

Describe 'Get-CIPPAlertEntraEntitlementGap' {
    BeforeAll {
        function Get-CIPPEntraEntitlement { param($TenantFilter) $script:Report }
        function Get-CippException { param($Exception) [pscustomobject]@{ NormalizedError = "$Exception" } }
        function Get-CIPPAlertFailureSeverity { param($ErrorText) 'Error' }
        function Invoke-Alert { @(Get-CIPPAlertEntraEntitlementGap -TenantFilter 'contoso.com' | Where-Object { $_ }) }
        function Set-Report {
            param([object[]]$Findings = @(), [string[]]$Errors = @(), [int]$Short = 0)
            $script:Report = [pscustomobject]@{
                Errors = $Errors; Findings = $Findings
                Summary = if ($Errors.Count -gt 0) { $null } else { [pscustomobject]@{ CoveredP1 = $Short -eq 0; CoveredP2 = $true; P1Pool = 1; P1Shortfall = $Short } }
            }
        }
        $script:Short = [pscustomobject]@{ Key = 'P1Shortfall'; Severity = 'Warning'; Check = 'P1'; Account = ''; Message = '3 short'; Fix = 'buy' }
        $script:Short2 = [pscustomobject]@{ Key = 'P1Shortfall'; Severity = 'Warning'; Check = 'P1'; Account = ''; Message = '4 short'; Fix = 'buy' }
        $script:Gap = [pscustomobject]@{ Key = 'P1UserGaps'; Severity = 'Info'; Check = 'gaps'; Account = ''; Message = '2 users'; Fix = 'assign' }
    }
    BeforeEach { Reset-AlertStore }

    It 'raises the shortfall and not advisory gaps' {
        Set-Report -Findings @($script:Short, $script:Gap) -Short 3
        $null = Invoke-Alert
        $State = Get-LifecycleState 'Get-CIPPAlertEntraEntitlementGap'
        $State['P1Shortfall'] | Should -Be 'Open'
        $State.ContainsKey('P1UserGaps') | Should -BeFalse
    }

    It 'stores the summary for the all-tenants view and the test' {
        Set-Report -Findings @($script:Short) -Short 3
        $null = Invoke-Alert
        ($script:Store['EntraEntitlement'].Values | Where-Object PartitionKey -EQ 'Summary').P1Shortfall | Should -Be 3
    }

    It 'resolves the shortfall when it is fixed' {
        Set-Report -Findings @($script:Short) -Short 3
        $null = Invoke-Alert
        Set-Report
        $null = Invoke-Alert
        (Get-LifecycleState 'Get-CIPPAlertEntraEntitlementGap')['P1Shortfall'] | Should -Be 'Resolved'
    }

    It 'does not report or resolve on a failed read' {
        Set-Report -Findings @($script:Short) -Short 3
        $null = Invoke-Alert
        Set-Report -Errors @('denied')
        $null = Invoke-Alert
        (Get-LifecycleState 'Get-CIPPAlertEntraEntitlementGap')['P1Shortfall'] | Should -Be 'Open'
    }
}

Describe 'Invoke-CippTestGenericTestEntraEntitlement' {
    BeforeAll {
        function Get-CippException { param($Exception) [pscustomobject]@{ NormalizedError = "$Exception" } }
        function Add-CippTestResult { param($TenantFilter, $TestId, $TestType, $Name, $UserImpact, $ImplementationEffort, $Category, $Status, $Risk, $ResultMarkdown) $script:Result = [pscustomobject]@{ TestId = $TestId; Status = $Status; Markdown = [string]$ResultMarkdown } }
        function Add-Summary {
            param([bool]$Covered = $true)
            Add-CIPPAzDataTableEntity -TableName 'EntraEntitlement' -Force -Entity @{
                PartitionKey = 'Summary'; RowKey = 'contoso.com'; CheckedUtc = '2026-11-02T18:00:00Z'; CoveredP1 = $Covered; CoveredP2 = $true
                P1Pool = 5; P1InScope = 7; P1Shortfall = 2; P1UserGaps = 1; P1InScopeWithReportOnly = 7; P2Pool = 0; P2InScope = 0; P2Shortfall = 0; P2UserGaps = 0; P2InScopeWithReportOnly = 0
            }
        }
    }
    BeforeEach { Reset-AlertStore; $script:Result = $null }

    It 'is skipped until the tenant has been checked' {
        Invoke-CippTestGenericTestEntraEntitlement -Tenant 'contoso.com'
        $script:Result.Status | Should -Be 'Skipped'
    }

    It 'fails on a shortfall and shows the check time in US Central' {
        Add-Summary -Covered $false
        Invoke-CippTestGenericTestEntraEntitlement -Tenant 'contoso.com'
        $script:Result.Status | Should -Be 'Failed'
        $script:Result.TestId | Should -Be 'GenericTestEntraEntitlement'
        $script:Result.Markdown | Should -Match '2026-11-02 12:00 US Central'
    }

    It 'passes when covered' {
        Add-Summary
        Invoke-CippTestGenericTestEntraEntitlement -Tenant 'contoso.com'
        $script:Result.Status | Should -Be 'Passed'
    }
}
