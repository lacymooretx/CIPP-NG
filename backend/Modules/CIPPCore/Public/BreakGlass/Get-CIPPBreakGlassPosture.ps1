function Get-CIPPBreakGlassPosture {
    <#
    .SYNOPSIS
        Collects a tenant's break-glass data from Graph and evaluates it with Test-CIPPBreakGlassPosture.
    .DESCRIPTION
        Uses the BreakGlassAccounts registry. Every Graph read that needs a licence the tenant may not have
        (sign-in activity: P1; PIM schedules: P2) degrades to "unknown" rather than producing a false finding.
        Returns @{ Tenant; Findings; Accounts; PlanWarning; Errors }. Aspendora fork addition (Vikunja CIPP-4).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TenantFilter)

    $GlobalAdmin = '62e90394-69f5-4237-9190-012177145e10'
    $Errors = [System.Collections.Generic.List[string]]::new()
    $Graph = 'https://graph.microsoft.com'
    $Get = {
        param($Uri)
        New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -ErrorAction Stop
    }

    $Policies = try { @(& $Get "$Graph/v1.0/identity/conditionalAccess/policies") } catch { $Errors.Add("Conditional Access policies: $((Get-CippException -Exception $_).NormalizedError)"); @() }
    $DomainNeverExpires = @{}
    $Accounts = foreach ($Row in @(Get-CIPPBreakGlassAccounts -TenantFilter $TenantFilter)) {
        $Id = [string]$Row.RowKey
        $A = [ordered]@{ Id = $Id; UserPrincipalName = $Row.UserPrincipalName; Exists = $true; SignInActivityKnown = $false; Methods = $null; GroupIds = @(); RoleTemplateIds = @() }

        $User = $null
        try {
            $User = & $Get "$Graph/beta/users/$($Id)?`$select=id,userPrincipalName,accountEnabled,onPremisesSyncEnabled,passwordPolicies,signInActivity,isManagementRestricted"
            $A.SignInActivityKnown = $true
            $A.LastSuccessfulSignIn = $User.signInActivity.lastSuccessfulSignInDateTime
        } catch {
            $Err = (Get-CippException -Exception $_).NormalizedError
            if ($Err -match 'Request_ResourceNotFound|does not exist') { $A.Exists = $false; [pscustomobject]$A; continue }
            # Usually no P1 for signInActivity; read the rest without it.
            try { $User = & $Get "$Graph/v1.0/users/$($Id)?`$select=id,userPrincipalName,accountEnabled,onPremisesSyncEnabled,passwordPolicies,isManagementRestricted" } catch { $Errors.Add("User $($Id): $((Get-CippException -Exception $_).NormalizedError)"); [pscustomobject]$A; continue }
        }
        $A.UserPrincipalName = $User.userPrincipalName
        $A.AccountEnabled = $User.accountEnabled
        $A.OnPremisesSyncEnabled = $User.onPremisesSyncEnabled
        $A.PasswordPolicies = $User.passwordPolicies
        $A.ManagementRestricted = $User.isManagementRestricted -eq $true

        $Domain = ($User.userPrincipalName -split '@')[-1]
        if (-not $DomainNeverExpires.ContainsKey($Domain)) {
            $DomainNeverExpires[$Domain] = try { [int64](& $Get "$Graph/v1.0/domains/$($Domain)?`$select=passwordValidityPeriodInDays").passwordValidityPeriodInDays -ge 2147483647 } catch { $false }
        }
        $A.PasswordNeverExpiresByDomain = $DomainNeverExpires[$Domain]

        # Active Global Admin. Schedule instances tell permanent ('Assigned') from PIM-activated ones; without P2 fall back to roleAssignments.
        $A.ActiveGlobalAdmin = $false
        try {
            $Instances = @(& $Get "$Graph/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=principalId eq '$Id'")
            $A.ActiveGlobalAdmin = [bool]($Instances | Where-Object { $_.roleDefinitionId -eq $GlobalAdmin -and $_.directoryScopeId -eq '/' -and $_.assignmentType -eq 'Assigned' -and -not $_.endDateTime })
        } catch {
            try {
                $Assignments = @(& $Get "$Graph/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$Id'")
                $A.ActiveGlobalAdmin = [bool]($Assignments | Where-Object { $_.roleDefinitionId -eq $GlobalAdmin -and $_.directoryScopeId -eq '/' })
            } catch { $Errors.Add("Roles for $($User.userPrincipalName): $((Get-CippException -Exception $_).NormalizedError)"); $A.ActiveGlobalAdmin = $true }
        }
        $A.EligibleGlobalAdmin = try { [bool](@(& $Get "$Graph/v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$Id'") | Where-Object { $_.roleDefinitionId -eq $GlobalAdmin }) } catch { $false }

        try {
            $Member = @(& $Get "$Graph/v1.0/users/$($Id)/transitiveMemberOf?`$select=id,roleTemplateId")
            $A.GroupIds = @($Member | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' } | ForEach-Object id)
            $A.RoleTemplateIds = @($Member | Where-Object roleTemplateId | ForEach-Object roleTemplateId)
        } catch { $Errors.Add("Group membership for $($User.userPrincipalName): $((Get-CippException -Exception $_).NormalizedError)") }
        if ($A.ActiveGlobalAdmin -and $GlobalAdmin -notin $A.RoleTemplateIds) { $A.RoleTemplateIds += $GlobalAdmin }

        $A.Methods = try { @(& $Get "$Graph/v1.0/users/$($Id)/authentication/methods" | ForEach-Object { $_.'@odata.type' }) } catch { $null }
        [pscustomobject]$A
    }

    # Names for accounts with broad CA exclusions.
    $Ids = @{}
    foreach ($P in @($Policies | Where-Object { $_.state -eq 'enabled' -and (@($_.conditions.users.includeUsers) -contains 'All') })) {
        foreach ($X in @($P.conditions.users.excludeUsers | Where-Object { $_ -and $_ -ne 'GuestsOrExternalUsers' })) { $Ids[$X] = 1 + ($Ids[$X] ?? 0) }
    }
    $Names = @{}
    foreach ($X in @($Ids.Keys | Where-Object { $Ids[$_] -ge 3 })) {
        $Names[$X] = try { (& $Get "$Graph/v1.0/users/$($X)?`$select=userPrincipalName").userPrincipalName } catch { $X }
    }

    # Plans are on a beta API, so a failed read degrades to Info and does not block the rest of the report (Vikunja CIPP-56).
    $PlanSummary = $null
    try {
        $PlanSummary = Get-CIPPCAPlanSummary -Plans @(Get-CIPPConditionalAccessPlans -TenantFilter $TenantFilter)
    } catch {
        Write-Information "Break-glass posture: could not read Conditional Access plans for $($TenantFilter): $((Get-CippException -Exception $_).NormalizedError)"
    }

    # Exclusion groups are not registered: one is any group that holds a registered account and is excluded from a CA policy (Vikunja CIPP-54).
    $AccountGroupIds = @($Accounts | ForEach-Object { $_.GroupIds } | Where-Object { $_ })
    $PolicyExcludedGroupIds = @($Policies | ForEach-Object { $_.conditions.users.excludeGroups } | Where-Object { $_ } | Select-Object -Unique)
    $ExclusionGroups = foreach ($GroupId in @($PolicyExcludedGroupIds | Where-Object { $_ -in $AccountGroupIds })) {
        try {
            $Group = & $Get "$Graph/v1.0/groups/$($GroupId)?`$select=id,displayName"
            [pscustomobject]@{
                Id          = $GroupId
                DisplayName = $Group.displayName
                Members     = @(& $Get "$Graph/v1.0/groups/$($GroupId)/transitiveMembers?`$select=id,displayName,userPrincipalName&`$top=999")
            }
        } catch { $Errors.Add("Members of exclusion group $($GroupId): $((Get-CippException -Exception $_).NormalizedError)") }
    }

    # The property has no documented filter support, so restricted units are picked out client-side. Tenants rarely have any.
    $RestrictedUnits = @()
    $RestrictedUnitsUnknown = $false
    try {
        $RestrictedUnits = foreach ($Unit in @(& $Get "$Graph/v1.0/directory/administrativeUnits?`$select=id,displayName,isMemberManagementRestricted&`$top=999" | Where-Object { $_.isMemberManagementRestricted -eq $true })) {
            [pscustomobject]@{
                Id           = $Unit.id
                DisplayName  = $Unit.displayName
                Members      = @(& $Get "$Graph/v1.0/directory/administrativeUnits/$($Unit.id)/members?`$select=id,displayName,userPrincipalName&`$top=999")
                ScopedAdmins = @(& $Get "$Graph/v1.0/directory/administrativeUnits/$($Unit.id)/scopedRoleMembers")
            }
        }
    } catch {
        $RestrictedUnitsUnknown = $true
        Write-Information "Break-glass posture: could not read restricted management AUs for $($TenantFilter): $((Get-CippException -Exception $_).NormalizedError)"
    }

    $PostureArgs = @{
        Accounts               = @($Accounts)
        Policies               = $Policies
        UserNames              = $Names
        PlanSummary            = $PlanSummary
        PlansUnknown           = $null -eq $PlanSummary
        ExclusionGroups        = @($ExclusionGroups)
        RestrictedUnits        = @($RestrictedUnits)
        RestrictedUnitsUnknown = $RestrictedUnitsUnknown
    }
    [pscustomobject]@{
        Tenant      = $TenantFilter
        Findings    = @(Test-CIPPBreakGlassPosture @PostureArgs)
        Accounts    = @($Accounts | ForEach-Object { [pscustomobject]@{ UserPrincipalName = $_.UserPrincipalName; Exists = $_.Exists; ActiveGlobalAdmin = $_.ActiveGlobalAdmin; Methods = $_.Methods; LastSuccessfulSignIn = $_.LastSuccessfulSignIn; ManagementRestricted = $_.ManagementRestricted } })
        PlanWarning = $PlanSummary.Warning
        Errors      = @($Errors)
    }
}
