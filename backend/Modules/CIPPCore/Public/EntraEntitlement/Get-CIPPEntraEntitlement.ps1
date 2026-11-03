function Get-CIPPEntraEntitlement {
    <#
    .SYNOPSIS
        Collects a tenant's licences, users and Conditional Access scope, and evaluates them with
        Test-CIPPEntraEntitlement.
    .DESCRIPTION
        Read only. Reads:
          v1.0 subscribedSkus                                     licence pools by service plan
          v1.0 users (with assignedPlans)                         who is enabled and what they hold
          v1.0 identity/conditionalAccess/policies                enabled and report-only policies
          v1.0 groups/{id}/transitiveMembers                      only groups those policies reference
          v1.0 roleManagement/directory/roleAssignments           only roles those policies reference
          v1.0 roleManagement/directory/roleEligibilitySchedules  PIM-eligible holders (needs P2; silent without it)
          v1.0 users (with signInActivity)                        last sign-in, best effort (needs a premium tenant)
          CIPP cache: Mailboxes                                   shared and resource mailbox accounts, best effort

        Role assignments are read with $select only: $expand=principal fails the whole query if one assignment points
        at a deleted principal. A PIM-eligible holder counts as a role holder for inclusion and exclusion alike.

        Returns @{ Tenant; Summary; Skus; Users; Findings; Errors; Notes }. Errors lists reads that should have worked
        and did not, so a caller can tell "could not check" from "clear". With any Errors, Summary is $null.
        Aspendora fork addition (Vikunja CIPP-47).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TenantFilter)

    $Errors = [System.Collections.Generic.List[string]]::new()
    $Notes = [System.Collections.Generic.List[string]]::new()
    $Graph = 'https://graph.microsoft.com/v1.0'
    $Err = { param($E) (Get-CippException -Exception $E).NormalizedError }
    $Guid = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'

    # Assigned inside try: an empty array returned from a try expression would collapse to $null.
    $Skus = @()
    try { $Skus = @(New-GraphGetRequest -uri "$Graph/subscribedSkus?`$select=skuPartNumber,appliesTo,capabilityStatus,consumedUnits,prepaidUnits,servicePlans" -tenantid $TenantFilter -ErrorAction Stop) }
    catch { $Errors.Add("Licences: $(& $Err $_)") }

    $Users = @()
    try { $Users = @(New-GraphGetRequest -uri "$Graph/users?`$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,assignedPlans&`$top=999" -tenantid $TenantFilter -ErrorAction Stop) }
    catch { $Errors.Add("Users: $(& $Err $_)") }

    $Policies = @()
    try { $Policies = @(New-GraphGetRequest -uri "$Graph/identity/conditionalAccess/policies" -tenantid $TenantFilter -AsApp $true -ErrorAction Stop) }
    catch { $Errors.Add("Conditional Access policies: $(& $Err $_)") }

    $Active = @($Policies | Where-Object { [string]$_.state -in @('enabled', 'enabledForReportingButNotEnforced') })
    $UserIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($U in $Users) { if ($U.id) { [void]$UserIds.Add([string]$U.id) } }

    # --- Last sign-in: asked for separately because Graph caps the page at 500 with signInActivity. Best effort: without
    # it every account counts as active, so a failed read can only overstate a shortfall. A read returning no activity
    # for anyone is treated as unavailable, or a silent null would make every account look inactive and hide a shortfall.
    $LastSignIn = $null
    try {
        $Activity = @(New-GraphGetRequest -uri "$Graph/users?`$select=id,signInActivity&`$top=500" -tenantid $TenantFilter -AsApp $true -ErrorAction Stop)
        if (@($Activity | Where-Object { $_.signInActivity }).Count -gt 0) {
            $Map = @{}
            foreach ($Row in $Activity) {
                $Dates = @(foreach ($Name in 'lastSignInDateTime', 'lastNonInteractiveSignInDateTime', 'lastSuccessfulSignInDateTime') {
                        $Value = $Row.signInActivity.$Name
                        if ($Value) {
                            $Date = if ($Value -is [datetime]) { [datetimeoffset]$Value } else { [datetimeoffset][string]$Value }
                            if ($Date.Year -ge 2000) { $Date }
                        }
                    })
                $Map[[string]$Row.id] = if ($Dates.Count -gt 0) { ($Dates | Sort-Object -Descending | Select-Object -First 1) } else { $null }
            }
            $LastSignIn = $Map
        } else {
            $Notes.Add('Graph returned no sign-in activity, so every account counts as active.')
        }
    } catch {
        $Notes.Add("Could not read sign-in activity, so every account counts as active: $(& $Err $_)")
    }

    # --- Referenced groups ---
    $GroupMembers = @{}
    $GroupIds = @($Active | ForEach-Object { @($_.conditions.users.includeGroups) + @($_.conditions.users.excludeGroups) } | Where-Object { [string]$_ -match $Guid } | Sort-Object -Unique)
    foreach ($GroupId in $GroupIds) {
        try {
            $GroupMembers[[string]$GroupId] = @(New-GraphGetRequest -uri "$Graph/groups/$GroupId/transitiveMembers/microsoft.graph.user?`$select=id&`$top=999" -tenantid $TenantFilter -ErrorAction Stop | ForEach-Object { [string]$_.id })
        } catch {
            $Msg = & $Err $_
            if ($Msg -match 'does not exist|ResourceNotFound|Request_ResourceNotFound') {
                $Notes.Add("Group $GroupId is referenced by a policy but no longer exists; it was treated as empty.")
                $GroupMembers[[string]$GroupId] = @()
            } else {
                $Errors.Add("Group $($GroupId): $Msg")
            }
        }
    }

    # --- Referenced roles ---
    $RoleMembers = @{}
    $RoleIds = @($Active | ForEach-Object { @($_.conditions.users.includeRoles) + @($_.conditions.users.excludeRoles) } | Where-Object { [string]$_ -match $Guid } | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique)
    if ($RoleIds.Count -gt 0) {
        $Holders = @()
        try {
            $Holders = @(New-GraphGetRequest -uri "$Graph/roleManagement/directory/roleAssignments?`$select=principalId,roleDefinitionId,directoryScopeId" -tenantid $TenantFilter -ErrorAction Stop)
        } catch { $Errors.Add("Role assignments: $(& $Err $_)") }
        try {
            $Holders += @(New-GraphGetRequest -uri "$Graph/roleManagement/directory/roleEligibilitySchedules?`$select=principalId,roleDefinitionId,directoryScopeId" -tenantid $TenantFilter -ErrorAction Stop)
        } catch {
            Write-Information "Entra entitlement: no PIM eligibility for $($TenantFilter): $(& $Err $_)"
        }
        $Expanded = @{}
        foreach ($H in $Holders) {
            if ($H.directoryScopeId -and [string]$H.directoryScopeId -ne '/') { continue }
            $RoleId = ([string]$H.roleDefinitionId).ToLowerInvariant()
            if ($RoleId -notin $RoleIds -or -not $H.principalId) { continue }
            $PrincipalId = [string]$H.principalId
            if (-not $RoleMembers.ContainsKey($RoleId)) { $RoleMembers[$RoleId] = [System.Collections.Generic.List[string]]::new() }
            if ($UserIds.Contains($PrincipalId)) { $RoleMembers[$RoleId].Add($PrincipalId); continue }
            # Not a user: a role-assignable group, or an app, which returns not found here and has no seat.
            if (-not $Expanded.ContainsKey($PrincipalId)) {
                $Expanded[$PrincipalId] = try {
                    @(New-GraphGetRequest -uri "$Graph/groups/$PrincipalId/transitiveMembers/microsoft.graph.user?`$select=id&`$top=999" -tenantid $TenantFilter -ErrorAction Stop | ForEach-Object { [string]$_.id })
                } catch { @() }
            }
            foreach ($Member in @($Expanded[$PrincipalId])) { $RoleMembers[$RoleId].Add([string]$Member) }
        }
    }

    # --- Shared and resource mailboxes ---
    $NonPersonIds = @()
    try {
        $Mailboxes = @(New-CIPPDbRequest -TenantFilter $TenantFilter -Type 'Mailboxes' | Where-Object { $_ })
        if ($Mailboxes.Count -eq 0) {
            $Notes.Add('No cached mailbox data, so shared and resource mailbox accounts are counted as people.')
        }
        $NonPersonIds = @($Mailboxes | Where-Object { [string]$_.recipientTypeDetails -in @('SharedMailbox', 'RoomMailbox', 'EquipmentMailbox', 'SchedulingMailbox') -and $_.ExternalDirectoryObjectId } | ForEach-Object { [string]$_.ExternalDirectoryObjectId })
    } catch {
        $Notes.Add('Could not read cached mailbox data, so shared and resource mailbox accounts are counted as people.')
    }

    if ($Errors.Count -gt 0) {
        return [pscustomobject]@{ Tenant = $TenantFilter; Summary = $null; Skus = @(); Users = @(); Findings = @(); Errors = @($Errors); Notes = @($Notes) }
    }

    $Result = Test-CIPPEntraEntitlement -Skus $Skus -Users $Users -Policies $Policies -GroupMembers $GroupMembers -RoleMembers $RoleMembers -NonPersonIds $NonPersonIds -LastSignIn $LastSignIn
    [pscustomobject]@{
        Tenant   = $TenantFilter
        Summary  = $Result.Summary
        Skus     = $Result.Skus
        Users    = $Result.Users
        Findings = $Result.Findings
        Errors   = @()
        Notes    = @($Notes)
    }
}
