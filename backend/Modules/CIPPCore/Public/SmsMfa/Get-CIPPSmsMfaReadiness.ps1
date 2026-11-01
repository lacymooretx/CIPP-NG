function Get-CIPPSmsMfaReadiness {
    <#
    .SYNOPSIS
        Collects a tenant's MFA registration details, users and authentication methods policy, and evaluates them
        with Test-CIPPSmsMfaReadiness.
    .DESCRIPTION
        Read only. Reads:
          beta reports/authenticationMethods/userRegistrationDetails  (needs Entra ID P1; without it the report
                                                                       cannot be built and Errors says so)
          v1.0 users (id, accountEnabled, userType, assignedLicenses)   to count enabled members only
          beta policies/authenticationMethodsPolicy                     SMS and voice state
          beta reports/authenticationMethods/usersRegisteredByMethod     Microsoft's own method counts, returned as
                                                                       RegisteredByMethod for comparison
          v1.0 roleManagement/directory/roleAssignments (Global Admin)  who keeps SMS/voice until 2027-07-01
                                                                       (role-assignable groups expanded)
          v1.0 roleManagement/directory/roleEligibilitySchedules        PIM-eligible Global Admins (P2; skipped
                                                                       silently without it)
        Sign-in activity (which method users actually used) is not read: the sign-in log has no filter on the
        method used, so it would mean paging every sign-in. Registration is what decides lock-out anyway.
        Returns @{ Tenant; Summary; Users; Guests; Findings; RegisteredByMethod; Errors }. Errors lists reads that should have
        worked and did not, so a caller can tell "could not check" from "clear". Aspendora fork addition (Vikunja CIPP-6).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TenantFilter)

    $Errors = [System.Collections.Generic.List[string]]::new()
    $Graph = 'https://graph.microsoft.com'
    $Err = { param($E) (Get-CippException -Exception $E).NormalizedError }

    # Assigned inside try: an empty array returned from a try expression would collapse to $null.
    $Registrations = $null
    try {
        $Registrations = @(New-GraphGetRequest -uri "$Graph/beta/reports/authenticationMethods/userRegistrationDetails?`$select=id,userPrincipalName,userDisplayName,userType,isAdmin,isMfaCapable,isPasswordlessCapable,methodsRegistered,defaultMfaMethod,userPreferredMethodForSecondaryAuthentication,systemPreferredAuthenticationMethods,isSystemPreferredAuthenticationMethodEnabled" -tenantid $TenantFilter -ErrorAction Stop)
    } catch {
        $Msg = & $Err $_
        $Hint = if ($Msg -match 'P1|premium|licen[cs]e') { ' The registration report needs Entra ID P1 (Business Premium, E3 or E5).' } else { '' }
        $Errors.Add("Registration report: $Msg$Hint")
    }

    $Users = $null
    try {
        # userPrincipalName, creationType, externalUserState and identities tell external users (July 2027
        # retirement) from internal guests (February) - CIPP-46.
        $Users = @(New-GraphGetRequest -uri "$Graph/v1.0/users?`$select=id,accountEnabled,userType,assignedLicenses,userPrincipalName,creationType,externalUserState,identities&`$top=999" -tenantid $TenantFilter -ErrorAction Stop)
    } catch { $Errors.Add("Users: $(& $Err $_)") }

    # Global Administrator holders: they keep Microsoft-provided SMS/voice until 2027-07-01 (CIPP-46). Not added to
    # Errors when unreadable: the report still works, everyone just gets the earlier February date.
    $GaRole = '62e90394-69f5-4237-9190-012177145e10'
    $GlobalAdminIds = $null
    try {
        $Assignments = @(New-GraphGetRequest -uri "$Graph/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$GaRole'&`$select=principalId,directoryScopeId" -tenantid $TenantFilter -ErrorAction Stop)
        $GaIds = [System.Collections.Generic.List[string]]::new()
        $UserIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($U in @($Users)) { if ($U.id) { [void]$UserIds.Add([string]$U.id) } }
        foreach ($A in $Assignments) {
            if (-not $A.principalId) { continue }
            if ($A.directoryScopeId -and [string]$A.directoryScopeId -ne '/') { continue }
            $GaIds.Add([string]$A.principalId)
            # A principal that is not a user is a role-assignable group or an app. Expand groups; apps 404 here,
            # which is fine. Only attempted when the user list was read, so it is not tried for every principal.
            if ($null -ne $Users -and -not $UserIds.Contains([string]$A.principalId)) {
                try {
                    foreach ($M in @(New-GraphGetRequest -uri "$Graph/v1.0/groups/$($A.principalId)/transitiveMembers/microsoft.graph.user?`$select=id" -tenantid $TenantFilter -ErrorAction Stop)) {
                        if ($M.id) { $GaIds.Add([string]$M.id) }
                    }
                } catch { Write-Verbose "Global Administrator principal $($A.principalId) is not an expandable group." }
            }
        }
        # Direct assignment (an empty List through if/return would become $null, i.e. "unknown").
        $GlobalAdminIds = [string[]]@($GaIds)
    } catch {
        Write-Information "SMS MFA readiness: could not read Global Administrator holders for $($TenantFilter): $(& $Err $_)"
    }
    # PIM-eligible Global Administrators: needs Entra ID P2, so a failure is normal and silent.
    $GlobalAdminEligibleIds = $null
    try {
        $Eligible = @(New-GraphGetRequest -uri "$Graph/v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=roleDefinitionId eq '$GaRole'&`$select=principalId,directoryScopeId" -tenantid $TenantFilter -ErrorAction Stop)
        $GlobalAdminEligibleIds = [string[]]@($Eligible | Where-Object { $_.principalId -and (-not $_.directoryScopeId -or [string]$_.directoryScopeId -eq '/') } | ForEach-Object { [string]$_.principalId })
    } catch { $GlobalAdminEligibleIds = $null }

    $Policy = try { New-GraphGetRequest -uri "$Graph/beta/policies/authenticationMethodsPolicy" -tenantid $TenantFilter -ErrorAction Stop } catch { $Errors.Add("Authentication methods policy: $(& $Err $_)"); $null }

    # Microsoft's own counts (all users incl. guests and disabled). Nice to have; a failure is not an error.
    $ByMethod = try {
        $R = New-GraphGetRequest -uri "$Graph/beta/reports/authenticationMethods/usersRegisteredByMethod(includedUserTypes='all',includedUserRoles='all')" -tenantid $TenantFilter -ErrorAction Stop
        @($R.userRegistrationMethodCounts | Where-Object { $_.userCount -gt 0 } | ForEach-Object { [pscustomobject]@{ Method = $_.authenticationMethod; Users = $_.userCount } })
    } catch { @() }

    if ($null -eq $Registrations) {
        return [pscustomobject]@{ Tenant = $TenantFilter; Summary = $null; Users = @(); Guests = @(); Findings = @(); RegisteredByMethod = $ByMethod; Errors = @($Errors) }
    }

    $Params = @{ Registrations = $Registrations; Policy = $Policy }
    if ($null -ne $Users) { $Params.Users = $Users }
    if ($null -ne $GlobalAdminIds) { $Params.GlobalAdminIds = $GlobalAdminIds }
    if ($null -ne $GlobalAdminEligibleIds) { $Params.GlobalAdminEligibleIds = $GlobalAdminEligibleIds }
    $Result = Test-CIPPSmsMfaReadiness @Params

    [pscustomobject]@{
        Tenant             = $TenantFilter
        Summary            = $Result.Summary
        Users              = $Result.Users
        Guests             = $Result.Guests
        Findings           = $Result.Findings
        RegisteredByMethod = $ByMethod
        Errors             = @($Errors)
    }
}
