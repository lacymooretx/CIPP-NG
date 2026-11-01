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
        Sign-in activity (which method users actually used) is not read: the sign-in log has no filter on the
        method used, so it would mean paging every sign-in. Registration is what decides lock-out anyway.
        Returns @{ Tenant; Summary; Users; Findings; RegisteredByMethod; Errors }. Errors lists reads that should have
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
        $Users = @(New-GraphGetRequest -uri "$Graph/v1.0/users?`$select=id,accountEnabled,userType,assignedLicenses&`$top=999" -tenantid $TenantFilter -ErrorAction Stop)
    } catch { $Errors.Add("Users: $(& $Err $_)") }

    $Policy = try { New-GraphGetRequest -uri "$Graph/beta/policies/authenticationMethodsPolicy" -tenantid $TenantFilter -ErrorAction Stop } catch { $Errors.Add("Authentication methods policy: $(& $Err $_)"); $null }

    # Microsoft's own counts (all users incl. guests and disabled). Nice to have; a failure is not an error.
    $ByMethod = try {
        $R = New-GraphGetRequest -uri "$Graph/beta/reports/authenticationMethods/usersRegisteredByMethod(includedUserTypes='all',includedUserRoles='all')" -tenantid $TenantFilter -ErrorAction Stop
        @($R.userRegistrationMethodCounts | Where-Object { $_.userCount -gt 0 } | ForEach-Object { [pscustomobject]@{ Method = $_.authenticationMethod; Users = $_.userCount } })
    } catch { @() }

    if ($null -eq $Registrations) {
        return [pscustomobject]@{ Tenant = $TenantFilter; Summary = $null; Users = @(); Findings = @(); RegisteredByMethod = $ByMethod; Errors = @($Errors) }
    }

    $Params = @{ Registrations = $Registrations; Policy = $Policy }
    if ($null -ne $Users) { $Params.Users = $Users }
    $Result = Test-CIPPSmsMfaReadiness @Params

    [pscustomobject]@{
        Tenant             = $TenantFilter
        Summary            = $Result.Summary
        Users              = $Result.Users
        Findings           = $Result.Findings
        RegisteredByMethod = $ByMethod
        Errors             = @($Errors)
    }
}
