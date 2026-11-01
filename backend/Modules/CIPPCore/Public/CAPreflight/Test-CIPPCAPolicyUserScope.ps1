function Test-CIPPCAPolicyUserScope {
    <#
    .SYNOPSIS
        Says whether a Conditional Access policy's user assignment covers one principal, and why.
    .DESCRIPTION
        Pure: no Graph calls. Evaluates conditions.users only (users, groups, directory roles and the
        guest/external user types); applications, platforms, locations, client apps and risk are not
        considered, so "in scope" means "in scope for at least some sign-ins" (the worst case).

        Rules (as Entra applies them): exclusion wins over inclusion; 'All' includes every user, members
        and external users alike; groups and roles are matched against the principal's transitive group
        ids and active role template ids. For an external (e.g. GDAP service-provider) principal whose
        home tenant is unknown, an enumerated tenant list counts as including it but not as excluding it,
        so an unknown is never read as "safe".

        Shared by Test-CIPPBreakGlassPosture and Test-CIPPCAPreflight. Aspendora fork addition (Vikunja CIPP-5).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        # Conditional Access policy (Graph or template shape).
        [Parameter(Mandatory)]$Policy,
        # @{ Id; GroupIds; RoleTemplateIds; IsExternal; ExternalUserType ('serviceProvider', 'b2bCollaborationGuest', ...); HomeTenantId }
        [Parameter(Mandatory)]$Principal
    )

    $U = $Policy.conditions.users
    $Id = [string]$Principal.Id
    $Groups = @($Principal.GroupIds | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $Roles = @($Principal.RoleTemplateIds | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $External = $Principal.IsExternal -eq $true
    $ExtType = [string]($Principal.ExternalUserType ?? 'serviceProvider')

    $MatchExternal = {
        param($Spec, [bool]$UnknownTenantMatches)
        if (-not $External -or -not $Spec) { return $false }
        $Types = @(([string]$Spec.guestOrExternalUserTypes) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($ExtType -notin $Types) { return $false }
        $Tenants = $Spec.externalTenants
        if (-not $Tenants -or $Tenants.membershipKind -ne 'enumerated') { return $true }
        if (-not $Principal.HomeTenantId) { return $UnknownTenantMatches }
        return [string]$Principal.HomeTenantId -in @($Tenants.members | ForEach-Object { [string]$_ })
    }

    $Inc = [System.Collections.Generic.List[string]]::new()
    $Exc = [System.Collections.Generic.List[string]]::new()
    if ($U) {
        $IncUsers = @($U.includeUsers | ForEach-Object { [string]$_ })
        $ExcUsers = @($U.excludeUsers | ForEach-Object { [string]$_ })
        if ($IncUsers -contains 'All') { $Inc.Add('All users') }
        if ($Id -and $IncUsers -contains $Id) { $Inc.Add('included directly') }
        if ($External -and $IncUsers -contains 'GuestsOrExternalUsers') { $Inc.Add('all guests or external users') }
        foreach ($G in @($U.includeGroups | Where-Object { [string]$_ -in $Groups })) { $Inc.Add("included group $G") }
        foreach ($R in @($U.includeRoles | Where-Object { [string]$_ -in $Roles })) { $Inc.Add("included role $R") }
        if (& $MatchExternal $U.includeGuestsOrExternalUsers $true) { $Inc.Add("included external user type $ExtType") }

        if ($Id -and $ExcUsers -contains $Id) { $Exc.Add('excluded directly') }
        if ($External -and $ExcUsers -contains 'GuestsOrExternalUsers') { $Exc.Add('excluded as guest or external user') }
        foreach ($G in @($U.excludeGroups | Where-Object { [string]$_ -in $Groups })) { $Exc.Add("excluded group $G") }
        foreach ($R in @($U.excludeRoles | Where-Object { [string]$_ -in $Roles })) { $Exc.Add("excluded role $R") }
        if (& $MatchExternal $U.excludeGuestsOrExternalUsers $false) { $Exc.Add("excluded external user type $ExtType") }
    }

    $Included = $Inc.Count -gt 0
    $Excluded = $Exc.Count -gt 0
    [pscustomobject]@{
        Included   = $Included
        Excluded   = $Excluded
        InScope    = $Included -and -not $Excluded
        IncludedBy = @($Inc)
        ExcludedBy = @($Exc)
        Reason     = if ($Excluded) { $Exc -join '; ' } elseif ($Included) { $Inc -join '; ' } else { 'not included by the policy' }
    }
}
