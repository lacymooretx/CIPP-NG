function Get-CIPPAdminInventory {
    <#
    .SYNOPSIS
        Every holder of a privileged directory role in one tenant, with MFA and phishing-resistant status and flags.
    .DESCRIPTION
        Read-only. Active assignments come from roleManagement/directory/roleAssignments. PIM-eligible ones come
        from roleEligibilitySchedules, which needs Entra ID P2; without P2 the read fails and Eligible is reported
        as unknown, not as "none".
        Principals are resolved with directoryObjects/getByIds rather than $expand=principal: an assignment whose
        principal was deleted makes $expand drop or fail the page.
        Roles covered: every built-in role Graph marks isPrivileged, plus Billing, Exchange, SharePoint, Teams and
        Intune admins, which matter to an MSP even though Graph does not mark them.
        Flags: PermanentGA (active Global Admin that is not a registered break-glass account), ServicePrincipalGA,
        Synced (on-premises synced admin), NoMFA, NotPhishResistant.
        Aspendora fork addition (onboarding Phase 3).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TenantFilter)

    $GA = '62e90394-69f5-4237-9190-012177145e10'
    $AlwaysInclude = @(
        'b0f54661-2d74-4c50-afa3-1ec803f12efe', # Billing Administrator
        '29232cdf-9323-42fd-ade2-1d097af3e4de', # Exchange Administrator
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', # SharePoint Administrator
        '69091246-20e8-4a56-aa4d-066075b2a7a8', # Teams Administrator
        '3a2c62db-5318-420d-8d74-23affee5d9d5'  # Intune Administrator
    )
    $Notes = [System.Collections.Generic.List[string]]::new()

    $Defs = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?$select=id,displayName,isPrivileged,isBuiltIn' -tenantid $TenantFilter)
    $Names = @{}; foreach ($D in $Defs) { $Names[[string]$D.id] = $D.displayName }
    $Privileged = @($Defs | Where-Object { $_.isPrivileged -eq $true -or $_.id -in $AlwaysInclude } | ForEach-Object { [string]$_.id })

    $Rows = [System.Collections.Generic.List[object]]::new()
    # principalOrganizationId (beta) tells GDAP groups of a partner apart from deleted principals: a partner's group
    # is not a directory object in this tenant, so getByIds never returns it.
    $TenantId = ([string](Get-Tenants -TenantFilter $TenantFilter | Select-Object -First 1).customerId).ToLower()
    $OrgOf = @{}
    foreach ($A in @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId,principalOrganizationId' -tenantid $TenantFilter)) {
        if ($A.principalOrganizationId) { $OrgOf[[string]$A.principalId] = ([string]$A.principalOrganizationId).ToLower() }
        if ([string]$A.roleDefinitionId -in $Privileged) { $Rows.Add([pscustomobject]@{ PrincipalId = [string]$A.principalId; RoleId = [string]$A.roleDefinitionId; Assignment = 'Active'; Scope = $A.directoryScopeId }) }
    }
    $EligibleKnown = $true
    try {
        foreach ($E in @(New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$select=principalId,roleDefinitionId,directoryScopeId' -tenantid $TenantFilter -ErrorAction Stop)) {
            if ([string]$E.roleDefinitionId -in $Privileged) { $Rows.Add([pscustomobject]@{ PrincipalId = [string]$E.principalId; RoleId = [string]$E.roleDefinitionId; Assignment = 'Eligible'; Scope = $E.directoryScopeId }) }
        }
    } catch { $EligibleKnown = $false; $Notes.Add('PIM-eligible assignments could not be read (usually no Entra ID P2), so only active assignments are listed.') }

    $Ids = @($Rows.PrincipalId | Select-Object -Unique)
    $Principals = @{}
    $PartnerNames = @{}
    for ($i = 0; $i -lt $Ids.Count; $i += 1000) {
        $Chunk = $Ids[$i..([math]::Min($i + 999, $Ids.Count - 1))]
        $Body = @{ ids = @($Chunk); types = @('user', 'servicePrincipal', 'group') } | ConvertTo-Json -Compress
        # getByIds answers { value: [...] }; New-GraphPOSTRequest does not unwrap it.
        $Resp = New-GraphPOSTRequest -uri 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds?$select=id,displayName,userPrincipalName,accountEnabled,onPremisesSyncEnabled,appId' -tenantid $TenantFilter -type POST -body $Body
        foreach ($O in @($Resp.value ?? $Resp)) { if ($O.id) { $Principals[[string]$O.id] = $O } }
    }
    # Our own GDAP groups live in the partner tenant: resolve their names there.
    $Partner = ([string]$env:TenantID).ToLower()
    $KnownOrgs = @{}
    foreach ($K in @(Get-Tenants -IncludeAll)) { if ($K.customerId) { $KnownOrgs[([string]$K.customerId).ToLower()] = $K.displayName } }
    $PartnerIds = @($Ids | Where-Object { -not $Principals[$_] -and $OrgOf[$_] -eq $Partner })
    if ($PartnerIds.Count -and $Partner) {
        try {
            $Resp = New-GraphPOSTRequest -uri 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds?$select=id,displayName' -tenantid $Partner -type POST -body (@{ ids = @($PartnerIds); types = @('group') } | ConvertTo-Json -Compress)
            foreach ($O in @($Resp.value ?? $Resp)) { if ($O.id) { $PartnerNames[[string]$O.id] = $O.displayName } }
        } catch { $Notes.Add('Could not resolve the names of Aspendora GDAP groups in the partner tenant.') }
    }

    $BreakGlass = @(Get-CIPPBreakGlassAccounts -TenantFilter $TenantFilter | ForEach-Object { [string]$_.RowKey })
    $Strong = 'fido2|windowsHelloForBusiness|x509Certificate|platformCredential'
    $Out = [System.Collections.Generic.List[object]]::new()
    foreach ($Id in $Ids) {
        $P = $Principals[$Id]
        $Foreign = -not $P -and $OrgOf[$Id] -and $OrgOf[$Id] -ne $TenantId
        $Type = if ($P) { ([string]$P.'@odata.type' -replace '#microsoft.graph.', '') }
        elseif ($Foreign -and $OrgOf[$Id] -eq $Partner) { 'GDAP group (Aspendora)' }
        elseif ($Foreign -and $KnownOrgs[$OrgOf[$Id]]) { "GDAP group ($($KnownOrgs[$OrgOf[$Id]]))" }
        elseif ($Foreign) { "GDAP group (unknown organisation $($OrgOf[$Id]))" }
        else { 'Deleted or unknown' }
        $Mine = @($Rows | Where-Object PrincipalId -EQ $Id)
        $Methods = $null
        if ($Type -eq 'user') {
            try { $Methods = @(New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users/$Id/authentication/methods?`$select=id" -tenantid $TenantFilter -ErrorAction Stop | ForEach-Object { ([string]$_.'@odata.type' -replace '#microsoft.graph.', '' -replace 'AuthenticationMethod$', '') }) } catch { $Methods = $null }
        }
        $ActiveGA = @($Mine | Where-Object { $_.RoleId -eq $GA -and $_.Assignment -eq 'Active' }).Count -gt 0
        $IsBG = $Id -in $BreakGlass
        $Mfa = if ($null -eq $Methods) { $null } else { @($Methods | Where-Object { $_ -ne 'password' -and $_ -ne 'email' }).Count -gt 0 }
        $Phish = if ($null -eq $Methods) { $null } else { @($Methods | Where-Object { $_ -match $Strong }).Count -gt 0 }
        $Flags = [System.Collections.Generic.List[string]]::new()
        if ($ActiveGA -and -not $IsBG -and $Type -eq 'user') { $Flags.Add('PermanentGA') }
        if ($ActiveGA -and $Type -eq 'servicePrincipal') { $Flags.Add('ServicePrincipalGA') }
        if ($P.onPremisesSyncEnabled -eq $true) { $Flags.Add('Synced') }
        if ($Type -eq 'user' -and $Mfa -eq $false) { $Flags.Add('NoMFA') }
        if ($Type -eq 'user' -and $Mfa -eq $true -and $Phish -eq $false) { $Flags.Add('NotPhishResistant') }
        if (-not $P -and -not $Foreign) { $Flags.Add('DeletedPrincipal') }
        # An organisation CIPP manages (e.g. Aspendora's own tenant) is ours; anything else is someone else's standing access.
        if ($Foreign -and $OrgOf[$Id] -ne $Partner -and -not $KnownOrgs[$OrgOf[$Id]]) { $Flags.Add('ForeignPartner') }
        $Out.Add([pscustomobject]@{
                Name = $P.displayName ?? $PartnerNames[$Id] ?? $Id; UserPrincipalName = $P.userPrincipalName; Type = $Type; Enabled = $P.accountEnabled
                BreakGlass = $IsBG
                Roles = (($Mine | ForEach-Object { "$($Names[$_.RoleId] ?? $_.RoleId)$(if ($_.Assignment -eq 'Eligible') { ' (eligible)' })$(if ($_.Scope -and $_.Scope -ne '/') { ' (scoped)' })" } | Sort-Object -Unique) -join ', ')
                MFA = $Mfa; PhishResistant = $Phish; Methods = $(if ($null -eq $Methods) { 'unreadable' } else { ($Methods | Sort-Object -Unique) -join ', ' })
                Flags = @($Flags)
            })
    }
    [pscustomobject]@{
        Tenant = $TenantFilter; GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o'); EligibleKnown = $EligibleKnown
        Admins = @($Out | Sort-Object @{ e = { -not ($_.Roles -match 'Global Administrator') } }, Name); Notes = @($Notes)
    }
}
