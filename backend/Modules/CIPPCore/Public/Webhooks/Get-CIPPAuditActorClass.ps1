function Get-CIPPAuditActorClass {
    <#
    .SYNOPSIS
        Classifies who performed an audit-logged action: the MSP, CIPP, Microsoft, another partner, an app or a tenant user.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-32). Test-CIPPAuditLogRules stamps the result on every record as
        CIPPActorClass and CIPPActorIsMSP so an audit-log rule can exclude the MSP's own admins with an ordinary
        condition (CIPPActorIsMSP eq False, or CIPPActorClass notin MSP, CIPP, Microsoft).

        How each class is recognised, from real records:
          MSP          A GDAP (delegated partner) admin of one of the MSP's own partner tenants. Exchange writes the
                       actor as '<customer>.onmicrosoft.com\tenant: <partner tenant id>, object: <partner user id>'
                       (UserType 2, OrganizationName = the customer). Entra writes the partner's home tenant as
                       ActorContextId. A legacy 'user_<hex>@<partner>.onmicrosoft.com' UPN counts when the object is
                       one of the partner users CIPP already knows (Get-CIPPPartnerUserLookup). CIPP's own delegated
                       calls go through GDAP as a partner user, so they land here too.
          CIPP         App-only calls by the CIPP application itself (AppId / ClientAppId / ApplicationId = the CIPP
                       app id, or a ServicePrincipal_ actor that maps to it).
          Microsoft    Exchange / Entra service actors: 'NT AUTHORITY\...', 'NT SERVICE\...', S-1-5-18, and UserType
                       3 (DcAdmin) or 4 (System).
          OtherPartner A delegated admin from a partner tenant that is NOT one of the MSP's own.
          App          Any other application / service principal acting in the tenant.
          Tenant       Everything else: an account of the customer tenant itself.

        MSP tenant ids are the CIPP partner tenant ($env:TenantID) plus any listed in the optional CIPP_MSP_TENANT_IDS
        app setting (comma separated). With neither available, any partner tenant is treated as the MSP rather than
        flooding every rule with alerts for the MSP's own work.
    .PARAMETER Record
        The raw auditData of the record (before GUID mapping).
    .PARAMETER MappedUserId
        CIPPUserId from the GUID mapping, when present (a resolved partner UPN or a service principal object).
    .PARAMETER MspTenantIds
        The MSP's partner tenant ids.
    .PARAMETER CippAppId
        The CIPP application id.
    .PARAMETER PartnerUserLookup
        Hashtable keyed by partner user object id (Get-CIPPPartnerUserLookup).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Record,
        $MappedUserId,
        [string[]]$MspTenantIds = @(),
        [string]$CippAppId,
        [hashtable]$PartnerUserLookup = @{}
    )

    $MspIds = @($MspTenantIds | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() })
    $Customer = ([string]$Record.OrganizationId).ToLowerInvariant()
    $UserId = [string]$Record.UserId
    $UserKey = [string]$Record.UserKey
    $Result = {
        param($Class, $Detail)
        [pscustomobject]@{ Class = $Class; IsMsp = ($Class -in @('MSP', 'CIPP')); Detail = $Detail }
    }
    $IsMspTenant = {
        param($TenantId)
        if ($MspIds.Count -eq 0) { return $true }
        $MspIds -contains ([string]$TenantId).ToLowerInvariant()
    }

    # CIPP itself, app-only.
    if ($CippAppId) {
        foreach ($Candidate in @($Record.AppId, $Record.ClientAppId, $Record.ApplicationId, $Record.ActorAppId)) {
            if ($Candidate -and [string]$Candidate -eq $CippAppId) { return & $Result 'CIPP' "CIPP application $CippAppId" }
        }
        if ($MappedUserId -and $MappedUserId -isnot [string] -and [string]$MappedUserId.appId -eq $CippAppId) {
            return & $Result 'CIPP' "CIPP service principal $($MappedUserId.displayName)"
        }
    }

    # Microsoft service actors.
    if ($UserId -match '^(NT AUTHORITY|NT SERVICE)\\' -or $UserId -eq 'S-1-5-18' -or [string]$Record.UserType -in @('3', '4', 'DcAdmin', 'System')) {
        return & $Result 'Microsoft' $UserId
    }

    # Exchange delegated partner admin. The regex object is used rather than -match so $Matches is never read.
    foreach ($Value in @($UserId, $UserKey)) {
        $PartnerMatch = [regex]::Match($Value, '\\tenant:\s*(?<Tenant>[0-9a-fA-F-]{36}),\s*object:\s*(?<Object>[0-9a-fA-F-]{36})')
        if ($PartnerMatch.Success) {
            $ActorTenant = $PartnerMatch.Groups['Tenant'].Value.ToLowerInvariant()
            $ActorObject = $PartnerMatch.Groups['Object'].Value
            if ($ActorTenant -ne $Customer) {
                $Who = if ($MappedUserId -is [string] -and $MappedUserId) { $MappedUserId } else { "object $ActorObject" }
                if (& $IsMspTenant $ActorTenant) { return & $Result 'MSP' "GDAP partner admin $Who (partner tenant $ActorTenant)" }
                return & $Result 'OtherPartner' "Partner admin $Who from a partner tenant that is not the MSP's ($ActorTenant)"
            }
        }
    }

    # Entra: the actor's home tenant.
    $ActorContext = ([string]$Record.ActorContextId).ToLowerInvariant()
    if ($ActorContext -and $Customer -and $ActorContext -ne $Customer) {
        if (& $IsMspTenant $ActorContext) { return & $Result 'MSP' "Partner admin $UserId (home tenant $ActorContext)" }
        return & $Result 'OtherPartner' "Admin $UserId from another tenant ($ActorContext)"
    }

    # Legacy partner UPN.
    $UpnMatch = [regex]::Match($UserId, '^user_(?<Hex>[0-9a-f]{32})@')
    if ($UpnMatch.Success) {
        $Hex = $UpnMatch.Groups['Hex'].Value
        $Guid = '{0}-{1}-{2}-{3}-{4}' -f $Hex.Substring(0, 8), $Hex.Substring(8, 4), $Hex.Substring(12, 4), $Hex.Substring(16, 4), $Hex.Substring(20, 12)
        if ($PartnerUserLookup.ContainsKey($Guid) -or $MspIds.Count -eq 0) { return & $Result 'MSP' "Partner admin $UserId" }
        return & $Result 'OtherPartner' "Partner-format account $UserId not known as an MSP user"
    }

    if ($UserId -like 'ServicePrincipal_*' -or [string]$Record.UserType -in @('5', '6', 'Application', 'ServicePrincipal')) {
        return & $Result 'App' $UserId
    }

    & $Result 'Tenant' $UserId
}
