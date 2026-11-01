function Get-CIPPSessionTimelineSignIns {
    <#
    .SYNOPSIS
        Reads the Entra sign-ins (interactive and non-interactive) that belong to one sign-in session.
    .DESCRIPTION
        Read only. beta auditLogs/signIns supports `sessionId eq '<guid>'` (verified 2026-11-01 against a live tenant);
        without a signInEventTypes clause Graph returns interactive sign-ins only, so the filter asks for both
        interactiveUser and nonInteractiveUser. A long-lived session refreshes tokens every few minutes, so one page of
        the newest 999 is read and Truncated says when there were more. When truncated, the oldest sign-in of the session
        is fetched separately so the caller still knows when the session started.

        Each sign-in's uniqueTokenIdentifier is the same value the Unified Audit Log stores as
        AppAccessContext.UniqueTokenId (verified 2026-11-01), which is how audit records without an AADSessionId are
        tied back to the session.

        Sign-ins are kept for 30 days and need Entra ID P1. Aspendora fork addition (Vikunja CIPP-12).
    .PARAMETER TenantFilter
        Tenant default domain or id.
    .PARAMETER SessionId
        The sign-in sessionId (a GUID). Validated as a GUID before it goes into the OData filter.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantFilter,
        [Parameter(Mandatory = $true)][string]$SessionId
    )

    $Guid = [guid]::Empty
    if (-not [guid]::TryParse($SessionId.Trim(), [ref]$Guid)) { throw "SessionId '$SessionId' is not a GUID." }
    $Id = $Guid.ToString()

    $Select = 'id,createdDateTime,userPrincipalName,userId,appDisplayName,resourceDisplayName,ipAddress,userAgent,status,location,signInEventTypes,isInteractive,uniqueTokenIdentifier,sessionId,clientAppUsed,conditionalAccessStatus,riskLevelDuringSignIn,correlationId'
    $Filter = "sessionId eq '$Id' and (signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser'))"
    $Base = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$([uri]::EscapeDataString($Filter))&`$select=$Select"

    $SignIns = [System.Collections.Generic.List[object]]::new()
    foreach ($S in @(New-GraphGetRequest -uri "$Base&`$top=999" -tenantid $TenantFilter -noPagination $true)) {
        if ($S) { $SignIns.Add($S) }
    }
    $Truncated = $SignIns.Count -ge 999
    $Oldest = $null
    if ($Truncated) {
        # Only the newest 999 came back; ask for the very first one so the search window still starts at the session start.
        try {
            $Oldest = @(New-GraphGetRequest -uri "$Base&`$orderby=createdDateTime asc&`$top=1" -tenantid $TenantFilter -noPagination $true) | Select-Object -First 1
        } catch {
            $Oldest = $null
        }
    }

    [pscustomobject]@{
        SessionId = $Id
        SignIns   = $SignIns
        Truncated = $Truncated
        Oldest    = $Oldest
    }
}
