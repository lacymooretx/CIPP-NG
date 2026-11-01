function Get-CIPPUserRecentSessions {
    <#
    .SYNOPSIS
        Lists one user's recent Entra sign-in sessions (grouped by sessionId) so a session can be picked for tracing.
    .DESCRIPTION
        Read only. Reads the newest 999 interactive sign-ins of the user in the last Days (beta auditLogs/signIns) and
        groups them by sessionId: first and last sign-in (US Central with UTC), sign-in and failure counts, IP addresses,
        countries, apps and the newest user agent. Interactive only: a session always starts with an interactive sign-in,
        and non-interactive refreshes would swamp the page. Sign-ins without a sessionId (some legacy and service flows)
        are left out because they cannot be traced. Aspendora fork addition (Vikunja CIPP-12).
    .PARAMETER TenantFilter
        Tenant default domain or id.
    .PARAMETER UserPrincipalName
        The user's UPN or object id.
    .PARAMETER Days
        Days back, 1 to 30 (sign-ins are kept for 30 days). Default 7.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantFilter,
        [Parameter(Mandatory = $true)][string]$UserPrincipalName,
        [ValidateRange(1, 30)][int]$Days = 7
    )

    $Start = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $Who = $UserPrincipalName.Trim()
    $Guid = [guid]::Empty
    $UserClause = if ([guid]::TryParse($Who, [ref]$Guid)) { "userId eq '$($Guid.ToString())'" } else { "userPrincipalName eq '$($Who -replace "'", "''")'" }
    $Filter = "$UserClause and createdDateTime ge $Start"
    $Select = 'id,createdDateTime,userPrincipalName,appDisplayName,ipAddress,userAgent,status,location,sessionId'
    $Uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$([uri]::EscapeDataString($Filter))&`$select=$Select&`$top=999"
    $SignIns = @(New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -noPagination $true | Where-Object { $_ })

    ConvertTo-CIPPSessionList -SignIns $SignIns
}
