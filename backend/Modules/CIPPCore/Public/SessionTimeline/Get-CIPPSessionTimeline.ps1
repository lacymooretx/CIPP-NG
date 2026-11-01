function Get-CIPPSessionTimeline {
    <#
    .SYNOPSIS
        Reads a session timeline search started by Start-CIPPSessionTimelineSearch and returns the session's timeline.
    .DESCRIPTION
        Read only. Checks the Graph audit log query status; until it is 'succeeded' only the status comes back
        (Ready = false) so the page can poll. Once finished it reads every record, re-reads the session's sign-ins and
        hands both to ConvertTo-CIPPSessionTimeline, which keeps the records whose AADSessionId, SessionId, device
        SessionId or UniqueTokenId match the session and builds the timeline (US Central with UTC) and summary.

        Graph activity logs (MicrosoftGraphActivityLogs) are not included: they exist only when the tenant streams them
        to Log Analytics / storage / Event Hub through Entra diagnostic settings, and CIPP has no access to those.
        Aspendora fork addition (Vikunja CIPP-12).
    .PARAMETER TenantFilter
        Tenant default domain or id.
    .PARAMETER QueryId
        The audit log query id returned by Start-CIPPSessionTimelineSearch.
    .PARAMETER SessionId
        The sign-in sessionId to keep.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantFilter,
        [Parameter(Mandatory = $true)][string]$QueryId,
        [Parameter(Mandatory = $true)][string]$SessionId
    )

    $QueryGuid = [guid]::Empty
    if (-not [guid]::TryParse($QueryId.Trim(), [ref]$QueryGuid)) { throw "QueryId '$QueryId' is not a GUID." }
    $SessionGuid = [guid]::Empty
    if (-not [guid]::TryParse($SessionId.Trim(), [ref]$SessionGuid)) { throw "SessionId '$SessionId' is not a GUID." }

    $Query = New-GraphGetRequest -uri "https://graph.microsoft.com/beta/security/auditLog/queries/$($QueryGuid.ToString())" -tenantid $TenantFilter -AsApp $true -noPagination $true | Select-Object -First 1
    $Status = [string]$Query.status
    $Base = [ordered]@{
        QueryId                = $QueryGuid.ToString()
        SessionId              = $SessionGuid.ToString()
        Status                 = $Status
        Ready                  = $false
        ApproximateRecordCount = $Query.approximateReturnedRecordCount
        UserPrincipalName      = (@($Query.userPrincipalNameFilters) -join ', ')
        WindowStart            = ConvertTo-CIPPCentralTime -Value $Query.filterStartDateTime
        WindowEnd              = ConvertTo-CIPPCentralTime -Value $Query.filterEndDateTime
        TimeZone               = 'Times are US Central (America/Chicago) with UTC alongside.'
        Errors                 = @()
    }
    if ($Status -ne 'succeeded') {
        $Base.Message = switch ($Status) {
            'failed' { 'Microsoft reported the audit log search as failed. Start a new search.' }
            'cancelled' { 'The audit log search was cancelled. Start a new search.' }
            default { 'The audit log search is still running on Microsoft''s side. Check again in a few minutes.' }
        }
        return [pscustomobject]$Base
    }

    $Errors = [System.Collections.Generic.List[string]]::new()
    if ($Query.isRecordCountLimitExceeded -eq $true) { $Errors.Add('Microsoft capped the search at its record limit; narrow the time window for a complete timeline.') }

    $Records = @(Get-CippAuditLogSearchResults -TenantFilter $TenantFilter -QueryId $QueryGuid.ToString() | Where-Object { $_ })
    $SignIns = @()
    try {
        $Session = Get-CIPPSessionTimelineSignIns -TenantFilter $TenantFilter -SessionId $SessionGuid.ToString()
        $SignIns = @($Session.SignIns)
        if ($Session.Truncated) { $Errors.Add('The session has more than 999 sign-ins; only the newest 999 are shown and used for token matching.') }
    } catch {
        $Errors.Add("Sign-ins could not be read, so only AADSessionId/SessionId matches are shown: $((Get-CippException -Exception $_).NormalizedError)")
    }

    $Timeline = ConvertTo-CIPPSessionTimeline -Records $Records -SignIns $SignIns -SessionId $SessionGuid.ToString()
    $Base.Ready = $true
    $Base.Message = "$($Timeline.RecordsMatched) of $($Timeline.RecordsRead) audit records and $($Timeline.SignInCount) sign-ins belong to this session."
    $Base.Errors = @($Errors)
    foreach ($P in $Timeline.PSObject.Properties) {
        if ($P.Name -ne 'SessionId') { $Base[$P.Name] = $P.Value }
    }
    [pscustomobject]$Base
}
