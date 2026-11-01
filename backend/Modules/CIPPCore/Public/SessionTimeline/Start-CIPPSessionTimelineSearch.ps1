function Start-CIPPSessionTimelineSearch {
    <#
    .SYNOPSIS
        Starts the Unified Audit Log search that Get-CIPPSessionTimeline later filters down to one sign-in session.
    .DESCRIPTION
        Changes no tenant configuration. The UAL has no server-side session filter, so this creates a Graph
        security/auditLog/queries search scoped to the session's user and time window and the workloads that carry a
        session id; Get-CIPPSessionTimeline then keeps only the records whose session identifiers match.

        1. Reads the session's sign-ins (Get-CIPPSessionTimelineSignIns) to learn the user and when the session was used.
        2. User: UserPrincipalName if given, otherwise the user on the session's sign-ins. Without either it stops: a
           tenant-wide search is far too large to filter client-side.
        3. Window: StartTime/EndTime if given, otherwise from 15 minutes before the first sign-in to 2 hours after the
           last one (access tokens stay valid for 60-90 minutes after the last refresh), never later than now, at most
           31 days (sign-ins only go back 30).
        4. Creates the query through New-CippAuditLogSearch, which handles audit-disabled tenants and transient
           Microsoft errors and lists the search on the Audit Log Searches page.

        Searches typically take 5-20 minutes to finish on Microsoft's side. Aspendora fork addition (Vikunja CIPP-12).
    .PARAMETER TenantFilter
        Tenant default domain or id.
    .PARAMETER SessionId
        The sessionId from an Entra sign-in (auditLogs/signIns).
    .PARAMETER UserPrincipalName
        Optional user to scope the search to; defaults to the user on the session's sign-ins.
    .PARAMETER StartTime
        Optional window start. Defaults from the sign-ins (see above).
    .PARAMETER EndTime
        Optional window end. Defaults from the sign-ins (see above).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantFilter,
        [Parameter(Mandatory = $true)][string]$SessionId,
        [string]$UserPrincipalName,
        [Nullable[datetime]]$StartTime,
        [Nullable[datetime]]$EndTime
    )

    # The record types that carry AADSessionId / SessionId / UniqueTokenId (see ConvertTo-CIPPSessionTimeline).
    $RecordTypes = @(
        'exchangeItem', 'exchangeItemGroup', 'exchangeItemAggregated', 'exchangeAdmin',
        'sharePointFileOperation', 'sharePointSharingOperation', 'sharePoint', 'oneDrive',
        'microsoftTeams', 'azureActiveDirectoryStsLogon'
    )

    $Errors = [System.Collections.Generic.List[string]]::new()
    $Guid = [guid]::Empty
    if (-not [guid]::TryParse($SessionId.Trim(), [ref]$Guid)) { throw "SessionId '$SessionId' is not a GUID." }
    # A tenant without Entra ID P1 (or with sign-ins older than 30 days) cannot read the sign-ins. With a user and a
    # window given the audit search still works, so only stop below if they are missing.
    try {
        $Session = Get-CIPPSessionTimelineSignIns -TenantFilter $TenantFilter -SessionId $Guid.ToString()
    } catch {
        $Errors.Add("The session's sign-ins could not be read: $((Get-CippException -Exception $_).NormalizedError)")
        $Session = [pscustomobject]@{ SessionId = $Guid.ToString(); SignIns = @(); Truncated = $false; Oldest = $null }
    }
    $SignIns = @($Session.SignIns)

    $Upn = if ($UserPrincipalName) { $UserPrincipalName.Trim() } else { $null }
    if (-not $Upn -and $SignIns.Count -gt 0) {
        $Upn = @($SignIns | Where-Object { $_.userPrincipalName } | Group-Object -Property userPrincipalName | Sort-Object -Property Count -Descending)[0].Name
    }
    if (-not $Upn) {
        throw 'No sign-ins were found for this session in the last 30 days, so the user is unknown. Enter the user principal name (and a time window) and start again.'
    }

    $Now = (Get-Date).ToUniversalTime()
    $SignInTimes = [System.Collections.Generic.List[datetime]]::new()
    foreach ($S in @($SignIns) + @($Session.Oldest)) {
        if (-not $S) { continue }
        $C = ConvertTo-CIPPCentralTime -Value $S.createdDateTime
        if ($C) { $SignInTimes.Add([datetime]::Parse($C.Utc, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)) }
    }
    $SortedTimes = @($SignInTimes | Sort-Object)

    if ($StartTime) {
        $WindowStart = $StartTime.Value.ToUniversalTime()
    } elseif ($SortedTimes.Count -gt 0) {
        $WindowStart = $SortedTimes[0].AddMinutes(-15)
    } else {
        throw 'No sign-ins were found for this session, so the time window is unknown. Enter a start and end time.'
    }
    if ($EndTime) {
        $WindowEnd = $EndTime.Value.ToUniversalTime()
    } elseif ($SortedTimes.Count -gt 0) {
        $WindowEnd = $SortedTimes[-1].AddHours(2)
    } else {
        $WindowEnd = $Now
    }
    if ($WindowEnd -gt $Now) { $WindowEnd = $Now }
    if ($WindowEnd -le $WindowStart) { throw 'The end time must be after the start time.' }
    if (($WindowEnd - $WindowStart).TotalDays -gt 31) {
        $WindowStart = $WindowEnd.AddDays(-31)
        $Errors.Add('The window was longer than 31 days and was cut to the last 31 days before the end time.')
    }
    if ($Session.Truncated) {
        $Errors.Add('The session has more than 999 sign-ins; only the newest 999 are used to match audit records by token.')
    }

    $ShortId = ([string]$Session.SessionId).Substring(0, 8)
    $Search = New-CippAuditLogSearch -DisplayName "CIPP Session Timeline - $ShortId - $Upn" -TenantFilter $TenantFilter `
        -StartTime $WindowStart -EndTime $WindowEnd -RecordTypeFilters $RecordTypes -UserPrincipalNameFilters @($Upn)

    [pscustomobject]@{
        QueryId           = $Search.id
        Status            = [string]$Search.status
        Message           = if ($Search.id) { "Audit log search started. Microsoft usually needs 5-20 minutes to finish it." } else { [string]$Search.message }
        SessionId         = $Session.SessionId
        UserPrincipalName = $Upn
        WindowStart       = ConvertTo-CIPPCentralTime -Value $WindowStart
        WindowEnd         = ConvertTo-CIPPCentralTime -Value $WindowEnd
        SignInCount       = $SignIns.Count
        RecordTypes       = $RecordTypes
        Errors            = @($Errors)
    }
}
