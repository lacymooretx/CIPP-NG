function Invoke-ExecSessionTimelineSearch {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Security.Incident.ReadWrite
    .SYNOPSIS
        Start a Unified Audit Log search to trace everything one Entra sign-in session did
    .DESCRIPTION
        Takes the sessionId from a suspicious Entra sign-in, reads the session's sign-ins to find the user and when the
        session was used, and starts a Graph audit log search (security/auditLog/queries) for that user and window over
        Exchange, SharePoint, OneDrive, Teams and Entra logon records. Returns the query id; poll ListSessionTimeline with
        it to get the timeline once Microsoft finishes the search (usually 5-20 minutes). Creates a search only; changes
        no tenant configuration. Aspendora fork addition (Vikunja CIPP-12).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    # The tenant the session belongs to. AllTenants is not supported.
    $TenantFilter = $Request.Body.tenantFilter
    # The sessionId (GUID) from an Entra sign-in log entry.
    $SessionId = $Request.Body.sessionId
    # Optional user principal name to scope the search to. Defaults to the user on the session's sign-ins.
    $UserPrincipalName = $Request.Body.userPrincipalName
    # Optional window start: ISO 8601 or Unix seconds. Defaults to 15 minutes before the session's first sign-in.
    $StartTime = $Request.Body.startTime
    # Optional window end: ISO 8601 or Unix seconds. Defaults to 2 hours after the session's last sign-in.
    $EndTime = $Request.Body.endTime

    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{
                StatusCode = [System.Net.HttpStatusCode]::BadRequest
                Body       = @{ Results = 'Select a single tenant: a session belongs to one tenant.' }
            })
    }
    $Guid = [guid]::Empty
    if (-not $SessionId -or -not [guid]::TryParse(([string]$SessionId).Trim(), [ref]$Guid)) {
        return ([HttpResponseContext]@{
                StatusCode = [System.Net.HttpStatusCode]::BadRequest
                Body       = @{ Results = 'sessionId must be the GUID from an Entra sign-in (the Session ID field).' }
            })
    }

    # Unix seconds or ISO 8601; a time without an offset is read as UTC, not as the server's local time.
    $ToUtc = {
        param($Value)
        if ($null -eq $Value -or "$Value" -eq '') { return $null }
        if ("$Value" -match '^\d+$') { return [DateTime]::UnixEpoch.AddSeconds([long]"$Value") }
        if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
        $Parsed = [DateTimeOffset]::MinValue
        $Styles = [System.Globalization.DateTimeStyles]::AssumeUniversal
        if ([DateTimeOffset]::TryParse([string]$Value, [cultureinfo]::InvariantCulture, $Styles, [ref]$Parsed)) { return $Parsed.UtcDateTime }
        throw "Could not read '$Value' as a date and time."
    }

    try {
        $Params = @{ TenantFilter = $TenantFilter; SessionId = $Guid.ToString() }
        if ($UserPrincipalName) { $Params.UserPrincipalName = [string]($UserPrincipalName.value ?? $UserPrincipalName) }
        $Start = & $ToUtc $StartTime
        $End = & $ToUtc $EndTime
        if ($Start) { $Params.StartTime = $Start }
        if ($End) { $Params.EndTime = $End }

        $Result = Start-CIPPSessionTimelineSearch @Params
        if ($Result.QueryId) {
            Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Started session timeline search $($Result.QueryId) for session $($Result.SessionId) ($($Result.UserPrincipalName))" -Sev 'Info'
            $StatusCode = [System.Net.HttpStatusCode]::OK
        } else {
            Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Session timeline search was not created: $($Result.Message)" -Sev 'Warning'
            $StatusCode = [System.Net.HttpStatusCode]::BadGateway
        }
        $Body = $Result
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Failed to start the session timeline search: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [System.Net.HttpStatusCode]::BadRequest
        $Body = @{ Results = "Failed to start the session timeline search: $($ErrorMessage.NormalizedError)" }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Body
        })
}
