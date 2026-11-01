function Invoke-ListSessionTimeline {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Security.Incident.Read
    .SYNOPSIS
        Timeline of everything one Entra sign-in session did, or a user's recent sessions to pick from
    .DESCRIPTION
        Read only. With queryId and sessionId: polls the audit log search started by ExecSessionTimelineSearch. While
        Microsoft is still running it, returns Ready = false and the status. Once finished, returns the session's sign-ins
        and every Exchange, SharePoint, OneDrive, Teams and Entra logon audit record whose AADSessionId, SessionId, device
        SessionId or UniqueTokenId matches the session, as one timeline in US Central with UTC alongside (workload,
        operation, object as message id / folder path or file path - never mail subjects - client IP, user agent, how it
        matched), plus counts per workload and operation, per IP, and highlights (mails read and sent, files accessed and
        downloaded, shares created, inbox rules changed, ...).
        With userPrincipalName instead: lists the user's interactive sign-in sessions in the last days (default 7) with
        first/last sign-in, IPs, countries and apps, so the suspicious one can be picked.
        Graph activity logs are not included (they need Log Analytics). Aspendora fork addition (Vikunja CIPP-12).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    # The tenant to read. AllTenants is not supported.
    $TenantFilter = $Request.Query.tenantFilter
    # The audit log query id returned by ExecSessionTimelineSearch.
    $QueryId = $Request.Query.queryId
    # The sign-in sessionId (GUID) being traced. Required with queryId.
    $SessionId = $Request.Query.sessionId
    # List this user's recent sessions instead of a timeline (UPN or object id).
    $UserPrincipalName = $Request.Query.userPrincipalName
    # Days back for the recent-session list, 1 to 30. Defaults to 7.
    $Days = if ($Request.Query.days -as [int]) { [math]::Min(30, [math]::Max(1, [int]$Request.Query.days)) } else { 7 }

    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{
                StatusCode = [System.Net.HttpStatusCode]::BadRequest
                Body       = @{ Results = 'Select a single tenant: a session belongs to one tenant.' }
            })
    }

    try {
        if ($QueryId) {
            if (-not $SessionId) {
                return ([HttpResponseContext]@{
                        StatusCode = [System.Net.HttpStatusCode]::BadRequest
                        Body       = @{ Results = 'sessionId is required with queryId.' }
                    })
            }
            $Body = Get-CIPPSessionTimeline -TenantFilter $TenantFilter -QueryId $QueryId -SessionId $SessionId
        } elseif ($UserPrincipalName) {
            $Sessions = @(Get-CIPPUserRecentSessions -TenantFilter $TenantFilter -UserPrincipalName $UserPrincipalName -Days $Days)
            $Body = @{ Results = $Sessions; Days = $Days }
        } else {
            return ([HttpResponseContext]@{
                    StatusCode = [System.Net.HttpStatusCode]::BadRequest
                    Body       = @{ Results = 'Pass queryId and sessionId for a timeline, or userPrincipalName for recent sessions.' }
                })
        }
        $StatusCode = [System.Net.HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Failed to read the session timeline: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [System.Net.HttpStatusCode]::InternalServerError
        $Body = @{ Results = "Failed to read the session timeline: $($ErrorMessage.NormalizedError)" }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Body
        })
}
