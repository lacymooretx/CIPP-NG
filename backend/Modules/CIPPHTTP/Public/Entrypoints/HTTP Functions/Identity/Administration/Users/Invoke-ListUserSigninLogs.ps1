Function Invoke-ListUserSigninLogs {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.User.Read
    .DESCRIPTION
        Lists recent sign-in log entries for a specific Entra ID user, ordered by most recent.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $top = $Request.Query.top ? $Request.Query.top : 50


    # Interact with query parameters or the body of the request.
    $TenantFilter = $Request.Query.tenantFilter
    $UserID = $Request.Query.UserID
    # Aspendora fork: UserID may be a UPN. signIns has no UPN in userId, so "userId eq '<upn>'" never matches and
    # Graph scans the whole log until it times out (seen for MikeR@ir100.com, CW #60357). Filter on the right field.
    $SafeUser = ([string]$UserID).Replace("'", "''")
    $UserClause = if ([guid]::TryParse([string]$UserID, [ref][guid]::Empty)) { "userId eq '$SafeUser'" } else { "userPrincipalName eq '$SafeUser'" }
    $URI = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=($UserClause)&`$top=$top&`$orderby=createdDateTime desc"

    try {
        $Result = New-GraphGetRequest -uri $URI -tenantid $TenantFilter -noPagination $true -verbose
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Result = "Failed to retrieve Sign In report for user $UserID : Error: $($ErrorMessage.NormalizedError)"
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @($Result)
        })
}
