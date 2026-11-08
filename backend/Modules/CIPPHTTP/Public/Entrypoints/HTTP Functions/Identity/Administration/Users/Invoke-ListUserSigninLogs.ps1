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
    # Aspendora fork: UserID may be a UPN (CW #60357). signIns only indexes userId: "userId eq '<upn>'" never matches,
    # and "userPrincipalName eq" scans the log and times out (verified live 2026-11-07). Resolve a UPN to its object
    # id first. No $orderby: signIns is already newest first.
    $ResolvedId = [string]$UserID
    if (-not [guid]::TryParse($ResolvedId, [ref][guid]::Empty)) {
        $ResolvedId = try {
            [string](New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($ResolvedId))?`$select=id" -tenantid $TenantFilter -noPagination $true).id
        } catch { '' }
    }
    $URI = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=(userId eq '$($ResolvedId.Replace("'", "''"))')&`$top=$top"

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
