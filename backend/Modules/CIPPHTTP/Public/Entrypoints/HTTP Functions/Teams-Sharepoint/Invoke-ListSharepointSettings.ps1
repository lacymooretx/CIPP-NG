Function Invoke-ListSharepointSettings {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Sharepoint.Admin.Read
    .DESCRIPTION
        Retrieves SharePoint Online tenant-level settings and configuration.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)


    # Interact with query parameters or the body of the request.
    # Body fallback is ours: the MCP gateway sends params in the body, so query-only
    # reads returned every tenant's settings as null.
    $Tenant = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter
    # -AsApp is required: the delegated token lacks the SharePoint admin scope and the
    # call fails with a 500/UnknownError without it.
    $SharePointSettings = New-GraphGetRequest -tenantid $Tenant -Uri 'https://graph.microsoft.com/beta/admin/sharepoint/settings' -AsApp $true

    return ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = @($SharePointSettings)
        })

}
