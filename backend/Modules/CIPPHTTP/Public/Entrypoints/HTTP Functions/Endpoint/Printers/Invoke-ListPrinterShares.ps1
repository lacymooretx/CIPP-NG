Function Invoke-ListPrinterShares {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.Printer.Read
    .DESCRIPTION
        Lists Universal Print printer shares in a tenant. Pass ShareId to expand the users and groups allowed to print to a single share.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter
    $ShareId = $Request.Query.ShareId ?? $Request.Body.ShareId

    try {
        # Delegated only - see Invoke-ListPrinters for why -AsApp is never used here.
        if ($ShareId) {
            $Uri = "https://graph.microsoft.com/v1.0/print/shares/$ShareId`?`$expand=allowedUsers,allowedGroups"
        } else {
            $Uri = 'https://graph.microsoft.com/v1.0/print/shares'
        }
        # Graph returns only id, displayName, manufacturer, model and location when the signed-in
        # identity is not a Printer Administrator, so a sparse row here means missing GDAP rights
        # rather than an empty share.
        $GraphRequest = New-GraphGetRequest -uri $Uri -tenantid $TenantFilter
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        $StatusCode = [HttpStatusCode]::Forbidden
        $GraphRequest = $ErrorMessage
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @($GraphRequest)
        })
}
