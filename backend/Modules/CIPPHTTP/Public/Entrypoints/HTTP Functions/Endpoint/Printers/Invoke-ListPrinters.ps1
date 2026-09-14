Function Invoke-ListPrinters {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.Printer.Read
    .DESCRIPTION
        Lists the Universal Print printers registered in a tenant, including status, model and whether the printer is shared.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter

    try {
        # Deliberately delegated: Microsoft documents "Application: Not supported." for every
        # /print endpoint, so -AsApp returns 403 no matter which Printer.* app role is granted.
        # The caller's rights come from the GDAP Printer Administrator role instead.
        $GraphRequest = New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/print/printers' -tenantid $TenantFilter
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
