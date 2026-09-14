Function Invoke-ListPrintConnectors {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.Printer.Read
    .DESCRIPTION
        Lists the Universal Print connectors registered in a tenant, including their reported location and application version.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter

    try {
        # Delegated only - see Invoke-ListPrinters for why -AsApp is never used here.
        $GraphRequest = New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/print/connectors' -tenantid $TenantFilter
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
