Function Invoke-ListPrintSettings {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.Printer.Read
    .DESCRIPTION
        Retrieves the tenant-wide Universal Print service settings, such as whether document conversion is enabled.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter

    try {
        # Delegated only - see Invoke-ListPrinters for why -AsApp is never used here.
        $GraphRequest = New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/print/settings' -tenantid $TenantFilter
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        $StatusCode = [HttpStatusCode]::Forbidden
        # Universal Print answers every authorization failure with the same "required security
        # scopes" text, which sends people hunting for a missing permission that is already
        # granted. Say what is actually wrong.
        if ($ErrorMessage -match 'security scopes') {
            $ErrorMessage = "$ErrorMessage -- Universal Print does not support partner delegated (GDAP) access: it is absent from the GDAP supported-workloads list, its Graph APIs publish no application permissions, and the GDAP identity is an external identity that cannot hold the Universal Print licence the service requires. Manage Universal Print printers in the customer tenant directly. CIPP can still DEPLOY Universal Print printers to users via the Intune settings catalog."
        }
        $GraphRequest = $ErrorMessage
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @($GraphRequest)
        })
}
