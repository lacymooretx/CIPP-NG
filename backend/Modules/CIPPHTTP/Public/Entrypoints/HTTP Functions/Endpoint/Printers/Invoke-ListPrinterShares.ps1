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
