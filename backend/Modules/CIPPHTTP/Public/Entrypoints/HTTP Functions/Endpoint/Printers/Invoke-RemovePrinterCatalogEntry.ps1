Function Invoke-RemovePrinterCatalogEntry {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.Printer.ReadWrite
    .DESCRIPTION
        Removes a printer from a tenant's printer catalogue. This only deletes the CIPP catalogue record; it does not remove printers already installed on devices.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers

    $TenantFilter = $Request.Body.tenantFilter ?? $Request.Query.tenantFilter
    $ID = $Request.Body.id ?? $Request.Query.id

    if (!$ID) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ 'Results' = 'You must supply the id of the catalogue entry to remove' }
            })
    }

    try {
        $Tenant = Get-Tenants -TenantFilter $TenantFilter
        $CustomerId = $Tenant.customerId ?? $TenantFilter

        $Table = Get-CIPPTable -TableName 'PrinterCatalog'
        $Entity = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$CustomerId' and RowKey eq '$ID'"
        if (!$Entity) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::NotFound
                    Body       = @{ 'Results' = "No catalogue entry $ID for this tenant" }
                })
        }
        Remove-CIPPAzDataTableEntity @Table -Entity $Entity -Force

        $Result = "Removed printer '$($Entity.Name)' from the catalogue. Printers already installed on devices are untouched."
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Result -Sev 'Info'
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Result = "Failed to remove catalogue entry $ID. $($ErrorMessage.NormalizedError)"
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Result -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @{ 'Results' = $Result }
        })
}
