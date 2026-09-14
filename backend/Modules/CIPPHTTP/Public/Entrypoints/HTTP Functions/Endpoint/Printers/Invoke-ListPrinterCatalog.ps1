Function Invoke-ListPrinterCatalog {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.Printer.Read
    .DESCRIPTION
        Lists the printer catalogue for a tenant. The catalogue holds every printer CIPP manages for that customer, whether it is a Universal Print share, a direct IP printer or a mapped print-server queue.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter

    try {
        # Key on customerId rather than the domain name, so a tenant that renames its default
        # domain does not orphan its catalogue.
        $Tenant = Get-Tenants -TenantFilter $TenantFilter
        $CustomerId = $Tenant.customerId ?? $TenantFilter

        $Table = Get-CIPPTable -TableName 'PrinterCatalog'
        $Entries = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$CustomerId'"

        $Results = foreach ($Entry in $Entries) {
            [PSCustomObject]@{
                id          = $Entry.RowKey
                Name        = $Entry.Name
                PrinterType = $Entry.PrinterType
                ShareId     = $Entry.ShareId
                ShareName   = $Entry.ShareName
                HostAddress = $Entry.HostAddress
                PortNumber  = $Entry.PortNumber
                DriverName  = $Entry.DriverName
                DriverSource = $Entry.DriverSource
                DriverInfPath = $Entry.DriverInfPath
                UNCPath     = $Entry.UNCPath
                Location    = $Entry.Location
                Comment     = $Entry.Comment
                AssignTo    = $Entry.AssignTo
                LastDeployed = $Entry.LastDeployed
                Updated     = $Entry.Timestamp
            }
        }
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        $StatusCode = [HttpStatusCode]::InternalServerError
        $Results = $ErrorMessage
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @($Results)
        })
}
