Function Invoke-ExecDeployCatalogPrinter {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.Printer.ReadWrite
    .DESCRIPTION
        Deploys a catalogue printer to a tenant through Intune. Universal Print entries become a settings catalog policy; direct IP and print-server entries become an Intune platform script, because Intune has no configuration service provider for either.
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
                Body       = @{ 'Results' = 'You must supply the id of the catalogue entry to deploy' }
            })
    }

    try {
        $Tenant = Get-Tenants -TenantFilter $TenantFilter
        $CustomerId = $Tenant.customerId ?? $TenantFilter

        $Table = Get-CIPPTable -TableName 'PrinterCatalog'
        $Printer = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$CustomerId' and RowKey eq '$ID'"
        if (!$Printer) { throw "No catalogue entry $ID for this tenant" }

        $AssignTo = $Request.Body.AssignTo.value ?? $Request.Body.AssignTo ?? $Printer.AssignTo

        $Result = Set-CIPPCatalogPrinter -Printer $Printer -TenantFilter $TenantFilter -AssignTo $AssignTo -Headers $Headers -APIName $APIName

        # Stamp the catalogue so the UI can show what was last pushed and when.
        $Printer.LastDeployed = (Get-Date).ToUniversalTime().ToString('o')
        $Table.Force = $true
        Add-CIPPAzDataTableEntity @Table -Entity $Printer -Force

        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Result -Sev 'Info'
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Result = "Failed to deploy catalogue printer $ID. $($ErrorMessage.NormalizedError)"
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Result -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @{ 'Results' = $Result }
        })
}
