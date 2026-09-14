Function Invoke-AddPrinterCatalogEntry {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.Printer.ReadWrite
    .DESCRIPTION
        Adds or updates a printer in a tenant's printer catalogue. Supply id to edit an existing entry. PrinterType must be UniversalPrint, DirectIP or ServerShare.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers

    $TenantFilter = $Request.Body.tenantFilter ?? $Request.Query.tenantFilter
    $Name = $Request.Body.Name
    $PrinterType = $Request.Body.PrinterType.value ?? $Request.Body.PrinterType

    if (!$Name -or !$PrinterType) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ 'Results' = 'You must supply both a Name and a PrinterType' }
            })
    }

    # Validate per type up front. Writing a half-specified entry would only fail later at deploy
    # time, on a different screen, with a less obvious message.
    switch ($PrinterType) {
        'UniversalPrint' {
            if (!$Request.Body.ShareId) {
                return ([HttpResponseContext]@{
                        StatusCode = [HttpStatusCode]::BadRequest
                        Body       = @{ 'Results' = 'A Universal Print entry requires a ShareId' }
                    })
            }
        }
        'DirectIP' {
            if (!$Request.Body.HostAddress -or !$Request.Body.DriverName) {
                return ([HttpResponseContext]@{
                        StatusCode = [HttpStatusCode]::BadRequest
                        Body       = @{ 'Results' = 'A direct IP entry requires a HostAddress and a DriverName' }
                    })
            }
            # A driver staged from an INF is useless without the path, and the failure would
            # otherwise surface on the device rather than here.
            $DriverSource = $Request.Body.DriverSource.value ?? $Request.Body.DriverSource ?? 'Inbox'
            if ($DriverSource -eq 'InfPath' -and !$Request.Body.DriverInfPath) {
                return ([HttpResponseContext]@{
                        StatusCode = [HttpStatusCode]::BadRequest
                        Body       = @{ 'Results' = 'A driver source of InfPath requires a DriverInfPath' }
                    })
            }
            if ($DriverSource -notin @('Inbox', 'Win32App', 'InfPath')) {
                return ([HttpResponseContext]@{
                        StatusCode = [HttpStatusCode]::BadRequest
                        Body       = @{ 'Results' = "Unknown DriverSource '$DriverSource'. Expected Inbox, Win32App or InfPath." }
                    })
            }
        }
        'ServerShare' {
            if (!$Request.Body.UNCPath) {
                return ([HttpResponseContext]@{
                        StatusCode = [HttpStatusCode]::BadRequest
                        Body       = @{ 'Results' = 'A server share entry requires a UNCPath' }
                    })
            }
        }
        default {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = @{ 'Results' = "Unknown PrinterType '$PrinterType'. Expected UniversalPrint, DirectIP or ServerShare." }
                })
        }
    }

    try {
        $Tenant = Get-Tenants -TenantFilter $TenantFilter
        $CustomerId = $Tenant.customerId ?? $TenantFilter

        # An id means edit in place; without one this is a new printer.
        $RowKey = $Request.Body.id ?? (New-Guid).GUID

        $Entity = @{
            PartitionKey = [string]$CustomerId
            RowKey       = [string]$RowKey
            Name         = [string]$Name
            PrinterType  = [string]$PrinterType
            ShareId      = [string]($Request.Body.ShareId ?? '')
            ShareName    = [string]($Request.Body.ShareName ?? '')
            HostAddress  = [string]($Request.Body.HostAddress ?? '')
            PortNumber   = [string]($Request.Body.PortNumber ?? '')
            DriverName   = [string]($Request.Body.DriverName ?? '')
            DriverSource = [string]($Request.Body.DriverSource.value ?? $Request.Body.DriverSource ?? 'Inbox')
            DriverInfPath = [string]($Request.Body.DriverInfPath ?? '')
            UNCPath      = [string]($Request.Body.UNCPath ?? '')
            Location     = [string]($Request.Body.Location ?? '')
            Comment      = [string]($Request.Body.Comment ?? '')
            AssignTo     = [string]($Request.Body.AssignTo.value ?? $Request.Body.AssignTo ?? '')
        }

        $Table = Get-CIPPTable -TableName 'PrinterCatalog'
        $Table.Force = $true
        Add-CIPPAzDataTableEntity @Table -Entity $Entity -Force

        $Result = "Saved printer '$Name' ($PrinterType) in the catalogue"
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Result -Sev 'Info'
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Result = "Failed to save printer '$Name'. $($ErrorMessage.NormalizedError)"
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Result -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @{ 'Results' = $Result }
        })
}
