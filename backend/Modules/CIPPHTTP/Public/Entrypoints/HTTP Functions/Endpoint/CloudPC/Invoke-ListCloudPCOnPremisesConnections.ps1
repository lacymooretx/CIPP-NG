using namespace System.Net

function Invoke-ListCloudPCOnPremisesConnections {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .DESCRIPTION
        Lists the Azure network connections a Windows 365 provisioning policy can join Cloud PCs
        through: the subscription, vNet, subnet, region and the connection's health check status.

        healthCheckStatus is the field that matters operationally - a connection that is not
        'passed' will fail provisioning, so it is surfaced as a first-class column rather than
        buried in the detail pane.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter

    try {
        if ([string]::IsNullOrWhiteSpace($TenantFilter)) { throw 'tenantFilter is required.' }

        $Collection = Get-CIPPCloudPCCollection -TenantFilter $TenantFilter -Collection 'onPremisesConnections'

        $Connections = foreach ($Connection in $Collection.Items) {
            [PSCustomObject]@{
                displayName            = $Connection.displayName
                connectionType         = $Connection.connectionType ?? $Connection.type
                healthCheckStatus      = $Connection.healthCheckStatus
                virtualNetworkLocation = $Connection.virtualNetworkLocation
                subscriptionName       = $Connection.subscriptionName
                adDomainName           = $Connection.adDomainName
                organizationalUnit     = $Connection.organizationalUnit
                virtualNetworkId       = $Connection.virtualNetworkId
                subnetId               = $Connection.subnetId
                subscriptionId         = $Connection.subscriptionId
                id                     = $Connection.id
                cloudPcState           = $Collection.State
                cloudPcStateMessage    = $Collection.Message
            }
        }

        if (-not $Connections -and $Collection.State -ne 'Ok') {
            $Connections = @([PSCustomObject]@{
                    displayName         = 'No network connections'
                    cloudPcState        = $Collection.State
                    cloudPcStateMessage = $Collection.Message
                })
        }

        $Body = @($Connections)
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "ListCloudPCOnPremisesConnections failed: $($ErrorMessage.NormalizedError)" -Sev Error -LogData $ErrorMessage
        $Body = @([PSCustomObject]@{ cloudPcState = 'Error'; cloudPcStateMessage = $ErrorMessage.NormalizedError })
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return ([HttpResponseContext]@{ StatusCode = $StatusCode; Body = $Body })
}
