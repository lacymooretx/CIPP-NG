using namespace System.Net

function Invoke-ListCloudPCProvisioningPolicies {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .DESCRIPTION
        Lists a tenant's Windows 365 provisioning policies - the templates Cloud PCs are created
        from: gallery or custom image, naming template, single sign-on, domain-join type and the
        on-premises network connection each one uses.

        Reads deviceManagement/virtualEndpoint/provisioningPolicies app-only, with the same
        licence-versus-access handling as ListCloudPCs.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter

    try {
        if ([string]::IsNullOrWhiteSpace($TenantFilter)) { throw 'tenantFilter is required.' }

        $Collection = Get-CIPPCloudPCCollection -TenantFilter $TenantFilter -Collection 'provisioningPolicies'

        $Policies = foreach ($Policy in $Collection.Items) {
            $DomainJoin = @($Policy.domainJoinConfigurations) | Select-Object -First 1
            [PSCustomObject]@{
                displayName          = $Policy.displayName
                description          = $Policy.description
                imageDisplayName     = $Policy.imageDisplayName
                imageType            = $Policy.imageType
                provisioningType     = $Policy.provisioningType
                cloudPcNamingTemplate = $Policy.cloudPcNamingTemplate
                enableSingleSignOn   = $Policy.enableSingleSignOn
                domainJoinType       = $DomainJoin.domainJoinType
                onPremisesConnectionId = $DomainJoin.onPremisesConnectionId
                regionName           = $DomainJoin.regionName
                managedBy            = $Policy.managedBy
                lastModifiedDateTime = $Policy.lastModifiedDateTime
                id                   = $Policy.id
                cloudPcState         = $Collection.State
                cloudPcStateMessage  = $Collection.Message
            }
        }

        if (-not $Policies -and $Collection.State -ne 'Ok') {
            $Policies = @([PSCustomObject]@{
                    displayName         = 'No provisioning policies'
                    cloudPcState        = $Collection.State
                    cloudPcStateMessage = $Collection.Message
                })
        }

        $Body = @($Policies)
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "ListCloudPCProvisioningPolicies failed: $($ErrorMessage.NormalizedError)" -Sev Error -LogData $ErrorMessage
        $Body = @([PSCustomObject]@{ cloudPcState = 'Error'; cloudPcStateMessage = $ErrorMessage.NormalizedError })
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return ([HttpResponseContext]@{ StatusCode = $StatusCode; Body = $Body })
}
