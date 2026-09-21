using namespace System.Net

function Invoke-ListCloudPCs {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .DESCRIPTION
        Lists a tenant's Windows 365 Cloud PCs: who each one belongs to, its SKU, provisioning
        policy, status, disk encryption state and grace period.

        Reads deviceManagement/virtualEndpoint/cloudPCs app-only. This tree cannot be read with a
        delegated token at all, so ListGraphRequest is not an alternative.

        A tenant with no Windows 365 licence is reported as NotLicensed with an empty list rather
        than as an error - the Graph API returns an access denial in that case, which is
        indistinguishable from a real permission fault. See Get-CIPPCloudPCCollection.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter

    try {
        if ([string]::IsNullOrWhiteSpace($TenantFilter)) { throw 'tenantFilter is required.' }

        $Collection = Get-CIPPCloudPCCollection -TenantFilter $TenantFilter -Collection 'cloudPCs'

        $CloudPCs = foreach ($PC in $Collection.Items) {
            [PSCustomObject]@{
                displayName           = $PC.displayName
                userPrincipalName     = $PC.userPrincipalName
                status                = $PC.status
                servicePlanName       = $PC.servicePlanName
                provisioningPolicyName = $PC.provisioningPolicyName
                imageDisplayName      = $PC.imageDisplayName
                managedDeviceName     = $PC.managedDeviceName
                diskEncryptionState   = $PC.diskEncryptionState
                provisioningType      = $PC.provisioningType
                gracePeriodEndDateTime = $PC.gracePeriodEndDateTime
                lastModifiedDateTime  = $PC.lastModifiedDateTime
                id                    = $PC.id
                managedDeviceId       = $PC.managedDeviceId
                aadDeviceId           = $PC.aadDeviceId
                cloudPcState          = $Collection.State
                cloudPcStateMessage   = $Collection.Message
            }
        }

        # A NotLicensed / AccessDenied tenant has no rows, so carry the explanation on a single
        # placeholder row - otherwise the table renders empty and says nothing about why.
        if (-not $CloudPCs -and $Collection.State -ne 'Ok') {
            $CloudPCs = @([PSCustomObject]@{
                    displayName         = 'No Cloud PCs'
                    cloudPcState        = $Collection.State
                    cloudPcStateMessage = $Collection.Message
                })
        }

        $Body = @($CloudPCs)
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "ListCloudPCs failed: $($ErrorMessage.NormalizedError)" -Sev Error -LogData $ErrorMessage
        $Body = @([PSCustomObject]@{ cloudPcState = 'Error'; cloudPcStateMessage = $ErrorMessage.NormalizedError })
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return ([HttpResponseContext]@{ StatusCode = $StatusCode; Body = $Body })
}
