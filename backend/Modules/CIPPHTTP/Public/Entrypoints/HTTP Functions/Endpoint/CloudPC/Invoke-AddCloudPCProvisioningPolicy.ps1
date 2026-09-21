using namespace System.Net

function Invoke-AddCloudPCProvisioningPolicy {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.ReadWrite
    .DESCRIPTION
        Creates a Windows 365 provisioning policy - the template Cloud PCs are built from.

        Creating the policy provisions nothing on its own. A Cloud PC is only created once the
        policy is assigned to a group whose members hold Windows 365 licences, which is a separate,
        deliberate step (ExecCloudPCProvisioningPolicyAssign). That separation is why this endpoint
        does not take a group: 'create' and 'start building machines for people' should not be one
        click.

        Domain join is either Entra-only (azureADJoin, needs a region) or hybrid
        (hybridAzureADJoin, needs an on-premises network connection). Supplying the wrong
        companion field is the usual way this call fails, so both are validated here rather than
        surfaced as a Graph schema error.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers

    $TenantFilter = $Request.Body.tenantFilter ?? $Request.Query.tenantFilter
    $DisplayName = $Request.Body.DisplayName
    $Description = $Request.Body.Description ?? ''
    $ImageId = $Request.Body.ImageId
    $ImageType = $Request.Body.ImageType ?? 'gallery'
    $ProvisioningType = $Request.Body.ProvisioningType ?? 'dedicated'
    $NamingTemplate = $Request.Body.CloudPcNamingTemplate
    $DomainJoinType = $Request.Body.DomainJoinType ?? 'azureADJoin'
    $OnPremisesConnectionId = $Request.Body.OnPremisesConnectionId
    $RegionName = $Request.Body.RegionName
    $Locale = $Request.Body.Locale ?? 'en-US'
    $EnableSingleSignOn = if ($null -eq $Request.Body.EnableSingleSignOn) { $true } else { ConvertTo-CIPPBoolean -Value $Request.Body.EnableSingleSignOn }

    try {
        if ([string]::IsNullOrWhiteSpace($TenantFilter)) { throw 'tenantFilter is required.' }
        if ([string]::IsNullOrWhiteSpace($DisplayName)) { throw 'DisplayName is required.' }
        if ([string]::IsNullOrWhiteSpace($ImageId)) { throw 'ImageId is required. Use ListCloudPCGalleryImages to get a valid image id.' }
        if ($ImageType -notin @('gallery', 'custom')) { throw "Invalid ImageType '$ImageType'. Allowed: gallery, custom." }
        if ($ProvisioningType -notin @('dedicated', 'shared', 'sharedByUser', 'sharedByEntraGroup')) {
            throw "Invalid ProvisioningType '$ProvisioningType'. Allowed: dedicated, shared, sharedByUser, sharedByEntraGroup."
        }
        if ($DomainJoinType -notin @('azureADJoin', 'hybridAzureADJoin')) {
            throw "Invalid DomainJoinType '$DomainJoinType'. Allowed: azureADJoin, hybridAzureADJoin."
        }
        if ($DomainJoinType -eq 'hybridAzureADJoin' -and [string]::IsNullOrWhiteSpace($OnPremisesConnectionId)) {
            throw 'hybridAzureADJoin requires OnPremisesConnectionId. Use ListCloudPCOnPremisesConnections; the connection must show healthCheckStatus "passed" or provisioning will fail.'
        }
        if ($DomainJoinType -eq 'azureADJoin' -and [string]::IsNullOrWhiteSpace($OnPremisesConnectionId) -and [string]::IsNullOrWhiteSpace($RegionName)) {
            throw 'azureADJoin requires either RegionName (Microsoft-hosted network) or OnPremisesConnectionId (your own vNet).'
        }

        $DomainJoinConfig = @{ domainJoinType = $DomainJoinType }
        if (-not [string]::IsNullOrWhiteSpace($OnPremisesConnectionId)) {
            $DomainJoinConfig.onPremisesConnectionId = $OnPremisesConnectionId
        } else {
            $DomainJoinConfig.regionName = $RegionName
            $DomainJoinConfig.regionGroup = $Request.Body.RegionGroup
        }

        $PolicyBody = @{
            displayName             = $DisplayName
            description             = $Description
            imageId                 = $ImageId
            imageType               = $ImageType
            provisioningType        = $ProvisioningType
            enableSingleSignOn      = $EnableSingleSignOn
            domainJoinConfigurations = @($DomainJoinConfig)
            windowsSetting          = @{ locale = $Locale }
        }
        if (-not [string]::IsNullOrWhiteSpace($NamingTemplate)) {
            $PolicyBody.cloudPcNamingTemplate = $NamingTemplate
        }

        $Json = $PolicyBody | ConvertTo-Json -Depth 10 -Compress
        $Created = New-GraphPOSTRequest -uri 'https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/provisioningPolicies' -tenantid $TenantFilter -body $Json -AsApp $true -ErrorAction Stop

        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Created Cloud PC provisioning policy '$DisplayName' ($($Created.id)). Not assigned to any group - no Cloud PCs will be built until it is." -Sev 'Info'

        $Body = [PSCustomObject]@{
            Results  = "Created provisioning policy '$DisplayName'. It is not assigned to any group yet, so no Cloud PCs will be provisioned until you assign it."
            PolicyId = $Created.id
            Policy   = $Created
        }
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Failed to create Cloud PC provisioning policy: $($ErrorMessage.NormalizedError)" -Sev Error -LogData $ErrorMessage
        $Body = [PSCustomObject]@{ Results = "Failed to create provisioning policy: $($ErrorMessage.NormalizedError)" }
        $StatusCode = [HttpStatusCode]::BadRequest
    }

    return ([HttpResponseContext]@{ StatusCode = $StatusCode; Body = $Body })
}
