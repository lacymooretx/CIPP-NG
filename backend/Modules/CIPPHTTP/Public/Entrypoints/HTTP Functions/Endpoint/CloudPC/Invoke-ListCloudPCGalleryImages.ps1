using namespace System.Net

function Invoke-ListCloudPCGalleryImages {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .DESCRIPTION
        Lists the Windows 365 gallery images a provisioning policy can be built from, so the
        policy form can offer real image IDs instead of asking an operator to type one.

        Defaults to supported images only. An unsupported or soon-to-expire image still provisions
        but stops receiving updates, so offering the full list by default invites picking one by
        accident; pass IncludeUnsupported=true to see them.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter
    $IncludeUnsupported = ConvertTo-CIPPBoolean -Value ($Request.Query.IncludeUnsupported ?? $Request.Body.IncludeUnsupported)

    try {
        if ([string]::IsNullOrWhiteSpace($TenantFilter)) { throw 'tenantFilter is required.' }

        $Collection = Get-CIPPCloudPCCollection -TenantFilter $TenantFilter -Collection 'galleryImages'

        $Images = foreach ($Image in $Collection.Items) {
            if (-not $IncludeUnsupported -and $Image.status -and $Image.status -ne 'supported') { continue }
            [PSCustomObject]@{
                displayName             = $Image.displayName
                status                  = $Image.status
                recommendedSku          = $Image.recommendedSku
                publisherName           = $Image.publisherName
                offerName               = $Image.offerName
                skuName                 = $Image.skuName
                expirationDate          = $Image.expirationDate
                endOfSupportDate        = $Image.endOfSupportDate
                id                      = $Image.id
                cloudPcState            = $Collection.State
                cloudPcStateMessage     = $Collection.Message
            }
        }

        if (-not $Images -and $Collection.State -ne 'Ok') {
            $Images = @([PSCustomObject]@{
                    displayName         = 'No gallery images'
                    cloudPcState        = $Collection.State
                    cloudPcStateMessage = $Collection.Message
                })
        }

        $Body = @($Images)
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "ListCloudPCGalleryImages failed: $($ErrorMessage.NormalizedError)" -Sev Error -LogData $ErrorMessage
        $Body = @([PSCustomObject]@{ cloudPcState = 'Error'; cloudPcStateMessage = $ErrorMessage.NormalizedError })
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return ([HttpResponseContext]@{ StatusCode = $StatusCode; Body = $Body })
}
