function Invoke-ListPersonalDevices {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.Device.Read
    .SYNOPSIS
        Personally owned Intune devices with each tenant's BYOD enrollment controls
    .DESCRIPTION
        Read only. Lists managed devices whose owner type is personal (device, OS, user, enrolled date, last sync,
        enrollment and join type, compliance, and whether a Windows device was Entra registered by adding a work account),
        plus a per-tenant summary with personalDeviceEnrollmentBlocked per platform from the default platform restriction
        and the "Disable MDM enrollment when adding work or school account" setting (isMdmEnrollmentDuringRegistrationDisabled).
        A single tenant is read live; AllTenants is read from the CIPP reporting cache. Aspendora fork addition (Vikunja CIPP-21).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    # The tenant to report on, or AllTenants to read every tenant from the CIPP reporting cache.
    $TenantFilter = $Request.Query.tenantFilter
    # Devices enrolled within this many days are flagged as new. Defaults to 30.
    $NewDays = if ($Request.Query.newDays -as [int]) { [int]$Request.Query.newDays } else { 30 }

    if (-not $TenantFilter) {
        return ([HttpResponseContext]@{
                StatusCode = [System.Net.HttpStatusCode]::BadRequest
                Body       = @{ Results = 'tenantFilter is required.' }
            })
    }

    try {
        $Body = Get-CIPPPersonalDevices -TenantFilter $TenantFilter -NewDays $NewDays
        $StatusCode = [System.Net.HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Failed to list personal devices: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [System.Net.HttpStatusCode]::InternalServerError
        $Body = @{ Results = "Failed to list personal devices: $($ErrorMessage.NormalizedError)" }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Body
        })
}
