function Invoke-ListDeviceEffectivePolicy {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .SYNOPSIS
        Effective Intune policy for one managed device, by id or serial
    .DESCRIPTION
        The effective-policy evaluation behind ListIntuneEffectivePolicy (CIPP-19), for callers holding a serial number
        or wanting distinct answers for a bad request (400), an unknown device (404) and an ambiguous serial (409). This
        is a simulation from assignments, groups and filters, not what the device itself reports. Devices that are not
        Intune-managed return 404 here; ListIntuneEffectivePolicy shows what would target those.
        Partial failures set Partial and list the Errors. Report only: nothing is changed. Aspendora fork addition.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    $DeviceId = [string]($Request.Query.DeviceId ?? $Request.Body.DeviceId)
    $SerialNumber = [string]($Request.Query.SerialNumber ?? $Request.Body.SerialNumber)

    try {
        $Resolved = Resolve-CIPPManagedDevice -TenantFilter $TenantFilter -DeviceId $DeviceId -SerialNumber $SerialNumber
        if ($Resolved.Status -ne 'Found') {
            return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]$Resolved.HttpStatus; Body = @{ Results = $Resolved.Message; Candidates = @($Resolved.Candidates); Detail = $Resolved.Detail } })
        }
        $Report = Get-CIPPIntuneEffectivePolicy -TenantFilter $TenantFilter -DeviceId $Resolved.Device.ManagedDeviceId
        $Report.Device | Add-Member -NotePropertyName MatchedBy -NotePropertyValue $Resolved.Device.MatchedBy -Force
        $Report | Add-Member -NotePropertyName Partial -NotePropertyValue (@($Report.Errors).Count -gt 0) -Force
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Report })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API $Request.Params.CIPPEndpoint -tenant $TenantFilter -message "Device effective policy lookup failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $($ErrorMessage.NormalizedError)" } })
    }
}
