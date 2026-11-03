function Invoke-ListDeviceComplianceState {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .SYNOPSIS
        Compliance policy state for one device
    .DESCRIPTION
        For one device (DeviceId: Intune managed device id or Entra deviceId, or SerialNumber), returns the device's
        overall compliance state and grace period, and each compliance policy with its worst state across user and system
        contexts. Non-compliant policies list their failing settings; IncludeSettings=true returns every setting.

        A device that cannot be resolved is a 400, 404 or 409. A failed state read is a 500, never an empty list; partial
        failures set Partial and list the Errors. Report only: nothing is changed. Aspendora fork addition.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    $DeviceId = [string]($Request.Query.DeviceId ?? $Request.Body.DeviceId)
    $SerialNumber = [string]($Request.Query.SerialNumber ?? $Request.Body.SerialNumber)
    $IncludeSettings = $Request.Query.IncludeSettings -eq $true -or $Request.Body.IncludeSettings -eq $true

    try {
        $Resolved = Resolve-CIPPManagedDevice -TenantFilter $TenantFilter -DeviceId $DeviceId -SerialNumber $SerialNumber
        if ($Resolved.Status -ne 'Found') {
            return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]$Resolved.HttpStatus; Body = @{ Results = $Resolved.Message; Candidates = @($Resolved.Candidates); Detail = $Resolved.Detail } })
        }

        $States = Get-CIPPManagedDevicePolicyStates -TenantFilter $TenantFilter -ManagedDeviceId $Resolved.Device.ManagedDeviceId -Collection 'deviceCompliancePolicyStates' -IncludeAllSettings:$IncludeSettings
        $Results = @($States.Results)
        $Body = @{
            Device  = $Resolved.Device
            Results = $Results
            Summary = @{
                Policies = $Results.Count
                Failing  = @($Results | Where-Object State -In @('error', 'conflict', 'nonCompliant')).Count
                ByState  = @($Results | Group-Object State | Sort-Object Name | ForEach-Object { [pscustomobject]@{ State = $_.Name; Count = $_.Count } })
            }
            Partial = @($States.Errors).Count -gt 0
            Errors  = @($States.Errors)
        }
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Body })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API $Request.Params.CIPPEndpoint -tenant $TenantFilter -message "Device compliance state lookup failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $($ErrorMessage.NormalizedError)" } })
    }
}
