function Invoke-ListIntuneEffectivePolicy {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .SYNOPSIS
        Effective Intune policy for one device
    .DESCRIPTION
        For one device (Intune managed device id, Entra deviceId or Entra object id), lists every Intune policy and
        assigned app that targets it through the device's or its primary user's transitive group membership, All
        Devices or All Users, with the group it came through, the assignment filter and whether CIPP could evaluate
        it, the exclusion that cancels it (exclusions win), and the device's reported status where Intune exposes
        one. Policies for another platform are skipped. Also flags Settings Catalog settings set by two or more
        applicable policies (Conflict when the values differ, Overlap when they agree).
        Report only: nothing is changed. Aspendora fork addition (Vikunja CIPP-19).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    $DeviceId = [string]($Request.Query.DeviceId ?? $Request.Body.DeviceId)
    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Pick a single tenant.' } })
    }
    $Guid = [guid]::Empty
    if (-not $DeviceId -or -not [guid]::TryParse($DeviceId, [ref]$Guid)) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'DeviceId is required: an Intune managed device id or an Entra device id.' } })
    }
    try {
        $Report = Get-CIPPIntuneEffectivePolicy -TenantFilter $TenantFilter -DeviceId $DeviceId
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Report })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API $Request.Params.CIPPEndpoint -tenant $TenantFilter -message "Effective policy lookup failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $($ErrorMessage.NormalizedError)" } })
    }
}
