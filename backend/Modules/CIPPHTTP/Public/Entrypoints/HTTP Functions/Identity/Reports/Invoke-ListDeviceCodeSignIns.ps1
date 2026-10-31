function Invoke-ListDeviceCodeSignIns {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.AuditLog.Read
    .SYNOPSIS
        Device-code sign-ins for a tenant, summarised per user, app and device
    .DESCRIPTION
        Reads the tenant's sign-in logs for authenticationProtocol 'deviceCode' over the last Days days (default 30,
        maximum 30), one day at a time because the filter is unindexed and times out over long windows. Returns a
        summary per user + app + device (count, successes, failures, first/last seen in US Central, IPs, locations)
        so legitimate device-code use can be excluded before the CIPP-8 "block device code flow" policy is enforced.
        Tenants without Entra ID P1 return Licensed = false and a message instead of an error.
        Report only: nothing is changed. Aspendora fork addition (Vikunja CIPP-8).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Pick a single tenant.' } })
    }
    $DaysRaw = $Request.Query.Days ?? $Request.Body.Days
    $Days = 30
    if ($null -ne $DaysRaw -and "$DaysRaw" -ne '') {
        if (-not [int]::TryParse([string]$DaysRaw, [ref]$Days) -or $Days -lt 1) {
            return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Days must be a whole number from 1 to 30.' } })
        }
        $Days = [math]::Min(30, $Days)
    }
    try {
        $Report = Get-CIPPDeviceCodeSignIns -TenantFilter $TenantFilter -Days $Days
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Report })
    } catch {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $((Get-CippException -Exception $_).NormalizedError)" } })
    }
}
