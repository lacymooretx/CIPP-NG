function Invoke-ListIntunePolicyHygiene {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .SYNOPSIS
        Intune policy assignment hygiene for a tenant
    .DESCRIPTION
        Finds Intune policies with no assignments, policies assigned only through exclusions, and assignments
        (policies and assigned apps) pointing at groups that no longer exist or have no members. Returns the
        findings with a count summary by category and policy type.
        Report only: nothing is changed. Aspendora fork addition (Vikunja CIPP-19).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Pick a single tenant.' } })
    }
    try {
        $Report = Get-CIPPIntunePolicyHygiene -TenantFilter $TenantFilter
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Report })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API $Request.Params.CIPPEndpoint -tenant $TenantFilter -message "Intune policy hygiene failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $($ErrorMessage.NormalizedError)" } })
    }
}
