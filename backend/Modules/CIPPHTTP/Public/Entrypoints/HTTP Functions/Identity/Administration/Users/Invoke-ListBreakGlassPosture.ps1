function Invoke-ListBreakGlassPosture {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.User.Read
    .SYNOPSIS
        Break-glass (emergency access) posture check for a tenant
    .DESCRIPTION
        Checks the tenant's registered break-glass accounts: at least two; cloud-only on *.onmicrosoft.com; permanent
        active Global Administrator (not PIM-eligible only); excluded from every enabled Conditional Access policy
        (users, groups and roles resolved); password never expires; FIDO2 and no person-bound methods; a successful
        sign-in within 90 days. Also flags other accounts excluded from many All-users CA policies.
        Report only: nothing is changed. Aspendora fork addition (Vikunja CIPP-4).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Pick a single tenant.' } })
    }
    try {
        $Report = Get-CIPPBreakGlassPosture -TenantFilter $TenantFilter
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Report })
    } catch {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $((Get-CippException -Exception $_).NormalizedError)" } })
    }
}
