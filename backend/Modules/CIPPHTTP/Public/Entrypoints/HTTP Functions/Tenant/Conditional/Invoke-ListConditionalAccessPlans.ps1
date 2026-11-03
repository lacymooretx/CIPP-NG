function Invoke-ListConditionalAccessPlans {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.ConditionalAccess.Read
    .SYNOPSIS
        Conditional Access plans and rules CIPP does not evaluate, from the cache
    .DESCRIPTION
        Returns PlanCount, RuleCount, Warning and Plans for one tenant from the ConditionalAccessPlans cache,
        collecting it on a miss. Report only: there is no plan write support. Aspendora fork addition (Vikunja CIPP-56).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $TenantFilter = [string]$Request.Query.tenantFilter
    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Pick a single tenant.' } })
    }
    try {
        $Plans = @(Get-CIPPSimulationCache -TenantFilter $TenantFilter -Type 'ConditionalAccessPlans')
        $Summary = Get-CIPPCAPlanSummary -Plans $Plans
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = [pscustomobject]@{
                    PlanCount = $Summary.PlanCount
                    RuleCount = $Summary.RuleCount
                    Warning   = $Summary.Warning
                    Plans     = $Plans
                }
            })
    } catch {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $((Get-CippException -Exception $_).NormalizedError)" } })
    }
}
