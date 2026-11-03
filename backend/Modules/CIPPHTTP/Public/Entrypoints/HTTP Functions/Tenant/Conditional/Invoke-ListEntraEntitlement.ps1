function Invoke-ListEntraEntitlement {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.ConditionalAccess.Read
    .SYNOPSIS
        Entra ID P1/P2 true-up: licence pools compared with the users Conditional Access covers
    .DESCRIPTION
        Single tenant: returns Summary (P1 and P2 pools, users in scope of enforced policies, shortfalls, per-user gaps,
        what enabling report-only policies would need), Skus, Users, Findings, Errors and Notes.
        tenantFilter=AllTenants: returns the stored per-tenant summaries (Results) from the last single-tenant view or
        EntraEntitlementGap alert run, with CheckedUtc; tenants never checked are not listed.
        Report only: nothing in the tenant is changed. Aspendora fork addition (Vikunja CIPP-47).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    if (-not $TenantFilter) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'tenantFilter is required.' } })
    }
    try {
        if ($TenantFilter -eq 'AllTenants') {
            $Table = Get-CIPPTable -tablename 'EntraEntitlement'
            # Only tenants this caller may see.
            $AllowedIds = @(Test-CIPPAccess -Request $Request -TenantList)
            $Allowed = @(Get-Tenants | Where-Object { $AllowedIds -contains 'AllTenants' -or $_.customerId -in $AllowedIds } | ForEach-Object { [string]$_.defaultDomainName })
            $Rows = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Summary'" | Where-Object { $_.RowKey -in $Allowed } |
                    Select-Object Tenant, CheckedUtc, CoveredP1, CoveredP2, P1Pool, P1InScope, P1Shortfall, P1UserGaps, P2Pool, P2InScope, P2Shortfall, P2UserGaps, P1InScopeWithReportOnly, P2InScopeWithReportOnly, EnforcedPolicies, EnforcedRiskPolicies, EnabledMembers, NonPersonExcluded, GuestsInScope, Warnings |
                    Sort-Object Tenant)
            return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = @{ Results = $Rows } })
        }
        $Report = Get-CIPPEntraEntitlement -TenantFilter $TenantFilter
        Save-CIPPEntraEntitlementSummary -TenantFilter $TenantFilter -Report $Report
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Report })
    } catch {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $((Get-CippException -Exception $_).NormalizedError)" } })
    }
}
