function Set-CIPPDBCacheConditionalAccessPlans {
    <#
    .SYNOPSIS
        Caches a tenant's Conditional Access policy plans and their rules (beta API, read only)

    .DESCRIPTION
        Rules in a plan do not appear under identity/conditionalAccess/policies. This cache lets posture, gap
        analysis, drift and the policy list warn that they cannot see them. A failed read leaves the previous
        rows in place. Aspendora fork addition (Vikunja CIPP-56).

    .PARAMETER TenantFilter
        The tenant to cache plans for

    .PARAMETER QueueId
        The queue ID to update with total tasks (optional)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [string]$QueueId
    )

    try {
        $Licensed = Test-CIPPStandardLicense -StandardName 'ConditionalAccessCache' -TenantFilter $TenantFilter -Preset Entra -SkipLog
        if ($Licensed -eq $false) {
            # A licence skip is a completed collection: record an authoritative empty set so collect-on-miss stops.
            Add-CIPPDbItem -TenantFilter $TenantFilter -Type 'ConditionalAccessPlans' -Data @() -AddCount -ClearOnEmpty
            return
        }
        $Plans = @(Get-CIPPConditionalAccessPlans -TenantFilter $TenantFilter)
        # The read throws on failure, so reaching here makes this the tenant's full set, including empty.
        Add-CIPPDbItem -TenantFilter $TenantFilter -Type 'ConditionalAccessPlans' -Data $Plans -AddCount -ClearOnEmpty
        Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "Cached $($Plans.Count) Conditional Access plans" -sev Debug
    } catch {
        Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "Failed to cache Conditional Access plans: $($_.Exception.Message)" -sev Warning
    }
}
