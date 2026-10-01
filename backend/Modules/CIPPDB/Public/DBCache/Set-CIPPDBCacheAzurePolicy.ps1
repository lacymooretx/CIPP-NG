function Set-CIPPDBCacheAzurePolicy {
    <#
    .SYNOPSIS
        Caches Azure Policy assignments with their non-compliant resource counts
    .PARAMETER TenantFilter
        The tenant to cache Azure Policy assignments for
    .PARAMETER QueueId
        The queue ID to update with total tasks (optional)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [string]$QueueId
    )

    $Query = @'
policyresources
| where type =~ 'microsoft.authorization/policyassignments'
| project id = tolower(id), subscriptionId, name, displayName = tostring(properties.displayName),
    policyDefinitionId = tostring(properties.policyDefinitionId), scope = tostring(properties.scope),
    enforcementMode = tostring(properties.enforcementMode)
| join kind=leftouter (
    policyresources
    | where type =~ 'microsoft.policyinsights/policystates' and tostring(properties.complianceState) =~ 'NonCompliant'
    | summarize nonCompliantResources = dcount(tostring(properties.resourceId)) by id = tolower(tostring(properties.policyAssignmentId))
) on id
| project-away id1
| extend nonCompliantResources = coalesce(nonCompliantResources, 0)
'@

    try {
        Set-CIPPAzureCacheItems -TenantFilter $TenantFilter -Type 'AzurePolicy' -ScriptBlock {
            param($SubscriptionIds)
            Search-CIPPAzureResourceGraph -TenantFilter $TenantFilter -Query $Query -Subscriptions $SubscriptionIds
        }
    } catch {
        Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "Failed to cache Azure Policy assignments: $($_.Exception.Message)" -sev Error
        throw
    }
}
