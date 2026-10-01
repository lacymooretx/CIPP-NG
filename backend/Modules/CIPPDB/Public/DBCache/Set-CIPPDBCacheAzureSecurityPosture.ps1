function Set-CIPPDBCacheAzureSecurityPosture {
    <#
    .SYNOPSIS
        Caches Defender for Cloud secure scores and unhealthy recommendations, summarised
    .DESCRIPTION
        Two kinds of item, told apart by `itemKind`: 'SecureScore' (one per subscription) and
        'Recommendation' (one per unhealthy recommendation per subscription, with a resource count
        and up to 20 sample resource ids). Summarising in KQL keeps the row count bounded on
        tenants with many resources.
    .PARAMETER TenantFilter
        The tenant to cache Azure security posture for
    .PARAMETER QueueId
        The queue ID to update with total tasks (optional)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [string]$QueueId
    )

    $ScoreQuery = @'
securityresources
| where type =~ 'microsoft.security/securescores' and name =~ 'ascScore'
| project id, subscriptionId, itemKind = 'SecureScore', currentScore = todouble(properties.score.current),
    maxScore = todouble(properties.score.max), percentage = todouble(properties.score.percentage)
'@
    $RecommendationQuery = @'
securityresources
| where type =~ 'microsoft.security/assessments' and tostring(properties.status.code) =~ 'Unhealthy'
| extend assessmentKey = name, displayName = tostring(properties.displayName),
    severity = tostring(properties.metadata.severity), resourceId = tolower(tostring(properties.resourceDetails.Id))
| summarize unhealthyCount = count(), sampleResources = make_list(resourceId, 20)
    by subscriptionId, assessmentKey, displayName, severity
| extend id = strcat(subscriptionId, '-', assessmentKey), itemKind = 'Recommendation'
'@

    try {
        Set-CIPPAzureCacheItems -TenantFilter $TenantFilter -Type 'AzureSecurityPosture' -ScriptBlock {
            param($SubscriptionIds)
            Search-CIPPAzureResourceGraph -TenantFilter $TenantFilter -Query $ScoreQuery -Subscriptions $SubscriptionIds
            Search-CIPPAzureResourceGraph -TenantFilter $TenantFilter -Query $RecommendationQuery -Subscriptions $SubscriptionIds
        }
    } catch {
        Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "Failed to cache Azure security posture: $($_.Exception.Message)" -sev Error
        throw
    }
}
