function Set-CIPPDBCacheAzureActivityLogSettings {
    <#
    .SYNOPSIS
        Caches each subscription's activity-log diagnostic settings (where the activity log is exported)
    .PARAMETER TenantFilter
        The tenant to cache activity-log export settings for
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
        Set-CIPPAzureCacheItems -TenantFilter $TenantFilter -Type 'AzureActivityLogSettings' -ScriptBlock {
            param($SubscriptionIds)
            foreach ($SubscriptionId in $SubscriptionIds) {
                $Settings = @(New-CIPPAzureRequest -TenantFilter $TenantFilter -Uri "/subscriptions/$SubscriptionId/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview" | ForEach-Object {
                        [pscustomobject]@{
                            name                        = $_.name
                            workspaceId                 = $_.properties.workspaceId
                            storageAccountId            = $_.properties.storageAccountId
                            eventHubAuthorizationRuleId = $_.properties.eventHubAuthorizationRuleId
                            logs                        = @($_.properties.logs | ForEach-Object { [pscustomobject]@{ category = $_.category; enabled = $_.enabled } })
                        }
                    })
                [pscustomobject]@{ id = $SubscriptionId; subscriptionId = $SubscriptionId; settings = $Settings }
            }
        }
    } catch {
        Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "Failed to cache Azure activity-log settings: $($_.Exception.Message)" -sev Error
        throw
    }
}
