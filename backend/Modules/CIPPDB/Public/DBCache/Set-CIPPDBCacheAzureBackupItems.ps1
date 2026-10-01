function Set-CIPPDBCacheAzureBackupItems {
    <#
    .SYNOPSIS
        Caches Azure Backup protected items (which resources are backed up, and their last result)
    .PARAMETER TenantFilter
        The tenant to cache Azure Backup protected items for
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
recoveryservicesresources
| where type =~ 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems'
| project id, subscriptionId, vaultId = tolower(tostring(split(id, '/backupFabrics/')[0])),
    sourceResourceId = tolower(tostring(properties.sourceResourceId)), workloadType = tostring(properties.workloadType),
    protectionState = tostring(properties.protectionState), lastBackupStatus = tostring(properties.lastBackupStatus),
    lastBackupTime = tostring(properties.lastBackupTime)
'@

    try {
        Set-CIPPAzureCacheItems -TenantFilter $TenantFilter -Type 'AzureBackupItems' -ScriptBlock {
            param($SubscriptionIds)
            Search-CIPPAzureResourceGraph -TenantFilter $TenantFilter -Query $Query -Subscriptions $SubscriptionIds
        }
    } catch {
        Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "Failed to cache Azure Backup protected items: $($_.Exception.Message)" -sev Error
        throw
    }
}
