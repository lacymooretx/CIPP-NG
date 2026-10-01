function Set-CIPPDBCacheAzureResources {
    <#
    .SYNOPSIS
        Caches the Azure resources the compliance tests inspect, via one Resource Graph query
    .DESCRIPTION
        Limited to the resource types an AZ_ test reads, so rows stay small and the query stays cheap.
        Add a type here when a new test needs it.
    .PARAMETER TenantFilter
        The tenant to cache Azure resources for
    .PARAMETER QueueId
        The queue ID to update with total tasks (optional)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [string]$QueueId
    )

    $ResourceTypes = @(
        'microsoft.storage/storageaccounts'
        'microsoft.keyvault/vaults'
        'microsoft.network/networksecuritygroups'
        'microsoft.network/networkinterfaces'
        'microsoft.network/publicipaddresses'
        'microsoft.network/virtualnetworks'
        'microsoft.network/bastionhosts'
        'microsoft.network/networkwatchers'
        'microsoft.network/networkwatchers/flowlogs'
        'microsoft.network/applicationgateways'
        'microsoft.network/azurefirewalls'
        'microsoft.compute/virtualmachines'
        'microsoft.compute/disks'
        'microsoft.sql/servers'
        'microsoft.dbforpostgresql/flexibleservers'
        'microsoft.dbformysql/flexibleservers'
        'microsoft.web/sites'
        'microsoft.recoveryservices/vaults'
        'microsoft.operationalinsights/workspaces'
        'microsoft.insights/activitylogalerts'
        'microsoft.containerservice/managedclusters'
        'microsoft.containerregistry/registries'
        'microsoft.cognitiveservices/accounts'
    )
    $TypeList = ($ResourceTypes | ForEach-Object { "'$_'" }) -join ','
    $Query = "resources | where type in~ ($TypeList) | project id, name, type = tolower(type), kind, location, resourceGroup, subscriptionId, sku, identity, tags, properties"

    try {
        Set-CIPPAzureCacheItems -TenantFilter $TenantFilter -Type 'AzureResources' -ScriptBlock {
            param($SubscriptionIds)
            Search-CIPPAzureResourceGraph -TenantFilter $TenantFilter -Query $Query -Subscriptions $SubscriptionIds
        }
    } catch {
        Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "Failed to cache Azure resources: $($_.Exception.Message)" -sev Error
        throw
    }
}
