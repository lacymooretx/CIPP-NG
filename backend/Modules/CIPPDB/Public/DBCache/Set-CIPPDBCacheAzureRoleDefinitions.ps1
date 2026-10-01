function Set-CIPPDBCacheAzureRoleDefinitions {
    <#
    .SYNOPSIS
        Caches custom Azure RBAC role definitions (built-in roles are well known and not cached)
    .PARAMETER TenantFilter
        The tenant to cache custom Azure role definitions for
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
authorizationresources
| where type =~ 'microsoft.authorization/roledefinitions' and tostring(properties.type) =~ 'CustomRole'
| project id, subscriptionId, name, roleName = tostring(properties.roleName), description = tostring(properties.description),
    permissions = properties.permissions, assignableScopes = properties.assignableScopes
'@

    try {
        Set-CIPPAzureCacheItems -TenantFilter $TenantFilter -Type 'AzureRoleDefinitions' -ScriptBlock {
            param($SubscriptionIds)
            Search-CIPPAzureResourceGraph -TenantFilter $TenantFilter -Query $Query -Subscriptions $SubscriptionIds
        }
    } catch {
        Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "Failed to cache Azure role definitions: $($_.Exception.Message)" -sev Error
        throw
    }
}
