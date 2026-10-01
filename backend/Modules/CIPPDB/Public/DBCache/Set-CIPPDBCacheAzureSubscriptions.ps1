function Set-CIPPDBCacheAzureSubscriptions {
    <#
    .SYNOPSIS
        Caches the Azure subscriptions the CIPP-SAM principal can read in a tenant
    .DESCRIPTION
        Visibility is controlled by Azure RBAC (a Reader grant per subscription or management group),
        so an empty list means "not onboarded", not "no Azure". Runs first in the Azure collection;
        every other Azure collector reads its subscription ids from this cache.
    .PARAMETER TenantFilter
        The tenant to cache Azure subscriptions for
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
        $Subscriptions = New-CIPPAzureRequest -TenantFilter $TenantFilter -Uri '/subscriptions?api-version=2022-12-01' |
            ForEach-Object {
                [pscustomobject]@{
                    id                   = $_.subscriptionId
                    subscriptionId       = $_.subscriptionId
                    displayName          = $_.displayName
                    state                = $_.state
                    tenantId             = $_.tenantId
                    authorizationSource  = $_.authorizationSource
                    managedByTenants     = @($_.managedByTenants.tenantId)
                    spendingLimit        = $_.subscriptionPolicies.spendingLimit
                    quotaId              = $_.subscriptionPolicies.quotaId
                    tags                 = $_.tags
                }
            }
        @($Subscriptions) | Add-CIPPDbItem -TenantFilter $TenantFilter -Type 'AzureSubscriptions' -AddCount -ClearOnEmpty
        Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "Cached $(@($Subscriptions).Count) Azure subscription(s)" -sev Debug
    } catch {
        Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "Failed to cache Azure subscriptions: $($_.Exception.Message)" -sev Error
        throw
    }
}
