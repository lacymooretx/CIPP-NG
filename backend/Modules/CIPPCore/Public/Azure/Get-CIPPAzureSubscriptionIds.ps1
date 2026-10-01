function Get-CIPPAzureSubscriptionIds {
    <#
    .SYNOPSIS
        Enabled subscription ids the CIPP-SAM principal can read in a tenant, from the AzureSubscriptions cache
    .DESCRIPTION
        Set-CIPPDBCacheAzureSubscriptions runs first in the Azure collection, so every later Azure
        collector reads the subscription list from the cache instead of calling ARM again.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter
    )

    @(New-CIPPDbRequest -TenantFilter $TenantFilter -Type 'AzureSubscriptions' |
            Where-Object { $_.state -eq 'Enabled' } |
            ForEach-Object { [string]$_.subscriptionId })
}
