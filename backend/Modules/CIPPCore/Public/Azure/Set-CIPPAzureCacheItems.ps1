function Set-CIPPAzureCacheItems {
    <#
    .SYNOPSIS
        Shared write path for the Azure compliance cache collectors
    .DESCRIPTION
        Runs the collector's script block only when the tenant has at least one readable, enabled
        subscription, and writes the result as an authoritative full set (-ClearOnEmpty), so a tenant
        whose Reader grant is removed stops showing stale Azure data on the next collection.

        Throws when the script block throws, leaving the previous data in place: a failed ARM call is
        not evidence that the resources are gone.
    .PARAMETER TenantFilter
        Tenant default domain.
    .PARAMETER Type
        CippReportingDB type, e.g. 'AzureResources'.
    .PARAMETER ScriptBlock
        Produces the items. Receives the subscription id array as its only argument.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        [Parameter(Mandatory = $true)]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock
    )

    $SubscriptionIds = Get-CIPPAzureSubscriptionIds -TenantFilter $TenantFilter
    if ($SubscriptionIds.Count -eq 0) {
        @() | Add-CIPPDbItem -TenantFilter $TenantFilter -Type $Type -AddCount -ClearOnEmpty
        Write-Information "[$Type] $TenantFilter has no readable Azure subscriptions; cleared."
        return
    }

    $Items = [System.Collections.Generic.List[object]]::new()
    foreach ($Item in @(& $ScriptBlock $SubscriptionIds)) {
        if ($null -ne $Item) { $Items.Add($Item) }
    }
    $Items | Add-CIPPDbItem -TenantFilter $TenantFilter -Type $Type -AddCount -ClearOnEmpty
    Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "Cached $($Items.Count) $Type item(s) across $($SubscriptionIds.Count) subscription(s)" -sev Debug
}
