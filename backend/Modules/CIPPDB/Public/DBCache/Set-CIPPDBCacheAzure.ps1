function Set-CIPPDBCacheAzure {
    <#
    .SYNOPSIS
        Refreshes every Azure compliance cache type for a tenant, in dependency order
    .DESCRIPTION
        On-demand entry point (ExecCIPPDBCache?Name=Azure). The Azure types depend on each other —
        subscriptions first, resource config after resources — so they run as the 'Azure' collection
        rather than individually.
    .PARAMETER TenantFilter
        The tenant to refresh Azure data for
    .PARAMETER QueueId
        The queue ID to update with total tasks (optional)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [string]$QueueId
    )

    $Params = @{ CollectionType = 'Azure'; TenantFilter = $TenantFilter }
    if ($QueueId) { $Params.QueueId = $QueueId }
    $null = Invoke-CIPPDBCacheCollection @Params
}
