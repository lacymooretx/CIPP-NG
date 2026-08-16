function Test-CIPPTenantManaged {
    <#
    .SYNOPSIS
        Resolve whether a tenant is under a managed agreement.
    .DESCRIPTION
        Single place to answer "should we be doing work for this client?". Membership of the
        managed group is synced daily from ConnectWise company types by
        Sync-CIPPTenantGroupsFromConnectWise, so this reads the agreement rather than a
        hand-kept list.

        Until now this logic existed once, inline, in Get-CIPPTenantOverviewReportData, where
        it only decided a line of text. Anything that gates alerting, ticketing or client
        documentation on managed status needs the same answer, and three copies of it would
        drift the same way the CIPP and ConnectWise lists drifted.

        FAILS CLOSED. If group membership cannot be read the status is 'Unknown' and
        IsManaged is false. The alternative - assuming managed on error - would raise tickets
        against clients we have no agreement with the first time the table is unavailable.
        Callers that are merely reporting can surface 'Unknown'; callers that create tickets
        or write client documentation should treat it as "do nothing" and say why.

    .PARAMETER TenantFilter
        Tenant default domain name or customerId, as accepted by Get-TenantGroups.
    .PARAMETER ManagedGroupName
        Tenant group that means "under a managed agreement".
    .PARAMETER UnmanagedGroupName
        Tenant group that means "mapped, but not under a managed agreement".
    .EXAMPLE
        if ((Test-CIPPTenantManaged -TenantFilter $TenantFilter).IsManaged) { ... }
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantFilter,
        [string]$ManagedGroupName = 'Managed Clients',
        [string]$UnmanagedGroupName = 'Unmanaged Clients'
    )

    $Result = [PSCustomObject]@{
        TenantFilter = $TenantFilter
        Status       = 'Unknown'
        IsManaged    = $false
        Groups       = @()
        Error        = $null
    }

    try {
        # Get-TenantGroups returns objects with a 'Name' property, not 'GroupName'. Reading
        # the wrong one yields an empty list rather than an error, which would silently
        # report every tenant as unclassified - and, here, silently stop all managed work.
        $Groups = Get-TenantGroups -TenantFilter $TenantFilter
        $GroupNames = @($Groups | ForEach-Object { $_.Name }) | Where-Object { $_ }
        $Result.Groups = $GroupNames

        $Result.Status = if ($GroupNames -contains $ManagedGroupName) { 'Managed' }
        elseif ($GroupNames -contains $UnmanagedGroupName) { 'Unmanaged' }
        else { 'Unclassified' }

        $Result.IsManaged = $Result.Status -eq 'Managed'
    } catch {
        $Result.Error = $_.Exception.Message
        Write-LogMessage -API 'TenantManaged' -tenant $TenantFilter -sev Warning `
            -message "Could not read tenant group membership; treating as not managed. Error: $($Result.Error)"
    }

    return $Result
}
