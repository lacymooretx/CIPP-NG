function Initialize-CIPPAlertLifecycleBaseline {
    <#
    .SYNOPSIS
        One-time hand-over from a fork alert's own DeltaCompare baseline to the AlertLifecycle table.
    .DESCRIPTION
        Several fork alerts predate the AlertLifecycle (CIPP 11.0) and kept their own "seen" list in
        the DeltaCompare table. Switching them to Write-AlertTrace naively would re-notify every
        item that is still present: the lifecycle's own one-time seed reads AlertLastRun, and these
        alerts only ever wrote NEW items there, so every long-pending item would look new and be
        ticketed again.

        This runs once per alert and tenant, before the alert's first real reconcile. It records
        every item the old baseline already knew as Open in the lifecycle, silently, so the real
        reconcile that follows treats them as Continuing. A tenant that was never baselined at all
        also gets its current items seeded, preserving the old "first run surfaces nothing" rule.

        Completion is recorded as LifecycleSeeded on the DeltaCompare row, not inferred from the
        lifecycle being empty: an alert that has only ever found nothing has an empty lifecycle, and
        treating that as "not seeded yet" would silently swallow the first genuine finding.

        Seed items only need the identity field the alert's real items are hashed on (see
        Get-AlertContentHash), e.g. @{ Id = '<request id>' }.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CmdletName,
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        # DeltaCompare PartitionKey of the alert's old baseline row (RowKey is the tenant).
        [Parameter(Mandatory = $true)]
        [string]$BaselinePartition,
        # Builds seed items from the old baseline row's parsed 'delta' list.
        [Parameter(Mandatory = $true)]
        [scriptblock]$KnownItemsFromBaseline,
        # The items this run found. Seeded too when the tenant has no old baseline at all.
        [object[]]$CurrentItems = @()
    )

    $DeltaTable = Get-CIPPTable -tablename 'DeltaCompare'
    $SafeTenant = ConvertTo-CIPPODataFilterValue -Value $TenantFilter -Type String
    $Row = Get-CIPPAzDataTableEntity @DeltaTable -Filter "PartitionKey eq '$BaselinePartition' and RowKey eq '$SafeTenant'" | Select-Object -First 1

    if ($Row -and [string]$Row.LifecycleSeeded -eq 'true') { return }

    $Known = @()
    if ($Row.delta) {
        $Parsed = @($Row.delta | ConvertFrom-Json -ErrorAction SilentlyContinue | Where-Object { $_ })
        $Known = @(& $KnownItemsFromBaseline $Parsed)
    }
    $Seed = if ($Row) { $Known } else { @($CurrentItems) }

    # -Append: add and refresh only. Known items that are not present this run are resolved by the
    # real reconcile that follows, without a notification, which is the correct end state.
    $null = Write-AlertTrace -cmdletName $CmdletName -tenantFilter $TenantFilter -data @($Seed) -Append

    Add-CIPPAzDataTableEntity @DeltaTable -Force -Entity @{
        PartitionKey      = $BaselinePartition
        RowKey            = $TenantFilter
        delta             = [string]($Row.delta ?? '[]')
        LifecycleSeeded   = 'true'
        LifecycleSeededAt = [datetime]::UtcNow.ToString('o')
    } | Out-Null

    Write-LogMessage -API 'Alerts' -tenant $TenantFilter -sev Info -message ("{0}: handed over to AlertLifecycle; {1} known item(s) seeded silently." -f $CmdletName, @($Seed).Count)
}
