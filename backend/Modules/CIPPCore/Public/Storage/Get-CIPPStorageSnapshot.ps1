function Get-CIPPStorageSnapshot {
    <#
    .SYNOPSIS
        Read persisted per-mailbox or per-site storage detail for a tenant.
    .DESCRIPTION
        Companion to Get-CIPPStorageTrend for the object-level rows. Defaults to the most
        recent collection date, which is what a report almost always wants; pass -Date to
        pull an older one for comparison.

        Rows are keyed '<Scope>-<yyyyMMdd>-<id>', so scope and date are selected with a
        server-side prefix range rather than by pulling the tenant's whole history and
        filtering in memory. On a tenant with a few hundred mailboxes and a quarter of
        retained snapshots that is the difference between one page and thousands of rows.

    .PARAMETER TenantFilter
        Tenant default domain name or customerId.
    .PARAMETER Scope
        'Mailbox' or 'Site'.
    .PARAMETER Date
        Collection date, yyyy-MM-dd. Defaults to the latest available.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantFilter,
        [Parameter(Mandatory = $true)][ValidateSet('Mailbox', 'Site')][string]$Scope,
        [string]$Date
    )

    $Domain = $TenantFilter
    try {
        $Tenant = Get-Tenants -TenantFilter $TenantFilter -IncludeErrors | Select-Object -First 1
        if ($Tenant.defaultDomainName) { $Domain = [string]$Tenant.defaultDomainName }
    } catch {}

    $Table = Get-CIPPTable -TableName 'CippStorageSnapshot'

    if (-not $Date) {
        # Cheapest way to find the newest date: project the keys only, no payloads.
        $Keys = @(Get-CIPPAzDataTableEntity @Table `
                -Filter "PartitionKey eq '$Domain' and RowKey ge '$Scope-' and RowKey lt '$Scope.'" `
                -Property 'PartitionKey', 'RowKey', 'SnapshotDate')
        if ($Keys.Count -eq 0) {
            return [pscustomobject]@{ Tenant = $Domain; Scope = $Scope; Date = $null; Items = @() }
        }
        $Date = @($Keys | ForEach-Object { [string]$_.SnapshotDate } | Where-Object { $_ } | Sort-Object -Descending)[0]
    }

    $Compact = $Date -replace '-', ''
    $Prefix = "$Scope-$Compact-"
    $Rows = @(Get-CIPPAzDataTableEntity @Table `
            -Filter "PartitionKey eq '$Domain' and RowKey ge '$Prefix' and RowKey lt '$Scope-$Compact.'")

    $Items = foreach ($Row in $Rows) {
        try { $Row.Data | ConvertFrom-Json -Depth 20 } catch { continue }
    }

    return [pscustomobject]@{
        Tenant = $Domain
        Scope  = $Scope
        Date   = $Date
        Items  = @($Items)
    }
}
