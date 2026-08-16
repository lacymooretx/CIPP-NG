function Get-CIPPStorageTrend {
    <#
    .SYNOPSIS
        Read a tenant's persisted daily storage history, newest last.
    .DESCRIPTION
        Returns the rows written by Push-CIPPStorageSnapshot, oldest first so the series can
        be charted or differenced directly.

        Growth rate and projected exhaustion are deliberately NOT computed here - pass the
        Series to Get-CIPPStorageGrowth for those. Keeping the reader free of arithmetic is
        what lets the growth maths be unit-tested without a table.

    .PARAMETER TenantFilter
        Tenant default domain name or customerId.
    .PARAMETER Days
        Only return the most recent N days. Omit for the full retained history.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantFilter,
        [int]$Days
    )

    $Domain = $TenantFilter
    try {
        $Tenant = Get-Tenants -TenantFilter $TenantFilter -IncludeErrors | Select-Object -First 1
        if ($Tenant.defaultDomainName) { $Domain = [string]$Tenant.defaultDomainName }
    } catch {}

    $Table = Get-CIPPTable -TableName 'CippStorageTrend'
    $Rows = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$Domain'")

    $Series = @($Rows | Sort-Object -Property RowKey | ForEach-Object {
            [pscustomobject]@{
                Date              = [string]$_.Date
                MailboxBytes      = [long]$_.MailboxBytes
                OneDriveBytes     = [long]$_.OneDriveBytes
                SharePointBytes   = [long]$_.SharePointBytes
                TotalBytes        = [long]$_.TotalBytes
                MeasuredWorkloads = [string]$_.MeasuredWorkloads
            }
        })

    if ($Days -gt 0 -and $Series.Count -gt $Days) {
        $Series = @($Series[($Series.Count - $Days)..($Series.Count - 1)])
    }

    return [pscustomobject]@{
        Tenant = $Domain
        Series = $Series
        First  = $(if ($Series.Count) { $Series[0] } else { $null })
        Latest = $(if ($Series.Count) { $Series[-1] } else { $null })
        Days   = $Series.Count
    }
}
