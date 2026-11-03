function Get-CIPPTenantChangeHealth {
    <#
    .SYNOPSIS
        How old the tenant's cached data is. Reports no changes of its own.
    .DESCRIPTION
        Read only. Reads the reporting database's count rows, one per cache type, whose Timestamp is that type's last
        write. Some types are written rarely, so old types are listed and do not hold back the verdict on the page. No
        rows throws, so the caller can say "could not read". Aspendora fork addition (Vikunja CIPP-58).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Tenant,
        [int]$StaleDays = 3,
        [int]$ListLimit = 5,
        [datetime]$Now = [datetime]::UtcNow
    )

    $Rows = @(Get-CIPPDbItem -Partition $Tenant -CountsOnly | Where-Object { $null -ne $_ })
    if ($Rows.Count -eq 0) { throw 'No cached data found for this tenant.' }

    $Types = @($Rows | ForEach-Object {
            [pscustomobject]@{
                Type = ([string]$_.RowKey -replace '-Count$', '')
                When = ConvertTo-CIPPTenantChangeUtc -Value $_.Timestamp
            }
        } | Where-Object { $_.When } | Sort-Object -Property When)
    if ($Types.Count -eq 0) { throw 'Cached data has no readable dates for this tenant.' }

    $Cutoff = $Now.AddDays(-$StaleDays)
    $Old = @($Types | Where-Object { $_.When -lt $Cutoff })
    $Newest = $Types[-1].When
    $Text = "$($Types.Count) cache types, newest written $(Format-CIPPCentralTime -Value $Newest)."
    if ($Old.Count -gt 0) {
        $Listed = @($Old | Select-Object -First $ListLimit | ForEach-Object { "$($_.Type) ($($_.When.ToString('yyyy-MM-dd')))" })
        $Text += " $($Old.Count) older than $StaleDays days, oldest first: $($Listed -join ', ')$(if ($Old.Count -gt $ListLimit) { ', and more' })."
    }

    [pscustomobject]@{
        Status     = $(if ($Newest -lt $Cutoff) { 'Stale' } else { 'OK' })
        Detail     = $Text
        Changes    = @()
        CacheTypes = $Types.Count
        OldTypes   = $Old.Count
    }
}
