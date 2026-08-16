function ConvertTo-CIPPStorageTrendRow {
    <#
    .SYNOPSIS
        Merge the three Graph aggregate storage series into one daily row per date.
    .DESCRIPTION
        Graph exposes mailbox, OneDrive and SharePoint consumption as three separate daily
        series (getMailboxUsageStorage / getOneDriveUsageStorage /
        getSharePointSiteUsageStorage). This folds them into the shape we persist: one row
        per calendar date carrying all three workloads and their total.

        Kept pure - no Graph, no tables - because the interesting behaviour here is entirely
        in how gaps and disagreements between the three series are handled, and that is
        worth testing directly.

        GAPS ARE CARRIED FORWARD, NOT ZEROED. Storage consumption is cumulative: a date
        missing from one series is a hole in Microsoft's reporting, not a day on which the
        client deleted everything. Substituting 0 would draw a cliff in the trend chart and,
        worse, make the next day look like enormous growth. The last known value is carried
        forward instead. Before any value is known, a workload counts as 0 - which is
        correct for the genuine case of a tenant that has never used it.

    .PARAMETER MailboxSeries
        Rows from getMailboxUsageStorage.
    .PARAMETER OneDriveSeries
        Rows from getOneDriveUsageStorage.
    .PARAMETER SharePointSeries
        Rows from getSharePointSiteUsageStorage.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][AllowNull()]$MailboxSeries,
        [Parameter(Mandatory = $false)][AllowNull()]$OneDriveSeries,
        [Parameter(Mandatory = $false)][AllowNull()]$SharePointSeries
    )

    # Reduce one Graph series to @{ 'yyyy-MM-dd' = <bytes> }.
    # Some of these reports break the day down by siteType. Where Microsoft supplies an
    # 'All' rollup row we take it; otherwise the day's rows are summed. Doing only one of
    # those would either miss workloads or double-count the rollup against its own parts.
    function ConvertTo-DateMap($Series) {
        $Map = @{}
        $ByDate = @{}
        foreach ($Row in @($Series)) {
            if (-not $Row) { continue }
            $Raw = $Row.reportDate
            if (-not $Raw) { continue }
            $Date = $null
            try {
                $Date = ([datetime]::Parse([string]$Raw, [cultureinfo]::InvariantCulture)).ToString('yyyy-MM-dd')
            } catch { continue }

            $Bytes = 0L
            if ($null -ne $Row.storageUsedInBytes) {
                try { $Bytes = [long]$Row.storageUsedInBytes } catch { $Bytes = 0L }
            }

            if (-not $ByDate.ContainsKey($Date)) {
                $ByDate[$Date] = [pscustomobject]@{ All = $null; Sum = 0L }
            }
            $Entry = $ByDate[$Date]
            if ("$($Row.siteType)" -eq 'All') {
                $Entry.All = $Bytes
            } else {
                $Entry.Sum += $Bytes
            }
        }
        foreach ($Date in $ByDate.Keys) {
            $Entry = $ByDate[$Date]
            $Map[$Date] = if ($null -ne $Entry.All) { [long]$Entry.All } else { [long]$Entry.Sum }
        }
        return $Map
    }

    $Mailbox = ConvertTo-DateMap $MailboxSeries
    $OneDrive = ConvertTo-DateMap $OneDriveSeries
    $SharePoint = ConvertTo-DateMap $SharePointSeries

    $AllDates = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($Map in @($Mailbox, $OneDrive, $SharePoint)) {
        foreach ($Key in $Map.Keys) { $null = $AllDates.Add($Key) }
    }

    $Rows = [System.Collections.Generic.List[object]]::new()
    # Ascending, so carry-forward reads the previous day and not a later one.
    $LastMailbox = 0L; $LastOneDrive = 0L; $LastSharePoint = 0L
    foreach ($Date in @($AllDates) | Sort-Object) {
        if ($Mailbox.ContainsKey($Date)) { $LastMailbox = [long]$Mailbox[$Date] }
        if ($OneDrive.ContainsKey($Date)) { $LastOneDrive = [long]$OneDrive[$Date] }
        if ($SharePoint.ContainsKey($Date)) { $LastSharePoint = [long]$SharePoint[$Date] }

        $Rows.Add([pscustomobject]@{
                Date             = $Date
                MailboxBytes     = $LastMailbox
                OneDriveBytes    = $LastOneDrive
                SharePointBytes  = $LastSharePoint
                TotalBytes       = [long]($LastMailbox + $LastOneDrive + $LastSharePoint)
                # Which workloads Microsoft actually reported for this date, so a record can
                # distinguish "carried forward" from "measured" instead of implying all three
                # were freshly measured every day.
                MeasuredWorkloads = @(
                    if ($Mailbox.ContainsKey($Date)) { 'Mailbox' }
                    if ($OneDrive.ContainsKey($Date)) { 'OneDrive' }
                    if ($SharePoint.ContainsKey($Date)) { 'SharePoint' }
                ) -join ','
            })
    }

    return $Rows
}
