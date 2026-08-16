function Push-CIPPStorageSnapshot {
    <#
    .SYNOPSIS
        Collect and persist a tenant's Microsoft 365 storage position, with history.
    .DESCRIPTION
        CIPP already knows current storage for every workload - what it has never had is a
        time dimension. The reporting DB is an overwrite cache with a 30-day purge, so
        "how fast is this client growing" and "when do they run out" cannot be answered.
        This writes the two tables that make those questions answerable:

          CippStorageTrend    - one row per tenant per DAY: mailbox / OneDrive / SharePoint
                                bytes and their total. Small enough to keep indefinitely.
          CippStorageSnapshot - per-mailbox and per-site detail for one collection date.
                                Retention-capped (see Start-TableCleanup); this is where
                                volume lives.

        THE FIRST RUN IS NOT EMPTY. The aggregate storage reports return a full daily series
        for the requested period, so the trend table is seeded with real history - up to 180
        days - the first time this runs, rather than starting flat and becoming useful in a
        quarter. Every subsequent run re-reads the window and upserts, so the series
        self-heals: a missed run leaves no gap as long as the gap is shorter than the window.

        Per-object detail cannot be backfilled the same way. Graph exposes only current
        state per mailbox and per site, so per-user and per-site growth becomes meaningful
        only after several collections. Reports built on this must say which is which.

        MANAGED CLIENTS ONLY. Storage reporting, documentation and alerting are scoped to
        clients under a managed agreement; membership is synced from ConnectWise. An
        unmanaged or unclassified tenant is skipped and says so, rather than quietly
        producing data nobody is entitled to act on. -Force overrides for testing.

    .PARAMETER TenantFilter
        Tenant default domain name or customerId.
    .PARAMETER TrendDays
        Days of aggregate history to request. Graph accepts 7, 30, 90 or 180.
    .PARAMETER SkipDetail
        Collect the trend rollup only; skip the per-mailbox and per-site snapshot.
    .PARAMETER Force
        Collect even if the tenant is not in the managed group.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)][string]$TenantFilter,
        [ValidateSet(7, 30, 90, 180)][int]$TrendDays = 180,
        [switch]$SkipDetail,
        [switch]$Force
    )

    $Result = [PSCustomObject]@{
        Tenant          = $TenantFilter
        Status          = 'Skipped'
        TrendRows       = 0
        MailboxRows     = 0
        SiteRows        = 0
        SnapshotDate    = $null
        CollectionNotes = [System.Collections.Generic.List[string]]::new()
        Errors          = [System.Collections.Generic.List[string]]::new()
    }

    # ---- resolve tenant --------------------------------------------------------------
    $Tenant = $null
    try { $Tenant = Get-Tenants -TenantFilter $TenantFilter -IncludeErrors | Select-Object -First 1 } catch {}
    if (-not $Tenant) {
        $Result.Errors.Add("Tenant '$TenantFilter' not found.")
        $Result.Status = 'Failed'
        return $Result
    }
    $Domain = [string]$Tenant.defaultDomainName
    $Result.Tenant = $Domain

    # ---- managed gate ----------------------------------------------------------------
    $Managed = Test-CIPPTenantManaged -TenantFilter $Domain
    if (-not $Managed.IsManaged -and -not $Force) {
        $Result.Status = 'SkippedNotManaged'
        $Result.CollectionNotes.Add("Tenant is '$($Managed.Status)', not Managed; storage collection is restricted to managed clients.")
        return $Result
    }

    $GraphBeta = 'https://graph.microsoft.com/beta'

    # ---- trend rollup ----------------------------------------------------------------
    # v1.0 refuses $format=application/json on these functions ("JSON format is not
    # supported") - beta accepts it, which is why every shipped caller in CIPP uses beta.
    $Series = @{}
    foreach ($Report in @(
            @{ Key = 'Mailbox'; Name = 'getMailboxUsageStorage' }
            @{ Key = 'OneDrive'; Name = 'getOneDriveUsageStorage' }
            @{ Key = 'SharePoint'; Name = 'getSharePointSiteUsageStorage' }
        )) {
        try {
            $Uri = "$GraphBeta/reports/$($Report.Name)(period='D$TrendDays')?`$format=application/json"
            $Series[$Report.Key] = @(New-GraphGetRequest -uri $Uri -tenantid $Domain -AsApp $true)
        } catch {
            $Series[$Report.Key] = @()
            $Result.CollectionNotes.Add("$($Report.Key) storage history unavailable: $($_.Exception.Message)")
        }
    }

    $TrendRows = @(ConvertTo-CIPPStorageTrendRow -MailboxSeries $Series['Mailbox'] `
            -OneDriveSeries $Series['OneDrive'] -SharePointSeries $Series['SharePoint'])

    if ($TrendRows.Count -eq 0) {
        $Result.CollectionNotes.Add('No storage history returned by any workload; trend not updated.')
    } elseif ($PSCmdlet.ShouldProcess($Domain, "Write $($TrendRows.Count) storage trend rows")) {
        $TrendTable = Get-CIPPTable -TableName 'CippStorageTrend'
        # Accumulate-and-flush, exactly as Add-CIPPDbItem does. A first cut sliced the list
        # with a range index instead - $List[0..99] - which returns object[] for a multi-row
        # slice and unrolls to a bare Hashtable when the slice holds one row, so .ToArray()
        # threw "does not contain a method named 'ToArray'" on the first live run. Calling
        # ToArray on the List itself has neither problem.
        $Batch = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($Row in $TrendRows) {
            $Batch.Add(@{
                    PartitionKey      = $Domain
                    # Date as the RowKey is what makes a re-run an upsert rather than a
                    # duplicate day. Compact form so the key sorts chronologically.
                    RowKey            = ($Row.Date -replace '-', '')
                    Date              = [string]$Row.Date
                    MailboxBytes      = [long]$Row.MailboxBytes
                    OneDriveBytes     = [long]$Row.OneDriveBytes
                    SharePointBytes   = [long]$Row.SharePointBytes
                    TotalBytes        = [long]$Row.TotalBytes
                    MeasuredWorkloads = [string]$Row.MeasuredWorkloads
                })
            # Flush at 100: the table SDK rejects larger transactions and 180 days exceeds it.
            if ($Batch.Count -ge 100) {
                $null = Add-CIPPAzDataTableEntity @TrendTable -Entity $Batch.ToArray() -Force
                $Batch.Clear()
            }
        }
        if ($Batch.Count -gt 0) {
            $null = Add-CIPPAzDataTableEntity @TrendTable -Entity $Batch.ToArray() -Force
        }
        $Result.TrendRows = $TrendRows.Count
    }

    if ($SkipDetail) {
        $Result.Status = 'Success'
        return $Result
    }

    # ---- per-object detail -----------------------------------------------------------
    # Refuse to write pseudonymised data. With concealed names on, Graph returns hashes
    # instead of UPNs and site names; persisting those would fill the snapshot - and any
    # documentation built on it - with identifiers nobody can act on, while looking fine.
    try {
        $ReportSettings = New-GraphGetRequest -uri "$GraphBeta/admin/reportSettings" -tenantid $Domain -AsApp $true
        if ($ReportSettings.displayConcealedNames -eq $true) {
            $Result.Status = 'PartialConcealed'
            $Result.CollectionNotes.Add('Report pseudonymisation is enabled for this tenant, so per-user and per-site names are hashed. Detail was not collected. Apply the AnonReportDisable standard to fix.')
            return $Result
        }
    } catch {
        $Result.CollectionNotes.Add("Could not confirm report pseudonymisation setting: $($_.Exception.Message)")
    }

    $SnapshotDate = $null
    $DetailBatch = [System.Collections.Generic.List[hashtable]]::new()

    # Mailboxes: read live rather than from the MailboxUsage cache. These numbers drive
    # quota tickets, so a stale cache would mean raising - or failing to raise - a ticket on
    # last night's picture. It is one call per tenant per run.
    try {
        $Mailboxes = @(New-GraphGetRequest -tenantid $Domain -AsApp $true `
                -uri "$GraphBeta/reports/getMailboxUsageDetail(period='D7')?`$format=application/json&`$top=999")
        foreach ($Mailbox in $Mailboxes) {
            if ($Mailbox.isDeleted -eq $true) { continue }
            if (-not $Mailbox.userPrincipalName) { continue }
            if (-not $SnapshotDate -and $Mailbox.reportRefreshDate) {
                # The report refresh date, never Get-Date: these reports lag 24-48h and
                # stamping "now" silently misdates the whole series.
                try { $SnapshotDate = ([datetime]::Parse([string]$Mailbox.reportRefreshDate, [cultureinfo]::InvariantCulture)).ToString('yyyy-MM-dd') } catch {}
            }
            $DetailBatch.Add(@{
                    Scope = 'Mailbox'
                    Id    = [string]$Mailbox.userPrincipalName
                    Data  = [string]($Mailbox | ConvertTo-Json -Depth 5 -Compress)
                })
        }
        $Result.MailboxRows = @($DetailBatch | Where-Object { $_.Scope -eq 'Mailbox' }).Count
    } catch {
        $Result.CollectionNotes.Add("Mailbox detail unavailable: $($_.Exception.Message)")
    }

    # Sites: read the SiteActivity cache rather than the raw usage reports. It already
    # unions SharePoint + OneDrive + Teams, resolves display names and web URLs (the raw
    # report returns a blank Site URL in our tenants) and carries rootWebTemplate and
    # effectiveLastActivityDate. Re-deriving that here would be a second implementation of
    # a join that already runs nightly.
    try {
        $SiteRows = @(Get-CIPPDbItem -TenantFilter $Domain -Type 'SiteActivity' |
                Where-Object { $_.RowKey -notlike '*-Count' })
        if ($SiteRows.Count -eq 0) {
            $Result.CollectionNotes.Add('No SiteActivity cache for this tenant, so SharePoint and OneDrive detail was not collected. Run a cache sync first.')
        }
        foreach ($Entity in $SiteRows) {
            $Site = $null
            try { $Site = $Entity.Data | ConvertFrom-Json -Depth 20 } catch { continue }
            if (-not $Site -or -not $Site.siteId) { continue }
            if ($Site.isDeleted -eq $true) { continue }
            $DetailBatch.Add(@{
                    Scope = 'Site'
                    Id    = [string]$Site.siteId
                    Data  = [string]($Site | ConvertTo-Json -Depth 10 -Compress)
                })
        }
        $Result.SiteRows = @($DetailBatch | Where-Object { $_.Scope -eq 'Site' }).Count
    } catch {
        $Result.CollectionNotes.Add("Site detail unavailable: $($_.Exception.Message)")
    }

    if (-not $SnapshotDate) { $SnapshotDate = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd') }
    $Result.SnapshotDate = $SnapshotDate
    $Compact = $SnapshotDate -replace '-', ''

    if ($DetailBatch.Count -gt 0 -and $PSCmdlet.ShouldProcess($Domain, "Write $($DetailBatch.Count) storage snapshot rows for $SnapshotDate")) {
        $SnapTable = Get-CIPPTable -TableName 'CippStorageSnapshot'
        $Entities = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($Item in $DetailBatch) {
            $Entities.Add(@{
                    PartitionKey = $Domain
                    RowKey       = ConvertTo-CIPPStorageRowKey -Scope $Item.Scope -Date $Compact -Id $Item.Id
                    Scope        = [string]$Item.Scope
                    SnapshotDate = [string]$SnapshotDate
                    ObjectId     = [string]$Item.Id
                    Data         = [string]$Item.Data
                })
            if ($Entities.Count -ge 100) {
                $null = Add-CIPPAzDataTableEntity @SnapTable -Entity $Entities.ToArray() -Force
                $Entities.Clear()
            }
        }
        if ($Entities.Count -gt 0) {
            $null = Add-CIPPAzDataTableEntity @SnapTable -Entity $Entities.ToArray() -Force
        }
    }

    $Result.Status = if ($Result.CollectionNotes.Count -gt 0) { 'PartialSuccess' } else { 'Success' }

    Write-LogMessage -API 'StorageSnapshot' -tenant $Domain -sev Info `
        -message "Storage snapshot $($Result.Status): $($Result.TrendRows) trend day(s), $($Result.MailboxRows) mailbox(es), $($Result.SiteRows) site(s) at $SnapshotDate"

    return $Result
}
