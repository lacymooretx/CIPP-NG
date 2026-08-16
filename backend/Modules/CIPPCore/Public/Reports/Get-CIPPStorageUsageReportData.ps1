function Get-CIPPStorageUsageReportData {
    <#
    .SYNOPSIS
        Gather the M365 Storage and Usage report model for a single tenant.
    .DESCRIPTION
        The consolidated storage picture CIPP has never had in one place: what the tenant is
        consuming across mail, OneDrive and SharePoint, how fast that is moving, who the
        heavy users are, which mailboxes are approaching Microsoft's own warning quota, and
        which SharePoint sites are genuinely worth archiving.

        Reads the history written by Push-CIPPStorageSnapshot, so the growth figures are
        real measurements rather than a single point pretending to be a trend. Where there
        is no history yet the report says so instead of drawing a flat line.

        MANAGED CLIENTS ONLY, by operator decision - unlike the other documentation reports,
        which cover every mapped client. An unmanaged tenant gets a one-section report
        stating why, rather than a silent empty document.

        Both of the thresholds here were set by what real tenant data did to them:
          - mailbox risk is judged on the HARD send/receive quota, not issueWarningQuota.
            The warning quota is not always rescaled when a mailbox moves to a bigger plan,
            and on 3E NDT it would have raised a capacity alarm for a mailbox with 30 GB
            free. Mailboxes warned below their real limit get their own section as a
            configuration finding instead.
          - archival candidates exclude system sites and apply a size floor. Across five
            tenants a naive "inactive 90 days" rule listed 46 sites; the filtered rule
            lists 2. The other 44 are things like the Tenant Admin Site.

        Same contract as the other builders: stable section Keys for the IT Glue trait
        mapping, per-section collection so one failure does not lose the report, and a
        section that could not be read is a note rather than an empty table.
    .PARAMETER TenantFilter
        Tenant default domain name.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter
    )

    $GraphBeta = 'https://graph.microsoft.com/beta'
    $Findings = [System.Collections.Generic.List[object]]::new()
    $Sections = [System.Collections.Generic.List[object]]::new()
    $Notes = [System.Collections.Generic.List[object]]::new()

    function Add-Finding($Title, $Status, $Detail) {
        $Findings.Add(@{ Title = $Title; Status = $Status; Detail = $Detail })
    }
    function Add-Section($Key, $Title, $Status, $Description, $Columns, $Rows, $Empty) {
        $Sections.Add(@{ Key = $Key; Title = $Title; Status = $Status; Description = $Description; Columns = $Columns; Rows = $Rows; Empty = $Empty })
    }
    function New-RowList { , [System.Collections.Generic.List[object]]::new() }
    function Invoke-Section($Key, $Name, [scriptblock]$Builder) {
        try { & $Builder } catch {
            $Reason = $_.Exception.Message
            $Notes.Add(@{ Section = $Name; Detail = $Reason })
            $r = New-RowList; $r.Add(@($Reason))
            Add-Section $Key $Name 'warn' 'This section could not be retrieved - the data below is incomplete.' @('Error') $r 'Data unavailable.'
        }
    }
    function Format-Size([double]$Bytes) {
        if ($Bytes -ge 1TB) { return '{0:N2} TB' -f ($Bytes / 1TB) }
        if ($Bytes -ge 1GB) { return '{0:N2} GB' -f ($Bytes / 1GB) }
        if ($Bytes -ge 1MB) { return '{0:N1} MB' -f ($Bytes / 1MB) }
        return '{0:N0} KB' -f ($Bytes / 1KB)
    }
    function Format-Rate([double]$BytesPerDay) {
        $Sign = if ($BytesPerDay -lt 0) { '-' } else { '+' }
        '{0}{1}/day' -f $Sign, (Format-Size ([math]::Abs($BytesPerDay)))
    }

    # ---- tenant identity -------------------------------------------------------------
    $Org = $null
    try { $Org = New-GraphGetRequest -uri "$GraphBeta/organization" -tenantid $TenantFilter | Select-Object -First 1 } catch {}
    $TenantName = if ($Org.displayName) { $Org.displayName } else { $TenantFilter }
    $DefaultDomain = ($Org.verifiedDomains | Where-Object { $_.isDefault }).name
    if (-not $DefaultDomain) { $DefaultDomain = $TenantFilter }

    $State = @{ Count = 0; AtRisk = 0; StaleWarning = 0; Archival = 0; ReclaimBytes = 0L; Trend = 'Unknown'; NoHistory = $false }

    # ---- managed gate ----------------------------------------------------------------
    $Managed = Test-CIPPTenantManaged -TenantFilter $TenantFilter
    if (-not $Managed.IsManaged) {
        $r = New-RowList
        $r.Add(@('Management status', $Managed.Status))
        $r.Add(@('Reason', 'Storage reporting is restricted to clients under a managed agreement.'))
        if ($Managed.Error) { $r.Add(@('Group lookup error', $Managed.Error)) }
        Add-Section 'Summary' 'Storage Summary' 'info' `
            'This tenant is not in the Managed Clients group, so no storage data was collected.' `
            @('Item', 'Value') $r 'Not collected.'
        Add-Finding 'Not a managed client' 'info' `
            "$TenantName is '$($Managed.Status)'. Storage reporting, documentation and alerting are scoped to managed clients; classification syncs from ConnectWise."
        return @{
            Title           = 'M365 Storage and Usage'
            TenantName      = $TenantName
            TenantDomain    = $DefaultDomain
            GeneratedDate   = (Get-Date).ToString('dd MMMM yyyy')
            Findings        = $Findings
            Sections        = $Sections
            CollectionNotes = $Notes
            ObjectCount     = 0
        }
    }

    # ---- history + growth --------------------------------------------------------------
    $Trend = $null
    $Growth = $null
    try {
        $Trend = Get-CIPPStorageTrend -TenantFilter $TenantFilter
        $Growth = Get-CIPPStorageGrowth -Series $Trend.Series
    } catch {
        $Notes.Add(@{ Section = 'Storage Summary'; Detail = "Stored history unavailable: $($_.Exception.Message)" })
    }
    if (-not $Trend -or $Trend.Days -eq 0) {
        $State.NoHistory = $true
        $Notes.Add(@{ Section = 'Storage Summary'; Detail = 'No stored storage history for this tenant yet. Run Push-CIPPStorageSnapshot; growth figures are omitted rather than shown as zero.' })
    }

    # ---- Summary -----------------------------------------------------------------------
    Invoke-Section 'Summary' 'Storage Summary' {
        $r = New-RowList
        if ($Trend -and $Trend.Latest) {
            $L = $Trend.Latest
            $r.Add(@('Total consumption', (Format-Size $L.TotalBytes), $L.Date))
            $r.Add(@('Exchange mailboxes', (Format-Size $L.MailboxBytes), ''))
            $r.Add(@('OneDrive', (Format-Size $L.OneDriveBytes), ''))
            $r.Add(@('SharePoint', (Format-Size $L.SharePointBytes), ''))
            $State.Count++
        } else {
            $r.Add(@('Total consumption', 'No history collected yet', ''))
        }
        Add-Section 'Summary' 'Storage Summary' 'info' `
            'Consumption across all three workloads at the most recent collection.' `
            @('Workload', 'Consumption', 'As at') $r 'No storage data collected.'
    }

    # ---- Growth ------------------------------------------------------------------------
    Invoke-Section 'Growth' 'Growth and Projection' {
        $r = New-RowList
        if ($Growth -and $Growth.Days -ge 2) {
            $State.Trend = $Growth.Trend
            $r.Add(@('Trend', $Growth.Trend, "based on the last $($Growth.BasisWindowDays) days"))
            $r.Add(@('Current rate', (Format-Rate $Growth.BytesPerDay), "$($Growth.Confidence) confidence"))
            foreach ($Span in @('30', '90', '180')) {
                if (-not $Growth.Windows.ContainsKey($Span)) { continue }
                $W = $Growth.Windows[$Span]
                $r.Add(@("Last $Span days", (Format-Rate $W.BytesPerDay), "total change $(Format-Size $W.ChangeBytes) since $($W.FromDate)"))
            }
            $r.Add(@('Typical day (median)', (Format-Rate $Growth.MedianBytesPerDay), 'robust to one-off events'))
            $r.Add(@('History held', "$($Growth.Days) days", "$($Growth.FirstDate) to $($Growth.LatestDate)"))

            # A one-off event is reported, not averaged into the rate - otherwise a single
            # cleanup makes a growing client look like a shrinking one for six months.
            foreach ($Step in @($Growth.StepChanges)) {
                $Direction = if ($Step.ChangeBytes -lt 0) { 'drop' } else { 'jump' }
                $r.Add(@('One-off change', "$Direction of $(Format-Size ([math]::Abs($Step.ChangeBytes)))", $Step.Date))
            }
            if ($Growth.Note) { $r.Add(@('Note', $Growth.Note, '')) }
            $State.Count++
        } else {
            $r.Add(@('Trend', 'Not enough history', 'At least two collections are needed. Tenant-level history backfills up to 180 days on the first run.'))
        }

        $Status = switch ($State.Trend) {
            'Accelerating' { 'warn' }
            'Shrinking' { 'pass' }
            default { 'info' }
        }
        Add-Section 'Growth' 'Growth and Projection' $Status `
            'Rates over several windows. A single whole-period figure is not shown on its own: one large cleanup or migration inside the window sets it, and it then disagrees with everything a client can see.' `
            @('Measure', 'Value', 'Detail') $r 'No growth data.'
    }

    # ---- Mailboxes at risk ---------------------------------------------------------------
    $Mailboxes = @()
    Invoke-Section 'MailboxRisk' 'Mailboxes Approaching Quota' {
        $Mailboxes = @(New-GraphGetRequest -tenantid $TenantFilter -AsApp $true `
                -uri "$GraphBeta/reports/getMailboxUsageDetail(period='D7')?`$format=application/json&`$top=999" |
                Where-Object { $_.isDeleted -ne $true -and $_.userPrincipalName })

        $Risk = Get-CIPPMailboxQuotaRisk -Mailboxes $Mailboxes
        $State.AtRisk = @($Risk.AtRisk).Count
        $State.StaleWarning = @($Risk.StaleWarning).Count

        $r = New-RowList
        foreach ($A in $Risk.AtRisk) {
            $r.Add(@($A.Upn, (Format-Size $A.UsedBytes), (Format-Size $A.HardBytes), "$($A.PercentUsed)%",
                    (Format-Size ($A.HardBytes - $A.UsedBytes)),
                    $(if ($A.HasArchive) { 'Yes' } else { 'No' })))
        }
        $State.Count += $State.AtRisk

        Add-Section 'MailboxRisk' 'Mailboxes Approaching Quota' `
            $(if ($State.AtRisk -gt 0) { 'warn' } else { 'pass' }) `
        "Mailboxes at or past 85% of their send/receive quota. Judged on the hard quota rather than issueWarningQuota, because the warning quota is not always rescaled when a mailbox moves to a larger plan and would otherwise raise a capacity alarm for a mailbox with tens of gigabytes free. $($Risk.Checked) mailbox(es) checked." `
            @('Mailbox', 'Used', 'Send/receive quota', 'Used %', 'Remaining', 'Archive enabled') $r `
            'No mailbox is within 15% of its quota.'
    }

    # ---- Warned but not at risk ------------------------------------------------------------
    Invoke-Section 'QuotaWarningConfig' 'Mailboxes Warned Below Their Quota' {
        $Risk = Get-CIPPMailboxQuotaRisk -Mailboxes $Mailboxes
        $r = New-RowList
        foreach ($W in $Risk.WarnedOnly) {
            $Stale = @($Risk.StaleWarning | Where-Object { $_.Upn -eq $W.Upn }).Count -gt 0
            $r.Add(@($W.Upn, (Format-Size $W.UsedBytes), (Format-Size $W.WarnBytes), (Format-Size $W.HardBytes),
                    "$($W.PercentUsed)%",
                    $(if ($Stale) { 'Warning quota not rescaled for this plan' } else { 'Approaching warning level' })))
        }
        $State.Count += @($Risk.WarnedOnly).Count
        Add-Section 'QuotaWarningConfig' 'Mailboxes Warned Below Their Quota' 'info' `
            'These users are seeing Outlook quota warnings while still having plenty of space. Where the warning quota is a small fraction of the send/receive quota it was almost certainly left behind when the mailbox moved to a larger plan - a configuration fix, not a capacity problem, and deliberately not ticketed as one.' `
            @('Mailbox', 'Used', 'Warning quota', 'Send/receive quota', 'Used %', 'Assessment') $r `
            'No mailbox is being warned below its quota.'
    }

    # ---- Largest mailboxes ----------------------------------------------------------------
    Invoke-Section 'TopMailboxes' 'Largest Mailboxes' {
        $r = New-RowList
        $Top = @($Mailboxes | Sort-Object -Property { [long]($_.storageUsedInBytes ?? 0) } -Descending | Select-Object -First 10)
        foreach ($M in $Top) {
            $Used = [long]($M.storageUsedInBytes ?? 0)
            $Hard = [long]($M.prohibitSendReceiveQuotaInBytes ?? 0)
            $r.Add(@($M.userPrincipalName, (Format-Size $Used),
                    $(if ($Hard -gt 0) { "$([math]::Round(($Used / $Hard) * 100, 1))%" } else { 'n/a' }),
                    "$([long]($M.itemCount ?? 0))",
                    [string]$M.recipientType,
                    $(if ($M.hasArchive) { 'Yes' } else { 'No' })))
        }
        $State.Count += $Top.Count
        Add-Section 'TopMailboxes' 'Largest Mailboxes' 'info' `
            'The ten largest mailboxes, which is usually where any mail-side reclamation starts.' `
            @('Mailbox', 'Used', 'Of quota', 'Items', 'Type', 'Archive') $r 'No mailbox data.'
    }

    # ---- Sites ------------------------------------------------------------------------------
    $Sites = @()
    Invoke-Section 'SharePointSites' 'Largest SharePoint Sites' {
        $Snapshot = Get-CIPPStorageSnapshot -TenantFilter $TenantFilter -Scope 'Site'
        $Sites = @($Snapshot.Items)
        if ($Sites.Count -eq 0) {
            $Notes.Add(@{ Section = 'Largest SharePoint Sites'; Detail = 'No site snapshot stored yet; run Push-CIPPStorageSnapshot.' })
        }
        $r = New-RowList
        $Top = @($Sites | Where-Object { $_.isPersonalSite -ne $true } |
                Sort-Object -Property { [long]($_.sharePointStorageUsedInBytes ?? 0) } -Descending | Select-Object -First 15)
        foreach ($S in $Top) {
            $r.Add(@([string]$S.displayName,
                    (Format-Size ([long]($S.sharePointStorageUsedInBytes ?? 0))),
                    "$([long]($S.sharePointFileCount ?? 0))",
                    $(if ($S.effectiveLastActivityDate) { ([datetime]$S.effectiveLastActivityDate).ToString('yyyy-MM-dd') } else { 'No activity recorded' }),
                    [string]$S.rootWebTemplate))
        }
        $State.Count += $Top.Count
        Add-Section 'SharePointSites' 'Largest SharePoint Sites' 'info' `
            'Per-site quota is not shown: every site inherits the tenant default (25 TB), so a per-site percentage reads as 0% forever and tells nobody anything. Absolute size and activity are the useful figures.' `
            @('Site', 'Storage', 'Files', 'Last activity', 'Template') $r 'No SharePoint site data.'
    }

    # ---- OneDrive ------------------------------------------------------------------------------
    Invoke-Section 'OneDrive' 'OneDrive Consumption' {
        $r = New-RowList
        $Drives = @($Sites | Where-Object { $_.isPersonalSite -eq $true } |
                Sort-Object -Property { [long]($_.oneDriveStorageUsedInBytes ?? 0) } -Descending)
        foreach ($D in @($Drives | Select-Object -First 10)) {
            $Used = [long]($D.oneDriveStorageUsedInBytes ?? 0)
            $Alloc = [long]($D.oneDriveStorageAllocatedInBytes ?? 0)
            $r.Add(@([string]$D.ownerPrincipalName,
                    (Format-Size $Used),
                    $(if ($Alloc -gt 0) { "$([math]::Round(($Used / $Alloc) * 100, 1))%" } else { 'n/a' }),
                    "$([long]($D.oneDriveFileCount ?? 0))",
                    $(if ($D.effectiveLastActivityDate) { ([datetime]$D.effectiveLastActivityDate).ToString('yyyy-MM-dd') } else { 'No activity recorded' })))
        }
        $State.Count += @($Drives).Count

        # Worth stating plainly: few provisioned OneDrives usually means staff are keeping
        # work somewhere we do not manage or back up, which is a bigger problem than usage.
        $Description = "$(@($Drives).Count) provisioned OneDrive(s)."
        if (@($Drives).Count -gt 0 -and @($Mailboxes).Count -gt (@($Drives).Count * 2)) {
            $Description += " Only $(@($Drives).Count) of $(@($Mailboxes).Count) mailbox users have a provisioned OneDrive - worth confirming where the rest are storing work."
        }
        Add-Section 'OneDrive' 'OneDrive Consumption' 'info' $Description `
            @('Owner', 'Used', 'Of allocation', 'Files', 'Last activity') $r 'No OneDrive data.'
    }

    # ---- Archival candidates -----------------------------------------------------------------
    Invoke-Section 'ArchivalCandidates' 'Archival Candidates' {
        $Archival = Get-CIPPStorageArchivalCandidate -Sites $Sites
        $State.Archival = @($Archival.Candidates).Count
        $State.ReclaimBytes = [long]$Archival.ReclaimableBytes

        $r = New-RowList
        foreach ($C in $Archival.Candidates) {
            $r.Add(@($C.Name, (Format-Size $C.StorageBytes), "$($C.FileCount)", $C.LastActivity, "$($C.IdleDays) days", $C.Url))
        }
        foreach ($U in $Archival.UnknownActivity) {
            $r.Add(@($U.Name, (Format-Size $U.StorageBytes), "$($U.FileCount)", 'No activity ever recorded', 'Unknown', $U.Url))
        }
        $State.Count += $r.Count

        Add-Section 'ArchivalCandidates' 'Archival Candidates' `
            $(if ($State.Archival -gt 0) { 'warn' } else { 'pass' }) `
        "Sites idle 90+ days and larger than 1 GB. System sites (Tenant Admin, Compliance Policy Center, Search, My Site Host, Content Type Hub) are excluded - they are dormant by design and must not be removed. Sites with no activity ever recorded are listed separately rather than assumed idle." `
            @('Site', 'Storage', 'Files', 'Last activity', 'Idle', 'URL') $r `
            'No sites meet the archival criteria.'
    }

    # ---- Shared mailboxes ----------------------------------------------------------------------
    Invoke-Section 'SharedMailboxes' 'Shared Mailbox Storage' {
        $r = New-RowList
        $Shared = @($Mailboxes | Where-Object { ($_.recipientType -replace 'Mailbox$') -eq 'Shared' } |
                Sort-Object -Property { [long]($_.storageUsedInBytes ?? 0) } -Descending)
        foreach ($S in $Shared) {
            $Used = [long]($S.storageUsedInBytes ?? 0)
            $Hard = [long]($S.prohibitSendReceiveQuotaInBytes ?? 0)
            $r.Add(@($S.userPrincipalName, (Format-Size $Used),
                    $(if ($Hard -gt 0) { "$([math]::Round(($Used / $Hard) * 100, 1))%" } else { 'n/a' }),
                    "$([long]($S.itemCount ?? 0))",
                    $(if ($S.lastActivityDate) { ([datetime]$S.lastActivityDate).ToString('yyyy-MM-dd') } else { 'None' })))
        }
        $State.Count += $Shared.Count
        Add-Section 'SharedMailboxes' 'Shared Mailbox Storage' 'info' `
            'Shared mailboxes are capped at 50 GB without a licence, and they are the ones nobody notices filling up.' `
            @('Mailbox', 'Used', 'Of quota', 'Items', 'Last activity') $r 'No shared mailboxes.'
    }

    # ---- executive findings ----------------------------------------------------------------------
    if ($State.AtRisk -gt 0) {
        Add-Finding 'Mailboxes approaching quota' 'warn' "$($State.AtRisk) mailbox(es) are at or past 85% of their send/receive quota."
    } else {
        Add-Finding 'Mailbox quota' 'pass' 'No mailbox is within 15% of its quota.'
    }

    if ($State.StaleWarning -gt 0) {
        Add-Finding 'Stale mailbox warning quotas' 'info' "$($State.StaleWarning) mailbox(es) are showing the user Outlook quota warnings while well under their actual limit - the warning quota was not rescaled when the mailbox moved to a larger plan. A configuration fix, not a capacity problem." 
    }

    if ($State.Trend -eq 'Accelerating') {
        Add-Finding 'Storage growth accelerating' 'warn' "Consumption is growing materially faster over the last 30 days than the 90-day trend. Worth a capacity and cost conversation before it becomes urgent."
    } elseif ($State.NoHistory) {
        Add-Finding 'No history yet' 'info' 'No stored history for this tenant. Tenant totals backfill up to 180 days on the first collection; per-user and per-site growth needs several weeks.'
    }

    if ($State.Archival -gt 0) {
        Add-Finding 'Archival candidates' 'info' "$($State.Archival) SharePoint site(s) idle 90+ days, holding $(Format-Size $State.ReclaimBytes). System sites are excluded from this count."
    }

    Add-Finding 'Objects documented' 'info' "$($State.Count) storage objects captured for $TenantName."

    if ($Notes.Count -gt 0) {
        Add-Finding 'Collection warnings' 'warn' "$($Notes.Count) section(s) could not be read in full. See collection notes."
    }

    return @{
        Title           = 'M365 Storage and Usage'
        TenantName      = $TenantName
        TenantDomain    = $DefaultDomain
        GeneratedDate   = (Get-Date).ToString('dd MMMM yyyy')
        Findings        = $Findings
        Sections        = $Sections
        CollectionNotes = $Notes
        ObjectCount     = $State.Count
    }
}
