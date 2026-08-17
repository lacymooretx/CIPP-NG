# Integration coverage for the ORCHESTRATING storage functions.
#
# Why this file exists: the pure functions (merge, growth, row keys, archival, quota risk,
# suppression) were unit-tested heavily and were fine. Every defect that actually reached
# production was in the glue that was never executed even once before deploying:
#
#   1. Push-CIPPStorageSnapshot sliced a List with a range index and called .ToArray() on
#      the result. Failed on the first live run with "[System.Collections.Hashtable] does
#      not contain a method named 'ToArray'".
#   2. Get-CIPPStorageUsageReportData assigned $Mailboxes/$Sites inside Invoke-Section,
#      which runs in a child scope, so five of nine sections rendered empty against a
#      tenant with 95 mailboxes and 48 OneDrives.
#
# Both would have been caught by simply RUNNING these functions against stubs. So that is
# what this does. The stubs deliberately model the awkward parts of the real dependencies -
# a table that stores what it is given, a Graph that returns a different payload per URI -
# because a stub that is too forgiving is how bug 2 in the tenant-group tests survived
# seven passing cases.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))

    foreach ($File in @(
            'Modules/CIPPCore/Public/Storage/ConvertTo-CIPPStorageTrendRow.ps1'
            'Modules/CIPPCore/Public/Storage/ConvertTo-CIPPStorageRowKey.ps1'
            'Modules/CIPPCore/Public/Storage/Get-CIPPStorageGrowth.ps1'
            'Modules/CIPPCore/Public/Storage/Get-CIPPStorageArchivalCandidate.ps1'
            'Modules/CIPPCore/Public/Storage/Get-CIPPMailboxQuotaRisk.ps1'
            'Modules/CIPPCore/Public/Storage/Get-CIPPStorageTrend.ps1'
            'Modules/CIPPCore/Public/Storage/Get-CIPPStorageSnapshot.ps1'
            'Modules/CIPPCore/Public/Storage/Push-CIPPStorageSnapshot.ps1'
            'Modules/CIPPCore/Public/TenantGroups/Test-CIPPTenantManaged.ps1'
            'Modules/CIPPCore/Public/Reports/Get-CIPPStorageUsageReportData.ps1'
        )) { . (Join-Path $RepoRoot $File) }

    # ---- in-memory Azure Table -----------------------------------------------------
    # Globals, not $script:, so the helpers resolve to the same container Pester made.
    $global:Tables = @{}
    # One parameter, not two: PowerShell binds parameter names case-insensitively, so
    # -tablename and -TableName reach the same one. Declaring both is a parse error.
    function Get-CippTable { param($TableName) @{ Table = $TableName } }
    function Get-CIPPTable { param($TableName) @{ Table = $TableName } }

    function Add-CIPPAzDataTableEntity {
        param($Table, $Entity, [switch]$Force)
        if (-not $global:Tables.ContainsKey($Table)) { $global:Tables[$Table] = @{} }
        # The real SDK takes an array for a batch. Reject anything that is not enumerable
        # in the way the caller promised - this is the assertion that would have caught the
        # ToArray bug even if the code had not thrown first.
        foreach ($E in @($Entity)) {
            if ($E -isnot [hashtable] -and $E -isnot [pscustomobject]) {
                throw "Add-CIPPAzDataTableEntity got a $($E.GetType().Name), expected hashtable entities"
            }
            $global:Tables[$Table]["$($E.PartitionKey)|$($E.RowKey)"] = [pscustomobject]$E
        }
    }
    function Get-CIPPAzDataTableEntity {
        param($Table, $Filter, $Property)
        $Rows = @()
        if ($global:Tables.ContainsKey($Table)) { $Rows = @($global:Tables[$Table].Values) }
        if ($Filter -match "PartitionKey eq '([^']+)'") {
            $Pk = $Matches[1]
            $Rows = @($Rows | Where-Object { $_.PartitionKey -eq $Pk })
        }
        # Honour the RowKey prefix range the readers rely on: RowKey ge 'X' and RowKey lt 'Y'
        if ($Filter -match "RowKey ge '([^']+)' and RowKey lt '([^']+)'") {
            $Lo = $Matches[1]; $Hi = $Matches[2]
            $Rows = @($Rows | Where-Object { [string]$_.RowKey -ge $Lo -and [string]$_.RowKey -lt $Hi })
        }
        return $Rows
    }

    # ---- tenant + group stubs --------------------------------------------------------
    $global:ManagedDomains = @('managed.com')
    function Get-Tenants {
        param($TenantFilter, [switch]$IncludeErrors)
        if (-not $TenantFilter) { return @() }
        [pscustomobject]@{ defaultDomainName = $TenantFilter; displayName = "Tenant $TenantFilter"; customerId = 'cid-1' }
    }
    function Get-TenantGroups {
        param($TenantFilter, $GroupId, [switch]$SkipCache)
        if ($global:ManagedDomains -contains $TenantFilter) {
            return @([pscustomobject]@{ Name = 'Managed Clients' })
        }
        return @([pscustomobject]@{ Name = 'Unmanaged Clients' })
    }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $headers, $LogData) }
    function Get-CippException { param($Exception) @{ NormalizedError = "$Exception" } }

    # ---- Graph stub ------------------------------------------------------------------
    # One payload per report function, matching the SHAPES observed live: the mailbox
    # aggregate has no siteType, SharePoint has only 'All', and OneDrive returns BOTH an
    # 'OneDrive' row and an 'All' row for the same date.
    function Script:NewSeries($Days, $Base, $PerDay, $SiteType, $Dup) {
        $Start = [datetime]::Parse('2026-01-01', [cultureinfo]::InvariantCulture)
        $Out = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $Days; $i++) {
            $Row = @{ reportDate = $Start.AddDays($i).ToString('yyyy-MM-dd'); storageUsedInBytes = [long]($Base + $PerDay * $i); reportRefreshDate = '2026-08-14' }
            if ($SiteType) { $Row.siteType = $SiteType }
            $Out.Add([pscustomobject]$Row)
            if ($Dup) {
                $D = $Row.Clone(); $D.siteType = 'All'
                $Out.Add([pscustomobject]$D)
            }
        }
        return $Out
    }

    $global:GraphCalls = [System.Collections.Generic.List[string]]::new()
    $global:ConcealNames = $false
    function New-GraphGetRequest {
        param($uri, $tenantid, $AsApp, $NoAuthCheck, $Stream)
        $global:GraphCalls.Add($uri)
        switch -Regex ($uri) {
            'getMailboxUsageStorage' { return Script:NewSeries 180 (10GB) (100MB) $null $false }
            'getOneDriveUsageStorage' { return Script:NewSeries 180 (20GB) (200MB) 'OneDrive' $true }
            'getSharePointSiteUsageStorage' { return Script:NewSeries 180 (5GB) (50MB) 'All' $false }
            'admin/reportSettings' { return [pscustomobject]@{ displayConcealedNames = $global:ConcealNames } }
            'getMailboxUsageDetail' {
                return @(
                    [pscustomobject]@{ userPrincipalName = 'atrisk@managed.com'; displayName = 'At Risk'; isDeleted = $false
                        storageUsedInBytes = [long]48GB; issueWarningQuotaInBytes = [long]45GB
                        prohibitSendReceiveQuotaInBytes = [long]50GB; itemCount = 1000; hasArchive = $true
                        recipientType = 'User'; reportRefreshDate = '2026-08-14'; lastActivityDate = '2026-08-13'
                    }
                    [pscustomobject]@{ userPrincipalName = 'stale@managed.com'; displayName = 'Stale Warning'; isDeleted = $false
                        storageUsedInBytes = [long]60GB; issueWarningQuotaInBytes = [long]45GB
                        prohibitSendReceiveQuotaInBytes = [long]100GB; itemCount = 2000; hasArchive = $true
                        recipientType = 'User'; reportRefreshDate = '2026-08-14'; lastActivityDate = '2026-08-13'
                    }
                    [pscustomobject]@{ userPrincipalName = 'shared@managed.com'; displayName = 'Shared'; isDeleted = $false
                        storageUsedInBytes = [long]2GB; issueWarningQuotaInBytes = [long]45GB
                        prohibitSendReceiveQuotaInBytes = [long]50GB; itemCount = 50; hasArchive = $false
                        recipientType = 'Shared'; reportRefreshDate = '2026-08-14'; lastActivityDate = '2026-08-01'
                    }
                    [pscustomobject]@{ userPrincipalName = 'gone@managed.com'; isDeleted = $true }
                )
            }
            '/organization' { return @([pscustomobject]@{ displayName = 'Managed Co'; verifiedDomains = @([pscustomobject]@{ name = 'managed.com'; isDefault = $true }) }) }
        }
        return @()
    }

    # ---- SiteActivity cache stub -------------------------------------------------------
    function Get-CIPPDbItem {
        param($TenantFilter, $Type, [switch]$CountsOnly)
        if ($Type -ne 'SiteActivity') { return @() }
        $Sites = @(
            @{ siteId = 's1'; displayName = 'Old Archive'; webUrl = 'https://x.sharepoint.com/sites/OldArchive'
                rootWebTemplate = 'Group'; isPersonalSite = $false; isDeleted = $false
                sharePointStorageUsedInBytes = [long]40GB; sharePointFileCount = 22; effectiveLastActivityDate = '2023-01-01' }
            @{ siteId = 's2'; displayName = 'Active Site'; webUrl = 'https://x.sharepoint.com/sites/Active'
                rootWebTemplate = 'Group'; isPersonalSite = $false; isDeleted = $false
                sharePointStorageUsedInBytes = [long]10GB; sharePointFileCount = 500; effectiveLastActivityDate = '2026-08-14' }
            @{ siteId = 's3'; displayName = 'Tenant Admin'; webUrl = 'https://x-admin.sharepoint.com/'
                rootWebTemplate = 'Tenant Admin Site'; isPersonalSite = $false; isDeleted = $false
                sharePointStorageUsedInBytes = [long]30GB; sharePointFileCount = 2; effectiveLastActivityDate = '2019-01-01' }
            @{ siteId = 's4'; displayName = 'A Person'; ownerPrincipalName = 'person@managed.com'
                webUrl = 'https://x-my.sharepoint.com/personal/person'; isPersonalSite = $true; isDeleted = $false
                oneDriveStorageUsedInBytes = [long]100GB; oneDriveStorageAllocatedInBytes = [long]1TB
                oneDriveFileCount = 900; effectiveLastActivityDate = '2026-08-13' }
        )
        return @($Sites | ForEach-Object {
                [pscustomobject]@{ RowKey = "SiteActivity-$($_.siteId)"; Data = ($_ | ConvertTo-Json -Depth 5 -Compress) }
            })
    }

    function Reset-Harness {
        $global:Tables = @{}
        $global:GraphCalls.Clear()
        $global:ConcealNames = $false
    }
}

Describe 'Push-CIPPStorageSnapshot (integration)' {
    BeforeEach { Reset-Harness }

    It 'runs end to end and writes both tables' {
        # The bug that reached production threw before writing anything. Simply invoking
        # this function once would have caught it.
        $R = Push-CIPPStorageSnapshot -TenantFilter 'managed.com'

        $R.Status | Should -Be 'Success'
        $R.Errors.Count | Should -Be 0
        $R.CollectionNotes.Count | Should -Be 0
        $R.TrendRows | Should -Be 180
        $R.MailboxRows | Should -Be 3      # the deleted one is skipped
        $R.SiteRows | Should -Be 4
        $R.SnapshotDate | Should -Be '2026-08-14'
    }

    It 'writes 180 trend rows across multiple batches without losing any' {
        # 180 rows crosses the 100-row flush boundary, which is exactly where the slicing
        # bug lived. Anything less than 180 stored means a batch was dropped.
        $null = Push-CIPPStorageSnapshot -TenantFilter 'managed.com'
        $global:Tables['CippStorageTrend'].Count | Should -Be 180
    }

    It 'is idempotent - a second run does not duplicate a day' {
        $null = Push-CIPPStorageSnapshot -TenantFilter 'managed.com'
        $null = Push-CIPPStorageSnapshot -TenantFilter 'managed.com'
        $global:Tables['CippStorageTrend'].Count | Should -Be 180
    }

    It 'does not double-count OneDrive when Graph returns both a typed and an All row' {
        # Observed live: getOneDriveUsageStorage returns siteType 'OneDrive' AND 'All' with
        # identical values for the same date. Summing them doubles every OneDrive figure.
        $null = Push-CIPPStorageSnapshot -TenantFilter 'managed.com'
        $Row = $global:Tables['CippStorageTrend'].Values | Where-Object { $_.Date -eq '2026-01-01' }
        $Row.OneDriveBytes | Should -Be ([long]20GB)
    }

    It 'refuses an unmanaged tenant and writes nothing' {
        $R = Push-CIPPStorageSnapshot -TenantFilter 'unmanaged.com'
        $R.Status | Should -Be 'SkippedNotManaged'
        $global:Tables.Keys.Count | Should -Be 0
    }

    It 'refuses to persist detail when report names are pseudonymised' {
        $global:ConcealNames = $true
        $R = Push-CIPPStorageSnapshot -TenantFilter 'managed.com'
        $R.Status | Should -Be 'PartialConcealed'
        $R.MailboxRows | Should -Be 0
        # The trend rollup carries no names, so it is still written.
        $global:Tables['CippStorageTrend'].Count | Should -Be 180
        $global:Tables.ContainsKey('CippStorageSnapshot') | Should -BeFalse
    }
}

Describe 'Get-CIPPStorageUsageReportData (integration)' {
    BeforeEach {
        Reset-Harness
        $null = Push-CIPPStorageSnapshot -TenantFilter 'managed.com'
    }

    It 'populates every section, not just the ones that fetch their own data' {
        # THE regression test for the child-scope bug. Five of nine sections rendered empty
        # in production because they read a variable another section had assigned inside a
        # scriptblock. Asserting "9 sections exist" would NOT have caught it - the sections
        # existed, they were just empty. Row counts are what matters.
        $Model = Get-CIPPStorageUsageReportData -TenantFilter 'managed.com'
        $Model.Sections.Count | Should -Be 9

        $ByKey = @{}
        foreach ($S in $Model.Sections) { $ByKey[$S.Key] = $S }

        foreach ($Key in @('Summary', 'Growth', 'MailboxRisk', 'QuotaWarningConfig',
                'TopMailboxes', 'SharePointSites', 'OneDrive', 'ArchivalCandidates', 'SharedMailboxes')) {
            $ByKey.ContainsKey($Key) | Should -BeTrue -Because "section $Key must exist"
            @($ByKey[$Key].Rows).Count | Should -BeGreaterThan 0 -Because "section $Key must have rows, not just a heading"
        }
    }

    It 'classifies the two mailbox cases the way production data demanded' {
        $Model = Get-CIPPStorageUsageReportData -TenantFilter 'managed.com'
        $ByKey = @{}; foreach ($S in $Model.Sections) { $ByKey[$S.Key] = $S }

        # 48 of 50 GB -> a real capacity finding.
        (@($ByKey['MailboxRisk'].Rows) | ForEach-Object { $_[0] }) | Should -Contain 'atrisk@managed.com'
        # 60 of 100 GB with a 45 GB warning quota -> configuration, never a capacity ticket.
        (@($ByKey['MailboxRisk'].Rows) | ForEach-Object { $_[0] }) | Should -Not -Contain 'stale@managed.com'
        (@($ByKey['QuotaWarningConfig'].Rows) | ForEach-Object { $_[0] }) | Should -Contain 'stale@managed.com'
    }

    It 'excludes system sites and personal OneDrives from archival candidates' {
        $Model = Get-CIPPStorageUsageReportData -TenantFilter 'managed.com'
        $ByKey = @{}; foreach ($S in $Model.Sections) { $ByKey[$S.Key] = $S }
        $Names = @($ByKey['ArchivalCandidates'].Rows | ForEach-Object { $_[0] })
        $Names | Should -Contain 'Old Archive'
        $Names | Should -Not -Contain 'Tenant Admin'
        $Names | Should -Not -Contain 'Active Site'
        $Names | Should -Not -Contain 'A Person'
    }

    It 'reports real growth from the persisted history rather than a flat line' {
        $Model = Get-CIPPStorageUsageReportData -TenantFilter 'managed.com'
        $Growth = @($Model.Sections | Where-Object { $_.Key -eq 'Growth' })[0]
        $Trend = @($Growth.Rows | Where-Object { $_[0] -eq 'Trend' })[0]
        $Trend[1] | Should -BeIn @('Growing', 'Accelerating')
        @($Growth.Rows | Where-Object { $_[0] -eq 'History held' })[0][1] | Should -Be '180 days'
    }

    It 'returns a one-section explanation for an unmanaged tenant' {
        $Model = Get-CIPPStorageUsageReportData -TenantFilter 'unmanaged.com'
        $Model.Sections.Count | Should -Be 1
        $Model.ObjectCount | Should -Be 0
        @($Model.Findings | ForEach-Object { $_.Title }) | Should -Contain 'Not a managed client'
    }

    It 'says so plainly when there is no history yet, instead of drawing zeros' {
        Reset-Harness   # tables emptied, no snapshot taken
        $Model = Get-CIPPStorageUsageReportData -TenantFilter 'managed.com'
        @($Model.CollectionNotes | ForEach-Object { $_.Detail }) -join ' ' | Should -Match 'No stored storage history'
        @($Model.Findings | ForEach-Object { $_.Title }) | Should -Contain 'No history yet'
    }
}

Describe 'Storage readers (integration)' {
    BeforeEach {
        Reset-Harness
        $null = Push-CIPPStorageSnapshot -TenantFilter 'managed.com'
    }

    It 'reads the trend back oldest-first' {
        $T = Get-CIPPStorageTrend -TenantFilter 'managed.com'
        $T.Days | Should -Be 180
        $T.Series[0].Date | Should -Be '2026-01-01'
        $T.Latest.Date | Should -Be '2026-06-29'
    }

    It 'honours the Days window' {
        (Get-CIPPStorageTrend -TenantFilter 'managed.com' -Days 30).Series.Count | Should -Be 30
    }

    It 'selects snapshot rows by scope without returning the other scope' {
        $Mbx = Get-CIPPStorageSnapshot -TenantFilter 'managed.com' -Scope 'Mailbox'
        $Site = Get-CIPPStorageSnapshot -TenantFilter 'managed.com' -Scope 'Site'
        $Mbx.Items.Count | Should -Be 3
        $Site.Items.Count | Should -Be 4
        @($Mbx.Items | ForEach-Object { $_.userPrincipalName }) | Should -Not -Contain $null
    }
}
