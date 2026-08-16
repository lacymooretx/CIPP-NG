# Storage trending: the parts where being wrong is silent.
#
# A storage chart that is subtly wrong is worse than no chart, because nobody re-derives a
# number that already has a graph next to it. The three things tested here are the ones that
# would go unnoticed in production: a reporting gap rendered as a cliff, a RowKey that fails
# a whole batch, and a growth projection extrapolated from noise.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Storage/ConvertTo-CIPPStorageTrendRow.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Storage/ConvertTo-CIPPStorageRowKey.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Storage/Get-CIPPStorageGrowth.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Storage/Get-CIPPStorageArchivalCandidate.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Storage/Get-CIPPMailboxQuotaRisk.ps1')

    function Mbx($Upn, $Used, $Warn, $Hard) {
        [pscustomobject]@{
            userPrincipalName = $Upn; displayName = $Upn; isDeleted = $false
            storageUsedInBytes = [long]$Used; issueWarningQuotaInBytes = [long]$Warn
            prohibitSendReceiveQuotaInBytes = [long]$Hard; itemCount = 100
            hasArchive = $true; recipientType = 'User'
        }
    }

    # A site as stored from the SiteActivity cache.
    function Site($Name, $Template, $Bytes, $LastActivity, $Personal, $Url) {
        [pscustomobject]@{
            displayName                  = $Name
            rootWebTemplate              = $Template
            sharePointStorageUsedInBytes = $Bytes
            sharePointFileCount          = 10
            effectiveLastActivityDate    = $LastActivity
            isPersonalSite               = [bool]$Personal
            isDeleted                    = $false
            webUrl                       = $(if ($Url) { $Url } else { "https://x.sharepoint.com/sites/$Name" })
        }
    }

    function Day($Date, $Bytes, $SiteType) {
        $o = [pscustomobject]@{ reportDate = $Date; storageUsedInBytes = $Bytes }
        if ($SiteType) { $o | Add-Member -NotePropertyName siteType -NotePropertyValue $SiteType }
        $o
    }
    # A clean series growing by a fixed amount each day.
    function Series($Start, $Days, $Base, $PerDay) {
        $d = [datetime]::Parse($Start, [cultureinfo]::InvariantCulture)
        0..($Days - 1) | ForEach-Object {
            [pscustomobject]@{
                Date = $d.AddDays($_).ToString('yyyy-MM-dd')
                TotalBytes = [long]($Base + ($PerDay * $_))
            }
        }
    }
}

Describe 'ConvertTo-CIPPStorageTrendRow' {

    It 'merges the three workloads into one row per date' {
        $Rows = @(ConvertTo-CIPPStorageTrendRow `
                -MailboxSeries @((Day '2026-08-01' 100), (Day '2026-08-02' 110)) `
                -OneDriveSeries @((Day '2026-08-01' 200), (Day '2026-08-02' 220)) `
                -SharePointSeries @((Day '2026-08-01' 300), (Day '2026-08-02' 330)))

        $Rows.Count | Should -Be 2
        $Rows[0].Date | Should -Be '2026-08-01'
        $Rows[0].TotalBytes | Should -Be 600
        $Rows[1].TotalBytes | Should -Be 660
    }

    It 'carries a missing day forward instead of dropping it to zero' {
        # The whole point. A hole in Microsoft's reporting is not a day on which the client
        # deleted their mail; zeroing it would draw a cliff and then a fake spike.
        $Rows = @(ConvertTo-CIPPStorageTrendRow `
                -MailboxSeries @((Day '2026-08-01' 100), (Day '2026-08-03' 130)) `
                -OneDriveSeries @((Day '2026-08-01' 200), (Day '2026-08-02' 210), (Day '2026-08-03' 220)) `
                -SharePointSeries @())

        $Rows.Count | Should -Be 3
        $Rows[1].Date | Should -Be '2026-08-02'
        $Rows[1].MailboxBytes | Should -Be 100      # carried, not 0
        $Rows[1].TotalBytes | Should -Be 310
        # ...and the record says the mailbox figure was not measured that day.
        $Rows[1].MeasuredWorkloads | Should -Be 'OneDrive'
        $Rows[2].MeasuredWorkloads | Should -Be 'Mailbox,OneDrive'
    }

    It 'treats a workload with no data at all as zero' {
        # A tenant with no OneDrive genuinely has 0 bytes of it - that is not a gap.
        $Rows = @(ConvertTo-CIPPStorageTrendRow `
                -MailboxSeries @((Day '2026-08-01' 100)) -OneDriveSeries @() -SharePointSeries $null)
        $Rows.Count | Should -Be 1
        $Rows[0].OneDriveBytes | Should -Be 0
        $Rows[0].TotalBytes | Should -Be 100
    }

    It "prefers Microsoft's All rollup row over summing the per-type rows" {
        # Summing 'All' together with its own components would double-count the day.
        $Rows = @(ConvertTo-CIPPStorageTrendRow -MailboxSeries @() -OneDriveSeries @() `
                -SharePointSeries @((Day '2026-08-01' 500 'All'), (Day '2026-08-01' 300 'Group'), (Day '2026-08-01' 200 'Team Site')))
        $Rows[0].SharePointBytes | Should -Be 500
    }

    It 'sums per-type rows when there is no All rollup' {
        $Rows = @(ConvertTo-CIPPStorageTrendRow -MailboxSeries @() -OneDriveSeries @() `
                -SharePointSeries @((Day '2026-08-01' 300 'Group'), (Day '2026-08-01' 200 'Team Site')))
        $Rows[0].SharePointBytes | Should -Be 500
    }

    It 'returns dates in ascending order regardless of input order' {
        # Carry-forward is only correct if the walk is chronological.
        $Rows = @(ConvertTo-CIPPStorageTrendRow `
                -MailboxSeries @((Day '2026-08-03' 130), (Day '2026-08-01' 100), (Day '2026-08-02' 120)) `
                -OneDriveSeries @() -SharePointSeries @())
        @($Rows | ForEach-Object { $_.Date }) | Should -Be @('2026-08-01', '2026-08-02', '2026-08-03')
    }

    It 'ignores rows with an unparseable or missing date rather than throwing' {
        $Rows = @(ConvertTo-CIPPStorageTrendRow `
                -MailboxSeries @((Day '2026-08-01' 100), (Day 'not-a-date' 999), (Day $null 999)) `
                -OneDriveSeries @() -SharePointSeries @())
        $Rows.Count | Should -Be 1
        $Rows[0].MailboxBytes | Should -Be 100
    }

    It 'returns nothing when every series is empty' {
        @(ConvertTo-CIPPStorageTrendRow -MailboxSeries @() -OneDriveSeries @() -SharePointSeries @()).Count | Should -Be 0
    }
}

Describe 'ConvertTo-CIPPStorageRowKey' {

    It 'builds a scope- and date-prefixed key so a range scan can select them' {
        ConvertTo-CIPPStorageRowKey -Scope 'Mailbox' -Date '20260814' -Id 'lacy@aspendora.com' |
            Should -Be 'Mailbox-20260814-lacy@aspendora.com'
    }

    It 'strips characters Azure Table rejects in a RowKey' {
        # One bad identifier would otherwise fail the entire 100-row transaction.
        $Key = ConvertTo-CIPPStorageRowKey -Scope 'Site' -Date '20260814' -Id 'sites/HR#main?x'
        $Key | Should -Not -Match '[\\/#?]'
        $Key | Should -Match '^Site-20260814-'
    }

    It 'keeps two identifiers distinct after sanitising' {
        # 'a/b' and 'a#b' both sanitise to 'a_b'; the appended hash is what stops them
        # colliding onto one row and silently losing an object from the snapshot.
        $A = ConvertTo-CIPPStorageRowKey -Scope 'Site' -Date '20260814' -Id 'a/b'
        $B = ConvertTo-CIPPStorageRowKey -Scope 'Site' -Date '20260814' -Id 'a#b'
        $A | Should -Not -Be $B
    }

    It 'leaves a clean identifier unhashed' {
        ConvertTo-CIPPStorageRowKey -Scope 'Site' -Date '20260814' -Id 'abc-123' |
            Should -Be 'Site-20260814-abc-123'
    }

    It 'stays within the 1024 character key limit' {
        (ConvertTo-CIPPStorageRowKey -Scope 'Mailbox' -Date '20260814' -Id ('x' * 2000)).Length |
            Should -BeLessOrEqual 1024
    }
}

Describe 'Get-CIPPStorageGrowth' {

    It 'computes the per-day rate from a steady series' {
        $G = Get-CIPPStorageGrowth -Series (Series '2026-01-01' 100 1000000000 5000000)
        $G.BytesPerDay | Should -Be 5000000
        $G.Days | Should -Be 100
        $G.Confidence | Should -Be 'High'
        $G.Trend | Should -Be 'Growing'
    }

    It 'is not reported as shrinking because of one old step down' {
        # Reproduces Aspendora, 2026: ~1.27 TB, a ~315 GB cleanup in March, steady growth
        # since. A least-squares slope over the whole window called this "shrinking
        # 973 MB/day" while every shorter window said it was growing. Acting on that would
        # mean doing nothing for a client that has grown 6% since the cleanup.
        $Points = [System.Collections.Generic.List[object]]::new()
        $Value = [long]1200GB
        $Start = [datetime]::Parse('2026-01-01', [cultureinfo]::InvariantCulture)
        for ($i = 0; $i -lt 180; $i++) {
            if ($i -eq 60) { $Value -= [long]315GB } else { $Value += [long]400MB }
            $Points.Add([pscustomobject]@{ Date = $Start.AddDays($i).ToString('yyyy-MM-dd'); TotalBytes = $Value })
        }

        $G = Get-CIPPStorageGrowth -Series $Points
        $G.Trend | Should -Be 'Growing'
        $G.BytesPerDay | Should -BeGreaterThan 0
        $G.MedianBytesPerDay | Should -Be ([long]400MB)
        # The step is reported rather than silently averaged away.
        $G.StepChanges.Count | Should -Be 1
        $G.StepChanges[0].ChangeBytes | Should -BeLessThan 0
        # The 180-day window still shows the drop - it is not hidden, just not the basis.
        $G.Windows['180'].ChangeBytes | Should -BeLessThan 0
        $G.BasisWindowDays | Should -Be 90
    }

    It 'flags an accelerating client instead of averaging the acceleration away' {
        # Reproduces 3E NDT: 30-day rate roughly 7x the long-run median.
        $Points = [System.Collections.Generic.List[object]]::new()
        $Value = [long]2000GB
        $Start = [datetime]::Parse('2026-01-01', [cultureinfo]::InvariantCulture)
        for ($i = 0; $i -lt 180; $i++) {
            $Value += $(if ($i -ge 150) { [long]9GB } else { [long]1GB })
            $Points.Add([pscustomobject]@{ Date = $Start.AddDays($i).ToString('yyyy-MM-dd'); TotalBytes = $Value })
        }

        $G = Get-CIPPStorageGrowth -Series $Points
        $G.Trend | Should -Be 'Accelerating'
        $G.Windows['30'].BytesPerDay | Should -BeGreaterThan $G.Windows['90'].BytesPerDay
    }

    It 'projects from the 90-day window rather than the whole history' {
        $G = Get-CIPPStorageGrowth -Series (Series '2026-01-01' 180 ([long]100GB) ([long]1GB)) -QuotaBytes ([long]1TB)
        $G.BasisWindowDays | Should -Be 90
        $G.ProjectedFullDate | Should -Not -BeNullOrEmpty
    }

    It 'still produces a rate on a short history with no full window' {
        # A two-week-old deployment should get a number, not silence.
        $G = Get-CIPPStorageGrowth -Series (Series '2026-01-01' 10 ([long]10GB) ([long]100MB))
        $G.BytesPerDay | Should -BeGreaterThan 0
        $G.Confidence | Should -Be 'Low'
    }

    It 'reports zero days when the series has already reached the quota' {
        # Start 10 GB, +1 GB/day for 11 points -> exactly 20 GB on the last day.
        $G = Get-CIPPStorageGrowth -Series (Series '2026-01-01' 11 ([long]10GB) ([long]1GB)) -QuotaBytes ([long]20GB)
        $G.LatestBytes | Should -Be ([long]20GB)
        $G.DaysUntilFull | Should -Be 0
        $G.Note | Should -Match 'at or over the quota'
    }

    It 'projects a future date when there is headroom' {
        $S = Series '2026-01-01' 30 ([long]10GB) ([long]100MB)
        $G = Get-CIPPStorageGrowth -Series $S -QuotaBytes ([long]20GB)
        $G.DaysUntilFull | Should -BeGreaterThan 0
        $G.ProjectedFullDate | Should -Not -BeNullOrEmpty
    }

    It 'refuses to project a flat series' {
        # A confident date derived from no growth is a lie with a graph next to it.
        $S = Series '2026-01-01' 30 ([long]10GB) 0
        $G = Get-CIPPStorageGrowth -Series $S -QuotaBytes ([long]20GB)
        $G.ProjectedFullDate | Should -BeNullOrEmpty
        $G.Note | Should -Match 'flat or falling'
    }

    It 'refuses to project a shrinking series' {
        $S = Series '2026-01-01' 30 ([long]10GB) (-1 * [long]10MB)
        $G = Get-CIPPStorageGrowth -Series $S -QuotaBytes ([long]20GB)
        $G.ProjectedFullDate | Should -BeNullOrEmpty
    }

    It 'reports low confidence on a short window' {
        $S = Series '2026-01-01' 3 ([long]10GB) ([long]100MB)
        (Get-CIPPStorageGrowth -Series $S).Confidence | Should -Be 'Low'
    }

    It 'declines to calculate from a single point' {
        $G = Get-CIPPStorageGrowth -Series (Series '2026-01-01' 1 ([long]10GB) 0)
        $G.Days | Should -Be 1
        $G.BytesPerDay | Should -Be 0
        $G.Note | Should -Match 'Not enough history'
    }

    It 'handles an empty or null series without throwing' {
        (Get-CIPPStorageGrowth -Series @()).Days | Should -Be 0
        (Get-CIPPStorageGrowth -Series $null).Days | Should -Be 0
    }

    It 'is not dragged off course by a single final-day spike' {
        # Regression against last-minus-first. A one-off 50 GB export on the last day would
        # have set the entire projection; regression lets the other 29 days outvote it.
        $S = [System.Collections.Generic.List[object]]::new()
        $S.AddRange([object[]](Series '2026-01-01' 30 ([long]10GB) ([long]10MB)))
        $S.Add([pscustomobject]@{ Date = '2026-01-31'; TotalBytes = [long]($S[-1].TotalBytes + [long]50GB) })
        $G = Get-CIPPStorageGrowth -Series $S
        # A naive last-minus-first slope would be ~1.7 GB/day; the true trend is 10 MB/day.
        $G.BytesPerDay | Should -BeLessThan ([long]1GB)
    }

    It 'uses real date gaps rather than row position' {
        # Two points a month apart is 1 MB/day, not 1 MB per "row".
        $S = @(
            [pscustomobject]@{ Date = '2026-01-01'; TotalBytes = [long]0 }
            [pscustomobject]@{ Date = '2026-01-31'; TotalBytes = [long]30MB }
        )
        (Get-CIPPStorageGrowth -Series $S).BytesPerDay | Should -Be ([long]1MB)
    }

    It 'does not project more than ten years out' {
        $S = Series '2026-01-01' 90 ([long]1GB) 1
        $G = Get-CIPPStorageGrowth -Series $S -QuotaBytes ([long]10TB)
        $G.ProjectedFullDate | Should -BeNullOrEmpty
        $G.Note | Should -Match 'ten years'
    }
}

Describe 'Get-CIPPStorageArchivalCandidate' {

    BeforeAll { $Now = [datetime]::Parse('2026-08-16', [cultureinfo]::InvariantCulture) }

    It 'flags a large, genuinely idle team site' {
        $R = Get-CIPPStorageArchivalCandidate -AsOf $Now -Sites @(
            (Site 'Old Projects' 'Group' ([long]40GB) '2024-01-01' $false $null))
        $R.Candidates.Count | Should -Be 1
        $R.Candidates[0].Name | Should -Be 'Old Projects'
        $R.ReclaimableBytes | Should -Be ([long]40GB)
    }

    It 'excludes the Microsoft system sites that are dormant by design' {
        # Reproduces Trinity Bay, where a naive 90-day rule flagged six sites the client
        # must not touch. The first recommendation being "delete your Tenant Admin Site"
        # is how a report stops being read.
        $R = Get-CIPPStorageArchivalCandidate -AsOf $Now -Sites @(
            (Site 'Admin' 'Tenant Admin Site' ([long]40GB) '2019-01-01' $false $null)
            (Site 'MySites' 'My Site Host' ([long]40GB) '2019-01-01' $false $null)
            (Site 'Compliance' 'Compliance Policy Center' ([long]40GB) '2019-01-01' $false $null)
            (Site 'Search' 'Enterprise Search Center' ([long]40GB) '2019-01-01' $false $null)
            (Site 'Video' 'Video Portal' ([long]40GB) '2019-01-01' $false $null)
        )
        $R.Candidates.Count | Should -Be 0
    }

    It 'excludes the Content Type Hub, whose template looks like a real team site' {
        # rootWebTemplate is 'Team Site' - only the URL gives it away.
        $R = Get-CIPPStorageArchivalCandidate -AsOf $Now -Sites @(
            (Site 'Team Site' 'Team Site' ([long]40GB) '2019-01-01' $false 'https://x.sharepoint.com/sites/contentTypeHub'))
        $R.Candidates.Count | Should -Be 0
    }

    It 'excludes personal OneDrive sites' {
        # A dormant OneDrive is a leaver question, not a SharePoint archival one.
        $R = Get-CIPPStorageArchivalCandidate -AsOf $Now -Sites @(
            (Site 'Someone' $null ([long]40GB) '2019-01-01' $true $null))
        $R.Candidates.Count | Should -Be 0
    }

    It 'ignores sites below the size floor' {
        $R = Get-CIPPStorageArchivalCandidate -AsOf $Now -Sites @(
            (Site 'Tiny' 'Group' ([long]2MB) '2019-01-01' $false $null))
        $R.Candidates.Count | Should -Be 0
    }

    It 'ignores sites that are idle but not idle enough' {
        $R = Get-CIPPStorageArchivalCandidate -AsOf $Now -Sites @(
            (Site 'Recent' 'Group' ([long]40GB) '2026-08-01' $false $null))
        $R.Candidates.Count | Should -Be 0
    }

    It 'separates never-reported sites from idle ones rather than assuming they are dead' {
        # Never used and never reported look identical here. Recommending deletion of
        # something we have no telemetry for is the same mistake in a different costume.
        $R = Get-CIPPStorageArchivalCandidate -AsOf $Now -Sites @(
            (Site 'Unknown' 'Group' ([long]40GB) $null $false $null)
            (Site 'Idle' 'Group' ([long]10GB) '2020-01-01' $false $null))
        $R.Candidates.Count | Should -Be 1
        $R.Candidates[0].Name | Should -Be 'Idle'
        $R.UnknownActivity.Count | Should -Be 1
        $R.UnknownActivity[0].Name | Should -Be 'Unknown'
        # The unknown one must NOT inflate the reclaimable figure.
        $R.ReclaimableBytes | Should -Be ([long]10GB)
    }

    It 'sorts candidates largest first' {
        $R = Get-CIPPStorageArchivalCandidate -AsOf $Now -Sites @(
            (Site 'Small' 'Group' ([long]5GB) '2020-01-01' $false $null)
            (Site 'Big' 'Group' ([long]50GB) '2020-01-01' $false $null))
        $R.Candidates[0].Name | Should -Be 'Big'
    }

    It 'handles an empty or null site list' {
        (Get-CIPPStorageArchivalCandidate -Sites @()).Candidates.Count | Should -Be 0
        (Get-CIPPStorageArchivalCandidate -Sites $null).Candidates.Count | Should -Be 0
    }
}

Describe 'Growth trend materiality' {

    It 'does not label a trivially small acceleration as Accelerating' {
        # Reproduces Trinity Bay: 30-day 75 MB/day against 90-day 31 MB/day. A doubling,
        # arithmetically - and far too small to put a warning on a client report.
        $Points = [System.Collections.Generic.List[object]]::new()
        $Value = [long]159GB
        $Start = [datetime]::Parse('2026-01-01', [cultureinfo]::InvariantCulture)
        for ($i = 0; $i -lt 120; $i++) {
            $Value += $(if ($i -ge 90) { [long]75MB } else { [long]20MB })
            $Points.Add([pscustomobject]@{ Date = $Start.AddDays($i).ToString('yyyy-MM-dd'); TotalBytes = $Value })
        }
        $G = Get-CIPPStorageGrowth -Series $Points
        $G.Trend | Should -Be 'Growing'
    }

    It 'still labels a material acceleration' {
        $Points = [System.Collections.Generic.List[object]]::new()
        $Value = [long]2000GB
        $Start = [datetime]::Parse('2026-01-01', [cultureinfo]::InvariantCulture)
        for ($i = 0; $i -lt 120; $i++) {
            $Value += $(if ($i -ge 90) { [long]9GB } else { [long]1GB })
            $Points.Add([pscustomobject]@{ Date = $Start.AddDays($i).ToString('yyyy-MM-dd'); TotalBytes = $Value })
        }
        (Get-CIPPStorageGrowth -Series $Points).Trend | Should -Be 'Accelerating'
    }
}

Describe 'Get-CIPPMailboxQuotaRisk' {

    It 'flags a mailbox genuinely close to its hard quota' {
        # ken@3endt.com: 47.13 GB of 50 GB. Real - about to stop receiving mail.
        $R = Get-CIPPMailboxQuotaRisk -Mailboxes @((Mbx 'ken@x.com' 50603098771 48318382080 53687091200))
        $R.AtRisk.Count | Should -Be 1
        $R.AtRisk[0].PercentUsed | Should -BeGreaterThan 90
        $R.WarnedOnly.Count | Should -Be 0
    }

    It 'does NOT flag a mailbox whose warning quota was left behind by a plan upgrade' {
        # Sameer@3endt.com: 69.47 GB used, warning quota still 45 GB, hard quota 100 GB.
        # Past the warning quota, but with 30 GB free. Ticketing this is the false positive
        # that trained everyone to ignore CIPP tickets last time.
        $R = Get-CIPPMailboxQuotaRisk -Mailboxes @((Mbx 'sameer@x.com' 74596200488 48318382080 107374182400))
        $R.AtRisk.Count | Should -Be 0
        $R.WarnedOnly.Count | Should -Be 1
        $R.StaleWarning.Count | Should -Be 1
        $R.StaleWarning[0].Upn | Should -Be 'sameer@x.com'
    }

    It 'treats a proportionate warning quota as not stale' {
        # A 41 GB warning on a 50 GB mailbox is 82% of the hard quota - correctly scaled.
        # 42 GB used is 84%: past the warning, under the 85% risk line. So the user sees a
        # warning without it being a capacity problem, and nothing is misconfigured.
        $R = Get-CIPPMailboxQuotaRisk -Mailboxes @((Mbx 'ok@x.com' 42GB 41GB 53687091200))
        $R.WarnedOnly.Count | Should -Be 1
        $R.StaleWarning.Count | Should -Be 0
    }

    It 'counts every mailbox it looked at, not just the risky ones' {
        $R = Get-CIPPMailboxQuotaRisk -Mailboxes @(
            (Mbx 'a@x.com' 1GB 45GB 50GB), (Mbx 'b@x.com' 2GB 45GB 50GB))
        $R.Checked | Should -Be 2
        $R.AtRisk.Count | Should -Be 0
    }

    It 'skips deleted mailboxes and rows with no quota' {
        $Deleted = Mbx 'gone@x.com' 49GB 45GB 50GB
        $Deleted.isDeleted = $true
        $R = Get-CIPPMailboxQuotaRisk -Mailboxes @($Deleted, (Mbx 'noquota@x.com' 49GB 0 0))
        $R.AtRisk.Count | Should -Be 0
    }

    It 'sorts the at-risk list fullest first' {
        $R = Get-CIPPMailboxQuotaRisk -Mailboxes @(
            (Mbx 'less@x.com' 43GB 45GB 50GB), (Mbx 'more@x.com' 49GB 45GB 50GB))
        $R.AtRisk[0].Upn | Should -Be 'more@x.com'
    }

    It 'handles an empty or null list' {
        (Get-CIPPMailboxQuotaRisk -Mailboxes @()).Checked | Should -Be 0
        (Get-CIPPMailboxQuotaRisk -Mailboxes $null).Checked | Should -Be 0
    }
}

Describe 'Format-Size (lifted verbatim from Get-CIPPStorageUsageReportData)' {
    # Copied rather than imported: it is a local function inside the report builder, which
    # is the house pattern for these formatter tests. Keep in step with the original.
    BeforeAll {
        function Format-Size([double]$Bytes) {
            $Sign = if ($Bytes -lt 0) { '-' } else { '' }
            $Abs = [math]::Abs($Bytes)
            if ($Abs -ge 1TB) { return '{0}{1:N2} TB' -f $Sign, ($Abs / 1TB) }
            if ($Abs -ge 1GB) { return '{0}{1:N2} GB' -f $Sign, ($Abs / 1GB) }
            if ($Abs -ge 1MB) { return '{0}{1:N1} MB' -f $Sign, ($Abs / 1MB) }
            return '{0}{1:N0} KB' -f $Sign, ($Abs / 1KB)
        }
    }

    It 'picks the unit from the magnitude, not the signed value' {
        # Shipped wrong once: a negative fails every -ge threshold and falls through to KB,
        # so Main Properties' 369 MB reduction read "-377,698 KB" in its IT Glue record.
        Format-Size (-387 * 1MB) | Should -Be '-387.0 MB'
        Format-Size (-2.5 * 1GB) | Should -Be '-2.50 GB'
        Format-Size (-3 * 1TB) | Should -Be '-3.00 TB'
    }

    It 'formats positives without a sign' {
        Format-Size (2.82 * 1TB) | Should -Be '2.82 TB'
        Format-Size (67.74 * 1GB) | Should -Be '67.74 GB'
        Format-Size 0 | Should -Be '0 KB'
    }
}
