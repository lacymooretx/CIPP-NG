# Pester tests for the month-over-month posture diff (Vikunja CIPP-16): snapshot packing, status normalisation,
# baseline selection, the diff rules (fixed, regressed, newly assessed, renamed / added / removed checks, no previous
# snapshot, Secure Score delta, priority buckets) and the Security Posture Change report model.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Modules = Join-Path $RepoRoot 'Modules'
    foreach ($Name in 'ConvertTo-CIPPPostureBlob.ps1', 'ConvertFrom-CIPPPostureBlob.ps1', 'Compare-CIPPPostureSnapshot.ps1',
        'Get-CIPPPostureCurrent.ps1', 'Save-CIPPPostureSnapshot.ps1', 'Get-CIPPPostureSnapshot.ps1', 'Get-CIPPPostureChange.ps1',
        'Get-CIPPPostureChangeReportData.ps1', 'Get-CippTestSuitePatterns.ps1') {
        $Path = Get-ChildItem -Path $Modules -Recurse -Filter $Name -File | Select-Object -First 1 -ExpandProperty FullName
        if (-not $Path) { throw "Could not locate $Name" }
        . $Path
    }

    # Stubs so Mock has something to replace.
    function Get-Tenants { [CmdletBinding()] param($TenantFilter, [switch]$IncludeErrors) }
    # One stub serves both spellings (Get-CippTable / Get-CIPPTable): command names are case-insensitive.
    function Get-CIPPTable { [CmdletBinding()] param($TableName) @{ Context = $TableName } }
    function Get-CIPPAzDataTableEntity { [CmdletBinding()] param($Context, $Filter, $Property) }
    function Add-CIPPAzDataTableEntity { [CmdletBinding()] param($Context, $Entity, [switch]$Force, $OperationType) }
    function Remove-AzDataTableEntity { [CmdletBinding()] param($Context, $Entity, [switch]$Force) }
    function Get-CIPPSecureScoreReport { [CmdletBinding()] param($TenantFilter) }
    function New-GraphGetRequest { [CmdletBinding()] param($uri, $tenantid) }

    function script:New-PT([string]$Id, [string]$Status, [string]$Risk = 'High', [string]$Name, [string]$Suite = 'ZTNA') {
        [pscustomobject]@{ Id = $Id; Name = $(if ($Name) { $Name } else { "Check $Id" }); Suite = $Suite; Category = 'Identity'; Status = $Status; Risk = $Risk }
    }
    function script:New-Snap([string]$Date, $Tests, $Score) {
        $L = [System.Collections.Generic.List[object]]::new()
        foreach ($T in @($Tests)) { $L.Add($T) }
        [pscustomobject]@{ Tenant = 'contoso.com'; Date = $Date; CapturedAt = "$($Date)T12:00:00.0000000Z"; TestsLastRun = $null; SecureScore = $Score; Tests = $L; Errors = @() }
    }
    function script:New-Score([double]$Current, [double]$Max) {
        [pscustomobject]@{ Current = $Current; Max = $Max; Percent = [math]::Round(100 * $Current / $Max, 1); Date = '2026-11-01' }
    }
}

Describe 'ConvertTo-CIPPPostureBlob / ConvertFrom-CIPPPostureBlob' {
    It 'round-trips a single test without unrolling it into its cells' {
        $Chunks = ConvertTo-CIPPPostureBlob -Tests @(New-PT -Id 'ZTNA1' -Status 'Fail')
        $Back = ConvertFrom-CIPPPostureBlob -Chunks $Chunks.ToArray()
        $Back.Count | Should -Be 1
        $Back[0].Id | Should -Be 'ZTNA1'
        $Back[0].Status | Should -Be 'Fail'
        $Back[0].Risk | Should -Be 'High'
    }

    It 'splits large snapshots into chunks no larger than the chunk size and reassembles them in order' {
        $Many = for ($i = 0; $i -lt 800; $i++) { New-PT -Id "CIS_$i" -Status $(if ($i % 3) { 'Pass' } else { 'Fail' }) -Name "A reasonably long check title number $i with some words" }
        $Chunks = ConvertTo-CIPPPostureBlob -Tests $Many -ChunkSize 1000
        $Chunks.Count | Should -BeGreaterThan 1
        @($Chunks | Where-Object { $_.Length -gt 1000 }).Count | Should -Be 0
        $Back = ConvertFrom-CIPPPostureBlob -Chunks $Chunks.ToArray()
        $Back.Count | Should -Be 800
        $Back[799].Id | Should -Be 'CIS_799'
        $Back[3].Status | Should -Be 'Fail'
    }

    It 'returns an empty list for no data' {
        $Back = ConvertFrom-CIPPPostureBlob -Chunks @()
        $Back.Count | Should -Be 0
    }
}

Describe 'Compare-CIPPPostureSnapshot' {
    It 'treats a missing previous snapshot as a baseline: everything open is listed, nothing is fixed or new' {
        $Cur = New-Snap '2026-11-01' @((New-PT 'A' 'Fail'), (New-PT 'B' 'Pass'), (New-PT 'C' 'Investigate' 'Medium')) (New-Score 50 100)
        $D = Compare-CIPPPostureSnapshot -Current $Cur -Previous $null
        $D.HasPrevious | Should -BeFalse
        $D.PreviousDate | Should -BeNullOrEmpty
        $D.Fixed.Count | Should -Be 0
        $D.NewIssues.Count | Should -Be 0
        $D.OpenNow.Count | Should -Be 2
        @($D.OpenNow.Change | Select-Object -Unique) | Should -Be @('Baseline')
        $D.SecureScore.PercentDelta | Should -BeNullOrEmpty
        $D.SecureScore.CurrentPercent | Should -Be 50
    }

    It 'returns empty lists, not $null, for empty diff categories' {
        $Cur = New-Snap '2026-11-01' @(New-PT 'A' 'Pass') $null
        $Prev = New-Snap '2026-10-01' @(New-PT 'A' 'Pass') $null
        $D = Compare-CIPPPostureSnapshot -Current $Cur -Previous $Prev
        # An empty List must survive as a List, not unroll to $null.
        $null -eq $D.Fixed | Should -BeFalse
        , $D.Fixed | Should -BeOfType ([System.Collections.Generic.List[object]])
        , $D.NewIssues | Should -BeOfType ([System.Collections.Generic.List[object]])
        $D.Counts.Fixed | Should -Be 0
    }

    It 'reports a check that went from failing to passing as fixed' {
        $Prev = New-Snap '2026-10-01' @((New-PT 'A' 'Fail'), (New-PT 'B' 'Investigate' 'Low')) $null
        $Cur = New-Snap '2026-11-01' @((New-PT 'A' 'Pass'), (New-PT 'B' 'Pass' 'Low')) $null
        $D = Compare-CIPPPostureSnapshot -Current $Cur -Previous $Prev
        $D.Counts.Fixed | Should -Be 2
        @($D.Fixed.Id) | Should -Contain 'A'
        ($D.Fixed | Where-Object Id -EQ 'B').PreviousStatus | Should -Be 'Investigate'
        $D.Counts.Open | Should -Be 0
        $D.DaysBetween | Should -Be 31
    }

    It 'reports a passing check that now fails as a regression ("Was passing")' {
        $Prev = New-Snap '2026-10-01' @(New-PT 'A' 'Pass') $null
        $Cur = New-Snap '2026-11-01' @(New-PT 'A' 'Fail') $null
        $D = Compare-CIPPPostureSnapshot -Current $Cur -Previous $Prev
        $D.NewIssues.Count | Should -Be 1
        $D.NewIssues[0].Change | Should -Be 'Was passing'
        $D.StillOpen.Count | Should -Be 0
        $D.OpenNow.Count | Should -Be 1
    }

    It 'never counts a move to or from not-assessed as fixed or regressed' {
        $Prev = New-Snap '2026-10-01' @((New-PT 'A' 'Fail'), (New-PT 'B' 'NA'), (New-PT 'C' 'Pass')) $null
        $Cur = New-Snap '2026-11-01' @((New-PT 'A' 'NA'), (New-PT 'B' 'Fail'), (New-PT 'C' 'NA')) $null
        $D = Compare-CIPPPostureSnapshot -Current $Cur -Previous $Prev
        $D.Counts.Fixed | Should -Be 0
        @($D.NoLongerAssessed.Id) | Should -Be @('A')
        $D.NewIssues.Count | Should -Be 1
        $D.NewIssues[0].Id | Should -Be 'B'
        $D.NewIssues[0].Change | Should -Be 'Newly assessed'
    }

    It 'still open is reported once and keeps the latest title' {
        $Prev = New-Snap '2026-10-01' @(New-PT 'A' 'Fail' -Name 'Old wording') $null
        $Cur = New-Snap '2026-11-01' @(New-PT 'a' 'Fail' -Name 'New wording') $null
        $D = Compare-CIPPPostureSnapshot -Current $Cur -Previous $Prev
        $D.StillOpen.Count | Should -Be 1
        $D.StillOpen[0].Name | Should -Be 'New wording'
        $D.Counts.Added | Should -Be 0
        $D.Counts.Removed | Should -Be 0
    }

    It 'matches a check whose id changed by its title, so a renumbered check is neither new nor removed' {
        $Prev = New-Snap '2026-10-01' @(New-PT 'ZTNA100' 'Fail' -Name 'Legacy auth is blocked') $null
        $Cur = New-Snap '2026-11-01' @(New-PT 'ZTNA200' 'Pass' -Name 'Legacy  Auth is blocked.') $null
        $D = Compare-CIPPPostureSnapshot -Current $Cur -Previous $Prev
        $D.Counts.Added | Should -Be 0
        $D.Counts.Removed | Should -Be 0
        $D.Counts.Fixed | Should -Be 1
        $D.RenamedTests.Count | Should -Be 1
        $D.RenamedTests[0].PreviousId | Should -Be 'ZTNA100'
    }

    It 'does not pair by title when the title is ambiguous' {
        $Prev = New-Snap '2026-10-01' @((New-PT 'X1' 'Fail' -Name 'Policy exists'), (New-PT 'X2' 'Fail' -Name 'Policy exists')) $null
        $Cur = New-Snap '2026-11-01' @(New-PT 'X3' 'Pass' -Name 'Policy exists') $null
        $D = Compare-CIPPPostureSnapshot -Current $Cur -Previous $Prev
        $D.Counts.Fixed | Should -Be 0
        $D.Counts.Added | Should -Be 1
        $D.Counts.Removed | Should -Be 2
        $D.RenamedTests.Count | Should -Be 0
    }

    It 'lists a new failing check as a new issue, and a vanished failing check as no longer assessed (not fixed)' {
        $Prev = New-Snap '2026-10-01' @((New-PT 'OLD' 'Fail'), (New-PT 'KEEP' 'Pass')) $null
        $Cur = New-Snap '2026-11-01' @((New-PT 'NEW' 'Fail' 'Medium'), (New-PT 'KEEP' 'Pass')) $null
        $D = Compare-CIPPPostureSnapshot -Current $Cur -Previous $Prev
        $D.NewIssues[0].Id | Should -Be 'NEW'
        $D.NewIssues[0].Change | Should -Be 'New check'
        @($D.AddedTests.Id) | Should -Be @('NEW')
        @($D.RemovedTests.Id) | Should -Be @('OLD')
        @($D.NoLongerAssessed.Id) | Should -Be @('OLD')
        $D.Counts.Fixed | Should -Be 0
    }

    It 'computes the Secure Score delta in points and percent' {
        $Prev = New-Snap '2026-10-01' @(New-PT 'A' 'Pass') (New-Score 600 1200)
        $Cur = New-Snap '2026-11-01' @(New-PT 'A' 'Pass') (New-Score 700 1250)
        $D = Compare-CIPPPostureSnapshot -Current $Cur -Previous $Prev
        $D.SecureScore.PointsDelta | Should -Be 100
        $D.SecureScore.PreviousPercent | Should -Be 50
        $D.SecureScore.CurrentPercent | Should -Be 56
        $D.SecureScore.PercentDelta | Should -Be 6
    }

    It 'leaves the score delta empty when either side has no Secure Score' {
        $Prev = New-Snap '2026-10-01' @(New-PT 'A' 'Pass') $null
        $Cur = New-Snap '2026-11-01' @(New-PT 'A' 'Pass') (New-Score 700 1000)
        $D = Compare-CIPPPostureSnapshot -Current $Cur -Previous $Prev
        $D.SecureScore.PercentDelta | Should -BeNullOrEmpty
        $D.SecureScore.CurrentPercent | Should -Be 70
    }

    It 'buckets open items by risk and sorts Do today first' {
        $Cur = New-Snap '2026-11-01' @((New-PT 'L' 'Fail' 'Low'), (New-PT 'U' 'Fail' ''), (New-PT 'M' 'Fail' 'Medium'), (New-PT 'C' 'Fail' 'Critical'), (New-PT 'H' 'Fail' 'High')) $null
        $D = Compare-CIPPPostureSnapshot -Current $Cur -Previous $null
        @($D.OpenNow.Id) | Should -Be @('C', 'H', 'M', 'L', 'U')
        @($D.OpenNow.Bucket) | Should -Be @('DoToday', 'DoToday', 'ThisMonth', 'LongTerm', 'LongTerm')
        $D.Counts.DoToday | Should -Be 2
        $D.Counts.ThisMonth | Should -Be 1
        $D.Counts.LongTerm | Should -Be 2
    }
}

Describe 'Get-CIPPPostureCurrent' {
    It 'normalises statuses, labels suites and reads the cached Secure Score' {
        Mock Get-Tenants { [pscustomobject]@{ defaultDomainName = 'contoso.com' } }
        Mock Get-CIPPAzDataTableEntity {
            @(
                [pscustomobject]@{ RowKey = 'ZTNA21816'; Name = 'PIM'; Status = 'Failed'; Risk = 'High '; Category = 'Identity' }
                [pscustomobject]@{ RowKey = 'CIS_1_1'; Name = 'CIS'; Status = 'Passed'; Risk = 'Medium'; Category = 'Identity' }
                [pscustomobject]@{ RowKey = 'ORCA100'; Name = 'ORCA'; Status = 'Postponed'; Risk = 'Low' }
                [pscustomobject]@{ RowKey = 'EIDSCAAM01'; Name = 'E'; Status = 'Investigate'; Risk = 'Low' }
                [pscustomobject]@{ RowKey = 'CustomScript-abc'; Name = 'Custom'; Status = 'Skipped'; Risk = '' }
                [pscustomobject]@{ RowKey = 'GenericTest1'; Name = ''; Status = 'Unlicensed'; Risk = '' }
            )
        }
        Mock Get-CIPPSecureScoreReport { @([pscustomobject]@{ CurrentScore = 919.21; MaxScore = 1410; PercentageScore = 65.2; CapturedAt = '2026-11-01T00:00:00Z' }) }
        $S = Get-CIPPPostureCurrent -TenantFilter 'contoso.com'
        $S.Tenant | Should -Be 'contoso.com'
        $S.Date | Should -Match '^\d{4}-\d{2}-\d{2}$'
        $ById = @{}; foreach ($T in $S.Tests) { $ById[$T.Id] = $T }
        $ById['ZTNA21816'].Status | Should -Be 'Fail'
        $ById['ZTNA21816'].Risk | Should -Be 'High'
        $ById['ZTNA21816'].Suite | Should -Be 'ZTNA'
        $ById['CIS_1_1'].Status | Should -Be 'Pass'
        $ById['CIS_1_1'].Suite | Should -Be 'CIS'
        $ById['ORCA100'].Status | Should -Be 'Fail'
        $ById['EIDSCAAM01'].Status | Should -Be 'Investigate'
        $ById['CustomScript-abc'].Suite | Should -Be 'Custom'
        $ById['CustomScript-abc'].Status | Should -Be 'NA'
        $ById['GenericTest1'].Status | Should -Be 'NA'
        $ById['GenericTest1'].Name | Should -Be 'GenericTest1'
        $S.SecureScore.Percent | Should -Be 65.2
        $S.SecureScore.Date | Should -Be '2026-11-01'
    }
}

Describe 'Save-CIPPPostureSnapshot' {
    BeforeEach {
        $script:Saved = $null
        Mock Add-CIPPAzDataTableEntity { $script:Saved = $Entity }
        Mock Get-CIPPAzDataTableEntity { @() }
        Mock Remove-AzDataTableEntity {}
    }

    It 'does not store a snapshot when there are no test results' {
        (Save-CIPPPostureSnapshot -Snapshot (New-Snap '2026-11-01' @() (New-Score 1 2))) | Should -BeFalse
        Should -Invoke Add-CIPPAzDataTableEntity -Times 0
    }

    It 'stores counts, score and a decodable blob keyed by tenant and date' {
        $Snap = New-Snap '2026-11-01' @((New-PT 'A' 'Fail'), (New-PT 'B' 'Pass'), (New-PT 'C' 'Investigate')) (New-Score 50 100)
        Save-CIPPPostureSnapshot -Snapshot $Snap | Should -BeTrue
        $script:Saved.PartitionKey | Should -Be 'contoso.com'
        $script:Saved.RowKey | Should -Be '2026-11-01'
        $script:Saved.TestCount | Should -Be 3
        $script:Saved.OpenCount | Should -Be 2
        $script:Saved.PassCount | Should -Be 1
        $script:Saved.SecureScorePercent | Should -Be 50
        Should -Invoke Add-CIPPAzDataTableEntity -Times 1 -ParameterFilter { $OperationType -eq 'UpsertReplace' }
        $Chunks = for ($i = 0; $i -lt $script:Saved.DataParts; $i++) { $script:Saved["Data$i"] }
        $Back = ConvertFrom-CIPPPostureBlob -Chunks @($Chunks)
        @($Back.Id) | Should -Be @('A', 'B', 'C')
    }
}

Describe 'Get-CIPPPostureChange baseline selection' {
    BeforeEach {
        $script:Cur = New-Snap '2026-11-01' @((New-PT 'A' 'Pass'), (New-PT 'B' 'Fail')) (New-Score 60 100)
        Mock Get-CIPPPostureCurrent { $script:Cur }
        Mock Save-CIPPPostureSnapshot { $true }
        Mock Get-CIPPPostureSnapshot -ParameterFilter { $Date } { New-Snap $Date @((New-PT 'A' 'Fail'), (New-PT 'B' 'Fail')) (New-Score 50 100) }
        # The index reader returns its list with the comma operator; the mock does the same.
        Mock Get-CIPPPostureSnapshot -ParameterFilter { -not $Date } { , $script:Index }
    }
    # Helpers live in BeforeAll: code directly in a Describe body only runs during Pester discovery.
    BeforeAll {
        function script:Set-Index([string[]]$Dates) {
            $L = [System.Collections.Generic.List[object]]::new()
            foreach ($D in $Dates) { $L.Add([pscustomobject]@{ Date = $D; TestCount = 2; SecureScore = $null }) }
            $script:Index = $L
        }
    }

    It 'prefers the newest snapshot at least 25 days old, ignoring today and recent ones' {
        Set-Index @('2026-08-30', '2026-10-01', '2026-10-20', '2026-11-01')
        $D = Get-CIPPPostureChange -TenantFilter 'contoso.com' -Snapshot
        $D.PreviousDate | Should -Be '2026-10-01'
        $D.BaselineRule | Should -Be 'MinAge'
        $D.SnapshotStored | Should -BeTrue
        $D.Counts.Fixed | Should -Be 1
        $D.SecureScore.PercentDelta | Should -Be 10
    }

    It 'falls back to the oldest earlier snapshot when none is old enough' {
        Set-Index @('2026-10-20', '2026-10-28', '2026-11-01')
        $D = Get-CIPPPostureChange -TenantFilter 'contoso.com'
        $D.PreviousDate | Should -Be '2026-10-20'
        $D.BaselineRule | Should -Be 'Oldest'
        $D.DaysBetween | Should -Be 12
        Should -Invoke Save-CIPPPostureSnapshot -Times 0
    }

    It 'is a baseline when only today exists' {
        Set-Index @('2026-11-01')
        $D = Get-CIPPPostureChange -TenantFilter 'contoso.com' -Snapshot
        $D.HasPrevious | Should -BeFalse
        $D.BaselineRule | Should -Be 'None'
        $D.OpenNow.Count | Should -Be 1
    }
}

Describe 'Get-CIPPPostureChangeReportData' {
    BeforeEach {
        Mock New-GraphGetRequest { [pscustomobject]@{ displayName = 'Contoso'; verifiedDomains = @(@{ name = 'contoso.com'; isDefault = $true }) } }
        Mock Get-CIPPPostureChange { $script:Diff }
    }
    BeforeAll {
        function script:Set-Diff($Cur, $Prev) {
            $script:Diff = Compare-CIPPPostureSnapshot -Current $Cur -Previous $Prev
            $script:Diff | Add-Member -NotePropertyName 'BaselineRule' -NotePropertyValue $(if ($Prev) { 'MinAge' } else { 'None' }) -Force
            $script:Diff | Add-Member -NotePropertyName 'MinDays' -NotePropertyValue 25 -Force
            $script:Diff | Add-Member -NotePropertyName 'Errors' -NotePropertyValue @() -Force
        }
    }

    It 'builds the client narrative with whole rows, single-row sections intact and priority buckets' {
        $Prev = New-Snap '2026-10-01' @((New-PT 'FIX' 'Fail'), (New-PT 'REG' 'Pass' 'Medium'), (New-PT 'OPEN' 'Fail' 'High')) (New-Score 50 100)
        $Cur = New-Snap '2026-11-01' @((New-PT 'FIX' 'Pass'), (New-PT 'REG' 'Fail' 'Medium'), (New-PT 'OPEN' 'Fail' 'High'), (New-PT 'LOW' 'Fail' 'Low')) (New-Score 55 100)
        Set-Diff $Cur $Prev
        $M = Get-CIPPPostureChangeReportData -TenantFilter 'contoso.com'
        $M.Title | Should -Be 'Security Posture Change'
        $M.TenantName | Should -Be 'Contoso'
        $Fixed = $M.Sections | Where-Object { $_.Title -eq 'Fixed Since Last Review' }
        $Fixed.Rows.Count | Should -Be 1
        $Fixed.Rows[0].Count | Should -Be $Fixed.Columns.Count
        $Fixed.Rows[0][0] | Should -Be 'Check FIX'
        $Fixed.Rows[0][1] | Should -Be 'Zero Trust / Identity'
        $New = $M.Sections | Where-Object { $_.Title -eq 'New Issues' }
        $New.Rows.Count | Should -Be 2
        @($New.Rows | ForEach-Object { , $_ } | ForEach-Object { $_[4] }) | Should -Contain 'Was passing'
        $Today = $M.Sections | Where-Object { $_.Title -eq 'Still Open: Do Today' }
        $Today.Rows.Count | Should -Be 1
        $Today.Status | Should -Be 'fail'
        ($M.Sections | Where-Object { $_.Title -eq 'Still Open: This Month' }).Rows[0][0] | Should -Be 'Check REG'
        ($M.Sections | Where-Object { $_.Title -eq 'Still Open: Long-term' }).Rows.Count | Should -Be 1
        $Head = $M.Sections | Where-Object { $_.Title -eq 'Since Last Review' }
        $Head.Description | Should -BeLike '*50% then, 55% now*1 fixed, 2 new, 3 still open*'
        @($M.Findings.Title) | Should -Contain 'Issues fixed'
        @($M.Findings.Title) | Should -Contain 'New issues'
        @($M.Findings.Title) | Should -Contain 'High-risk items open'
        ($M.Findings | Where-Object { $_.Title -eq 'Secure Score' }).Status | Should -Be 'pass'
    }

    It 'says the baseline was taken today when there is no previous snapshot' {
        Set-Diff (New-Snap '2026-11-01' @((New-PT 'A' 'Fail' 'Medium'), (New-PT 'B' 'Pass')) (New-Score 70 100)) $null
        $M = Get-CIPPPostureChangeReportData -TenantFilter 'contoso.com'
        ($M.Sections | Where-Object { $_.Title -eq 'Since Last Review' }).Description | Should -Be 'Baseline taken today; changes appear from next month.'
        ($M.Sections | Where-Object { $_.Title -eq 'Fixed Since Last Review' }).Empty | Should -BeLike 'Baseline taken today*'
        ($M.Sections | Where-Object { $_.Title -eq 'Still Open: This Month' }).Rows.Count | Should -Be 1
        @($M.Findings.Title) | Should -Contain 'Baseline taken today'
        @($M.Findings.Title) | Should -Not -Contain 'New issues'
        @($M.Findings.Title) | Should -Contain 'No high-risk items open'
    }

    It 'explains an empty tenant instead of producing an empty report' {
        Set-Diff (New-Snap '2026-11-01' @() $null) $null
        $M = Get-CIPPPostureChangeReportData -TenantFilter 'contoso.com'
        @($M.Findings.Title) | Should -Contain 'No security checks stored yet'
    }
}
