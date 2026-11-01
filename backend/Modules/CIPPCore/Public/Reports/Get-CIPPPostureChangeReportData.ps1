function Get-CIPPPostureChangeReportData {
    <#
    .SYNOPSIS
        Gather the Security Posture Change report model for a single tenant.
    .DESCRIPTION
        Client-facing month-over-month narrative on top of data CIPP already computes: the CIPPTests results (ZTNA,
        CIS, EIDSCA, ORCA, ...) and Microsoft Secure Score. Running the report stores today's posture snapshot
        (Save-CIPPPostureSnapshot), then compares it with the snapshot from about a month ago
        (Get-CIPPPostureChange): Secure Score then vs now, what was fixed, what is new, and everything still open
        bucketed Do today / This month / Long-term by risk. The first run has nothing to compare with and says so
        ("baseline taken today"); a monthly schedule of this report, or of the PostureSnapshot scripted alert, builds
        the history. Read only towards the tenant. Aspendora fork addition (Vikunja CIPP-16).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter
    )

    $Findings = [System.Collections.Generic.List[object]]::new()
    $Sections = [System.Collections.Generic.List[object]]::new()
    function Add-Finding($Title, $Status, $Detail) { $Findings.Add(@{ Title = $Title; Status = $Status; Detail = $Detail }) }
    function Add-Section($Title, $Status, $Description, $Columns, $Rows, $Empty) {
        $Sections.Add(@{ Title = $Title; Status = $Status; Description = $Description; Columns = $Columns; Rows = $Rows; Empty = $Empty })
    }
    function New-RowList { , [System.Collections.Generic.List[object]]::new() }
    # Client-facing names for the test suites; the raw suite key is kept when unknown.
    $SuiteNames = @{
        ZTNA = 'Zero Trust'; CIS = 'CIS Benchmark'; EIDSCA = 'Entra ID configuration'; ORCA = 'Email protection'
        CISA = 'CISA SCuBA'; SMB1001 = 'SMB1001'; E8 = 'Essential Eight'; Azure = 'Azure'; Custom = 'Custom check'
        CopilotReadiness = 'Copilot readiness'; GenericTests = 'General'; SecuritySimulations = 'Attack simulation'
    }
    function Get-Area($Item) {
        $S = if ($Item.Suite -and $SuiteNames.ContainsKey([string]$Item.Suite)) { $SuiteNames[[string]$Item.Suite] } else { [string]$Item.Suite }
        (@($S, [string]$Item.Category) | Where-Object { $_ } | Select-Object -Unique) -join ' / '
    }
    function Format-Status($S) { switch ([string]$S) { 'Fail' { 'Failing' } 'Investigate' { 'Needs review' } 'Pass' { 'Passing' } 'NA' { 'Not assessed' } default { 'Not checked' } } }
    function Format-Date($D) {
        if (-not $D) { return '' }
        try { return ([datetime]::ParseExact([string]$D, 'yyyy-MM-dd', [cultureinfo]::InvariantCulture)).ToString('dd MMMM yyyy') } catch { return [string]$D }
    }
    function Format-Pct($V) { if ($null -eq $V) { 'Not available' } else { '{0:0.#}%' -f [double]$V } }
    function Format-Signed($V, $Suffix) { if ($null -eq $V) { '' } elseif ([double]$V -gt 0) { "+$V$Suffix" } else { "$V$Suffix" } }
    # Index loops: each row is an array, and piping a list of arrays unrolls a single row into its cells.
    function ConvertTo-Rows($Items, [scriptblock]$Row) {
        $Out = New-RowList
        $Arr = @($Items)
        for ($i = 0; $i -lt $Arr.Count; $i++) { $Out.Add((& $Row $Arr[$i])) }
        return , $Out
    }

    $Org = $null
    try { $Org = New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/organization' -tenantid $TenantFilter | Select-Object -First 1 } catch {}
    $TenantName = if ($Org.displayName) { $Org.displayName } else { $TenantFilter }
    $DefaultDomain = ($Org.verifiedDomains | Where-Object { $_.isDefault }).name
    if (-not $DefaultDomain) { $DefaultDomain = $TenantFilter }
    $Model = @{ Title = 'Security Posture Change'; TenantName = $TenantName; TenantDomain = $DefaultDomain; GeneratedDate = (Get-Date).ToString('dd MMMM yyyy'); Findings = $Findings; Sections = $Sections }

    $D = $null
    try {
        $D = Get-CIPPPostureChange -TenantFilter $TenantFilter -Snapshot
    } catch {
        $r = New-RowList; $r.Add(@("$($_.Exception.Message)"))
        Add-Section 'Security Posture' 'warn' 'Posture data could not be read.' @('Error') $r 'Data unavailable.'
        return $Model
    }

    if ($D.Counts.Tests -eq 0) {
        Add-Finding 'No security checks stored yet' 'warn' 'CIPP has not stored any security test results for this tenant yet. They are collected by the nightly test run; this report fills in once they exist.'
        Add-Section 'Security Posture' 'warn' 'No CIPP security test results are stored for this tenant yet, so no snapshot was taken.' @('Measure', 'Value') (New-RowList) 'No data yet.'
        foreach ($E in @($D.Errors)) { Add-Finding 'Partial data' 'warn' $E }
        return $Model
    }

    $C = $D.Counts
    $SS = $D.SecureScore
    $Since = Format-Date $D.PreviousDate

    # ---- headline ------------------------------------------------------------------
    $Summary = New-RowList
    if ($D.HasPrevious) {
        $Summary.Add(@('Microsoft Secure Score', (Format-Pct $SS.PreviousPercent), (Format-Pct $SS.CurrentPercent), (Format-Signed $SS.PercentDelta ' pts')))
        $Summary.Add(@('Secure Score points', $(if ($null -ne $SS.Previous) { "$($SS.Previous) / $($SS.PreviousMax)" } else { 'Not available' }), $(if ($null -ne $SS.Current) { "$($SS.Current) / $($SS.CurrentMax)" } else { 'Not available' }), (Format-Signed $SS.PointsDelta '')))
        $PrevOpen = $C.StillOpen + $C.Fixed + $C.NoLongerAssessed
        $Summary.Add(@('Open issues', [string]$PrevOpen, [string]$C.Open, (Format-Signed ($C.Open - $PrevOpen) '')))
        $Summary.Add(@('Fixed since last review', '', [string]$C.Fixed, ''))
        $Summary.Add(@('New issues', '', [string]$C.NewIssues, ''))
        $Head = "Compared with $Since. Secure Score $(Format-Pct $SS.PreviousPercent) then, $(Format-Pct $SS.CurrentPercent) now. $($C.Fixed) fixed, $($C.NewIssues) new, $($C.Open) still open."
        Add-Section 'Since Last Review' 'info' $Head @('Measure', 'Then', 'Now', 'Change') $Summary $null
    } else {
        $Summary.Add(@('Microsoft Secure Score', '', (Format-Pct $SS.CurrentPercent), ''))
        $Summary.Add(@('Open issues', '', [string]$C.Open, ''))
        Add-Section 'Since Last Review' 'info' 'Baseline taken today; changes appear from next month.' @('Measure', 'Then', 'Now', 'Change') $Summary $null
    }

    # ---- fixed / new -----------------------------------------------------------------
    $FixedRows = ConvertTo-Rows $D.Fixed { param($I) @([string]$I.Name, (Get-Area $I), [string]$I.Risk, (Format-Status $I.PreviousStatus)) }
    $FixedEmpty = if ($D.HasPrevious) { 'Nothing was fixed since the last review.' } else { 'Baseline taken today; changes appear from next month.' }
    Add-Section 'Fixed Since Last Review' 'pass' $(if ($D.HasPrevious) { "Checks that were open on $Since and pass now." } else { 'No earlier snapshot to compare with.' }) @('Check', 'Area', 'Risk', 'Was') $FixedRows $FixedEmpty

    $NewRows = ConvertTo-Rows $D.NewIssues { param($I) @([string]$I.Name, (Get-Area $I), [string]$I.Risk, (Format-Status $I.Status), [string]$I.Change) }
    $NewStatus = if ($C.NewIssues -gt 0) { 'warn' } else { 'pass' }
    $NewEmpty = if ($D.HasPrevious) { 'No new issues since the last review.' } else { 'Baseline taken today; changes appear from next month.' }
    Add-Section 'New Issues' $NewStatus 'Open now but not last time. "Was passing" is a regression; "New check" and "Newly assessed" are checks that were not part of the last review.' @('Check', 'Area', 'Risk', 'Status', 'Why new') $NewRows $NewEmpty

    # ---- still open, by priority ---------------------------------------------------
    $Buckets = @(
        @{ Key = 'DoToday'; Title = 'Still Open: Do Today'; Status = 'fail'; Text = 'Critical and high risk. These are the first things to fix.' }
        @{ Key = 'ThisMonth'; Title = 'Still Open: This Month'; Status = 'warn'; Text = 'Medium risk. Plan these into this month''s work.' }
        @{ Key = 'LongTerm'; Title = 'Still Open: Long-term'; Status = 'info'; Text = 'Low risk or unrated. Improvements to schedule over time.' }
    )
    foreach ($B in $Buckets) {
        $Items = @($D.OpenNow | Where-Object { $_.Bucket -eq $B.Key })
        $Rows = ConvertTo-Rows $Items { param($I) @([string]$I.Name, (Get-Area $I), [string]$I.Risk, (Format-Status $I.Status), $(if ($I.Change -in @('Still open', 'Baseline')) { 'Open' } else { 'New' })) }
        $St = if ($Items.Count -gt 0) { $B.Status } else { 'pass' }
        Add-Section $B.Title $St $B.Text @('Check', 'Area', 'Risk', 'Status', 'Since') $Rows 'Nothing open in this group.'
    }

    if ($C.NoLongerAssessed -gt 0) {
        $NlaRows = ConvertTo-Rows $D.NoLongerAssessed { param($I) @([string]$I.Name, (Get-Area $I), [string]$I.Risk, (Format-Status $I.PreviousStatus), [string]$I.Change) }
        Add-Section 'No Longer Assessed' 'info' 'Open last time but not assessed this time (licence change, check skipped or retired). These are not counted as fixed.' @('Check', 'Area', 'Risk', 'Was', 'Now') $NlaRows $null
    }

    # ---- findings (executive summary) ----------------------------------------------
    if (-not $D.HasPrevious) {
        Add-Finding 'Baseline taken today' 'info' "Baseline taken today; changes appear from next month. $($C.Open) open issue(s) recorded, Secure Score $(Format-Pct $SS.CurrentPercent)."
    } else {
        if ($null -ne $SS.PercentDelta) {
            $ScoreSt = if ($SS.PercentDelta -ge 0) { 'pass' } else { 'warn' }
            Add-Finding 'Secure Score' $ScoreSt "$(Format-Pct $SS.PreviousPercent) on $Since, $(Format-Pct $SS.CurrentPercent) now ($(Format-Signed $SS.PercentDelta ' pts'))."
        }
        if ($C.Fixed -gt 0) { Add-Finding 'Issues fixed' 'pass' "$($C.Fixed) issue(s) fixed since $Since." }
        if ($C.NewIssues -gt 0) {
            $Regressed = @($D.NewIssues | Where-Object { $_.Change -eq 'Was passing' }).Count
            Add-Finding 'New issues' 'warn' "$($C.NewIssues) new issue(s) since $Since$(if ($Regressed) { ", $Regressed of them previously passing" })."
        } else {
            Add-Finding 'No new issues' 'pass' "Nothing new has started failing since $Since."
        }
        if ($D.BaselineRule -eq 'Oldest' -and $null -ne $D.DaysBetween -and $D.DaysBetween -lt $D.MinDays) {
            Add-Finding 'Short comparison window' 'info' "The earliest stored snapshot is only $($D.DaysBetween) day(s) old, so this compares a shorter period than a month."
        }
    }
    if ($C.DoToday -gt 0) { Add-Finding 'High-risk items open' 'fail' "$($C.DoToday) critical or high risk issue(s) are open and should be fixed first." }
    else { Add-Finding 'No high-risk items open' 'pass' 'No critical or high risk check is failing.' }
    foreach ($E in @($D.Errors)) { Add-Finding 'Partial data' 'warn' $E }

    return $Model
}
