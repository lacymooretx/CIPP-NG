function Compare-CIPPPostureSnapshot {
    <#
    .SYNOPSIS
        Diff two posture snapshots: fixed, new issues, still open (by priority), added / removed checks, score delta.
    .DESCRIPTION
        Pure function (no I/O), so every rule is unit-tested. Both inputs have the Get-CIPPPostureCurrent shape
        (Date, SecureScore, Tests[Id, Name, Suite, Category, Status, Risk]); Previous may be $null for the first run.

        Matching. Tests are matched by Id (case-insensitive). A check whose Id changed between runs (upstream renames
        happen when a suite is renumbered) is matched by its normalised title instead, but only when exactly one
        unmatched old check has that title, so two unrelated checks that share a generic name are never paired.

        Open = Fail or Investigate (ListTests counts Investigate as "needs attention"). NA = skipped, informational or
        unlicensed: it says nothing about configuration, so a move to or from NA is never a fix or a regression.
          Fixed             open before, Pass now
          New issues        open now and: Pass before ("Was passing"), NA before ("Newly assessed"), or the check did
                            not exist before ("New check")
          Still open        open both times
          No longer assessed  open before, now NA or no longer reported. Listed separately and NOT counted as fixed:
                            a check that stopped running has not been remediated.
        Priority bucket from Risk: Critical / High = DoToday, Medium = ThisMonth, anything else = LongTerm.

        Secure Score: points and percentage deltas. Microsoft changes the maximum as controls are added, so the
        percentage is the fair month-to-month comparison and the narrative uses it.
        Aspendora fork addition (Vikunja CIPP-16).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Current,
        [AllowNull()]
        $Previous
    )

    function Get-Bucket([string]$Risk) {
        switch -Regex ($Risk) {
            '^(?i)(critical|high)$' { return 'DoToday' }
            '^(?i)medium$' { return 'ThisMonth' }
            default { return 'LongTerm' }
        }
    }
    function Get-NameKey([string]$Name) { ($Name.ToLowerInvariant() -replace '[^a-z0-9]', '') }
    $RiskOrder = @{ critical = 0; high = 1; medium = 2; low = 3 }
    $BucketOrder = @{ DoToday = 0; ThisMonth = 1; LongTerm = 2 }
    $OpenStates = @('Fail', 'Investigate')

    function New-DiffItem($Test, $PreviousStatus, $Change) {
        [pscustomobject]@{
            Id             = [string]$Test.Id
            Name           = [string]$Test.Name
            Suite          = [string]$Test.Suite
            Category       = [string]$Test.Category
            Risk           = [string]$Test.Risk
            Status         = [string]$Test.Status
            PreviousStatus = $PreviousStatus
            Bucket         = (Get-Bucket ([string]$Test.Risk))
            Change         = $Change
        }
    }
    # Assign lists directly and sort into a new list: `$x = if (...) { $List }` would unroll an empty list to $null.
    function Get-Sorted($Items) {
        $Out = [System.Collections.Generic.List[object]]::new()
        $Sorted = @($Items | Sort-Object -Property @{ Expression = { $BucketOrder[$_.Bucket] } }, @{ Expression = { $r = $RiskOrder[([string]$_.Risk).ToLowerInvariant()]; if ($null -eq $r) { 9 } else { $r } } }, @{ Expression = { $_.Name } })
        for ($i = 0; $i -lt $Sorted.Count; $i++) { $Out.Add($Sorted[$i]) }
        return , $Out
    }

    $CurTests = @($Current.Tests | Where-Object { $_ -and $_.Id })
    $PrevTests = @($Previous.Tests | Where-Object { $_ -and $_.Id })

    $PrevById = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($T in $PrevTests) { if (-not $PrevById.ContainsKey($T.Id)) { $PrevById[$T.Id] = $T } }
    $CurIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($T in $CurTests) { [void]$CurIds.Add($T.Id) }

    # Title fallback for renamed ids: only old checks whose id has vanished are candidates.
    $PrevByName = @{}
    foreach ($T in $PrevTests) {
        if ($CurIds.Contains($T.Id)) { continue }
        $Key = Get-NameKey $T.Name
        if (-not $Key) { continue }
        if (-not $PrevByName.ContainsKey($Key)) { $PrevByName[$Key] = [System.Collections.Generic.List[object]]::new() }
        $PrevByName[$Key].Add($T)
    }

    $Fixed = [System.Collections.Generic.List[object]]::new()
    $NewIssues = [System.Collections.Generic.List[object]]::new()
    $StillOpen = [System.Collections.Generic.List[object]]::new()
    $NoLongerAssessed = [System.Collections.Generic.List[object]]::new()
    $Added = [System.Collections.Generic.List[object]]::new()
    $Removed = [System.Collections.Generic.List[object]]::new()
    $Renamed = [System.Collections.Generic.List[object]]::new()
    $MatchedPrev = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $HasPrevious = $null -ne $Previous -and $PrevTests.Count -gt 0

    foreach ($T in $CurTests) {
        $P = $null
        if ($HasPrevious) {
            if ($PrevById.ContainsKey($T.Id)) {
                $P = $PrevById[$T.Id]
            } else {
                $Key = Get-NameKey $T.Name
                if ($Key -and $PrevByName.ContainsKey($Key) -and $PrevByName[$Key].Count -eq 1 -and -not $MatchedPrev.Contains($PrevByName[$Key][0].Id)) {
                    $P = $PrevByName[$Key][0]
                    $Renamed.Add([pscustomobject]@{ PreviousId = [string]$P.Id; Id = [string]$T.Id; Name = [string]$T.Name })
                }
            }
        }
        if ($P) { [void]$MatchedPrev.Add($P.Id) }
        $IsOpen = $T.Status -in $OpenStates

        if (-not $HasPrevious) {
            if ($IsOpen) { $StillOpen.Add((New-DiffItem $T $null 'Baseline')) }
            continue
        }
        if (-not $P) {
            $Added.Add((New-DiffItem $T $null 'New check'))
            if ($IsOpen) { $NewIssues.Add((New-DiffItem $T $null 'New check')) }
            continue
        }
        $WasOpen = $P.Status -in $OpenStates
        if ($WasOpen -and $IsOpen) { $StillOpen.Add((New-DiffItem $T $P.Status 'Still open')) }
        elseif ($WasOpen -and $T.Status -eq 'Pass') { $Fixed.Add((New-DiffItem $T $P.Status 'Fixed')) }
        elseif ($WasOpen) { $NoLongerAssessed.Add((New-DiffItem $T $P.Status 'Not assessed this time')) }
        elseif ($IsOpen -and $P.Status -eq 'Pass') { $NewIssues.Add((New-DiffItem $T $P.Status 'Was passing')) }
        elseif ($IsOpen) { $NewIssues.Add((New-DiffItem $T $P.Status 'Newly assessed')) }
    }

    if ($HasPrevious) {
        foreach ($P in $PrevTests) {
            if ($MatchedPrev.Contains($P.Id)) { continue }
            $Removed.Add((New-DiffItem $P $P.Status 'No longer reported'))
            if ($P.Status -in $OpenStates) { $NoLongerAssessed.Add((New-DiffItem $P $P.Status 'No longer reported')) }
        }
    }

    $CS = $Current.SecureScore
    $PS = if ($HasPrevious) { $Previous.SecureScore } else { $null }
    $Score = [pscustomobject]@{
        Current         = $(if ($CS) { [double]$CS.Current } else { $null })
        CurrentMax      = $(if ($CS) { [double]$CS.Max } else { $null })
        CurrentPercent  = $(if ($CS) { [double]$CS.Percent } else { $null })
        Previous        = $(if ($PS) { [double]$PS.Current } else { $null })
        PreviousMax     = $(if ($PS) { [double]$PS.Max } else { $null })
        PreviousPercent = $(if ($PS) { [double]$PS.Percent } else { $null })
        PointsDelta     = $(if ($CS -and $PS) { [math]::Round([double]$CS.Current - [double]$PS.Current, 2) } else { $null })
        PercentDelta    = $(if ($CS -and $PS) { [math]::Round([double]$CS.Percent - [double]$PS.Percent, 1) } else { $null })
    }

    $Open = Get-Sorted $StillOpen
    $NewSorted = Get-Sorted $NewIssues
    # Everything open now, whether new or carried over, is what the "Still open / to do" buckets show.
    $AllOpen = Get-Sorted (@($StillOpen) + @($NewIssues))
    $Days = $null
    if ($HasPrevious) {
        try { $Days = [int]([datetime]::ParseExact([string]$Current.Date, 'yyyy-MM-dd', [cultureinfo]::InvariantCulture) - [datetime]::ParseExact([string]$Previous.Date, 'yyyy-MM-dd', [cultureinfo]::InvariantCulture)).TotalDays } catch {}
    }

    return [pscustomobject]@{
        Tenant           = [string]$Current.Tenant
        HasPrevious      = [bool]$HasPrevious
        CurrentDate      = [string]$Current.Date
        PreviousDate     = $(if ($HasPrevious) { [string]$Previous.Date } else { $null })
        DaysBetween      = $Days
        SecureScore      = $Score
        Fixed            = (Get-Sorted $Fixed)
        NewIssues        = $NewSorted
        StillOpen        = $Open
        OpenNow          = $AllOpen
        NoLongerAssessed = (Get-Sorted $NoLongerAssessed)
        AddedTests       = (Get-Sorted $Added)
        RemovedTests     = (Get-Sorted $Removed)
        RenamedTests     = $Renamed
        Counts           = [pscustomobject]@{
            Tests            = $CurTests.Count
            PreviousTests    = $PrevTests.Count
            Open             = $AllOpen.Count
            Fixed            = $Fixed.Count
            NewIssues        = $NewIssues.Count
            StillOpen        = $StillOpen.Count
            NoLongerAssessed = $NoLongerAssessed.Count
            Added            = $Added.Count
            Removed          = $Removed.Count
            DoToday          = @($AllOpen | Where-Object { $_.Bucket -eq 'DoToday' }).Count
            ThisMonth        = @($AllOpen | Where-Object { $_.Bucket -eq 'ThisMonth' }).Count
            LongTerm         = @($AllOpen | Where-Object { $_.Bucket -eq 'LongTerm' }).Count
        }
    }
}
