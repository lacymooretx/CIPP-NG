function Get-CIPPStorageGrowth {
    <#
    .SYNOPSIS
        Derive growth rates and projected quota exhaustion from a storage series.
    .DESCRIPTION
        Turns the daily series into the numbers worth putting in front of a client: how fast
        they are growing, whether that is speeding up, and when it meets the ceiling.

        REPORTS SEVERAL WINDOWS, NOT ONE RATE. A single whole-window figure was tried first
        and was actively misleading on real client data in both directions:

          - Aspendora dropped ~315 GB in one day in March (a cleanup). A least-squares slope
            over 180 days therefore reported "shrinking 973 MB/day" - while the 30, 90 and
            median figures all agreed the client was GROWING. Acting on the single number
            would mean doing nothing for a client that has grown 6% since April.
          - 3E NDT's last 30 days ran at 9.1 GB/day against a 180-day figure of 3.2 GB/day.
            One number understated a genuinely accelerating client by threefold.

        So: a robust median daily delta, per-window rates, and explicit step-change
        detection, which is what explains a disagreement between windows instead of leaving
        it a mystery.

        The projection is taken from the most recent window with enough history - 90 days by
        preference, since that is long enough to smooth monthly noise and short enough to
        sit after an old step change. Never from the full window, which is the one most
        likely to be poisoned by an event the client has already dealt with.

        Refuses to project rather than guessing when the answer would be meaningless: fewer
        than two points, a flat or shrinking recent trend, or no quota. A confident wrong
        date on a client-facing report is worse than "not enough history yet", because
        nobody re-checks a number that already has a graph next to it.

    .PARAMETER Series
        Rows from Get-CIPPStorageTrend, oldest first. Needs .Date and the byte property.
    .PARAMETER QuotaBytes
        Ceiling to project against. Omit for growth figures without a projection.
    .PARAMETER Property
        Which byte column to analyse. Defaults to the total.
    .PARAMETER MaterialityBytesPerDay
        How much faster the recent window must be running before the trend is called
        Accelerating. Without a floor the label fires on arithmetically-true nonsense -
        Trinity Bay at 75 MB/day against 31 MB/day is a doubling of nothing, and a report
        that flags it is training the reader to ignore the field.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][AllowNull()]$Series,
        [Parameter(Mandatory = $false)][AllowNull()][Nullable[long]]$QuotaBytes,
        [string]$Property = 'TotalBytes',
        [long]$MaterialityBytesPerDay = 250MB
    )

    $Points = @($Series | Where-Object { $_ -and $_.Date -and $null -ne $_.$Property })

    $Result = [pscustomobject]@{
        Days               = $Points.Count
        FirstDate          = $null
        LatestDate         = $null
        FirstBytes         = 0L
        LatestBytes        = 0L
        ChangeBytes        = 0L
        PercentChange      = $null
        BytesPerDay        = 0L
        BasisWindowDays    = $null
        MedianBytesPerDay  = 0L
        Windows            = @{}
        StepChanges        = @()
        Trend              = 'Unknown'
        ProjectedFullDate  = $null
        DaysUntilFull      = $null
        Confidence         = 'None'
        Note               = $null
    }

    if ($Points.Count -lt 2) {
        $Result.Note = 'Not enough history to calculate growth. At least two collection dates are needed.'
        if ($Points.Count -eq 1) {
            $Result.FirstDate = [string]$Points[0].Date
            $Result.LatestDate = [string]$Points[0].Date
            $Result.FirstBytes = [long]$Points[0].$Property
            $Result.LatestBytes = [long]$Points[0].$Property
        }
        return $Result
    }

    $First = $Points[0]
    $Last = $Points[-1]
    $Result.FirstDate = [string]$First.Date
    $Result.LatestDate = [string]$Last.Date
    $Result.FirstBytes = [long]$First.$Property
    $Result.LatestBytes = [long]$Last.$Property
    $Result.ChangeBytes = [long]($Result.LatestBytes - $Result.FirstBytes)
    if ($Result.FirstBytes -gt 0) {
        $Result.PercentChange = [math]::Round((($Result.LatestBytes - $Result.FirstBytes) / [double]$Result.FirstBytes) * 100, 1)
    }

    # ---- daily deltas, median rate, and step changes ---------------------------------
    $Deltas = [System.Collections.Generic.List[double]]::new()
    $IsStep = [System.Collections.Generic.List[bool]]::new()
    $StepChanges = [System.Collections.Generic.List[object]]::new()
    # A step is judged against current size: 5% of a 1 TB tenant is 50 GB, of a 10 GB tenant
    # 0.5 GB. The floor stops a rounding wobble on a tiny tenant reading as an event.
    $StepThreshold = [math]::Max([double]$Result.LatestBytes * 0.05, 100MB)

    # Gaps are measured in real days, not row positions. Once a scheduled collection is
    # ever missed the two stop agreeing, and dividing by row count would report a fortnight
    # of accumulation as one day of growth.
    $Gaps = [System.Collections.Generic.List[double]]::new()
    for ($i = 1; $i -lt $Points.Count; $i++) {
        $Delta = [double]($Points[$i].$Property - $Points[$i - 1].$Property)
        $Gap = 1.0
        try {
            $Gap = ([datetime]::Parse($Points[$i].Date, [cultureinfo]::InvariantCulture) -
                [datetime]::Parse($Points[$i - 1].Date, [cultureinfo]::InvariantCulture)).TotalDays
        } catch { $Gap = 1.0 }
        if ($Gap -le 0) { $Gap = 1.0 }

        $Deltas.Add($Delta)
        $Gaps.Add($Gap)

        # Only a SINGLE-day jump counts as a step. A large movement across a two-week gap
        # cannot be attributed to one event, and calling it one would discard a fortnight of
        # ordinary growth from the rate.
        $Step = ([math]::Abs($Delta) -ge $StepThreshold) -and ($Gap -le 1)
        $IsStep.Add($Step)
        if ($Step) {
            $StepChanges.Add([pscustomobject]@{
                    Date        = [string]$Points[$i].Date
                    ChangeBytes = [long]$Delta
                })
        }
    }
    $Result.StepChanges = @($StepChanges)

    if ($Deltas.Count -gt 0) {
        $Rates = @(for ($j = 0; $j -lt $Deltas.Count; $j++) { $Deltas[$j] / $Gaps[$j] })
        $Sorted = @($Rates | Sort-Object)
        $Mid = [int]([math]::Floor($Sorted.Count / 2))
        $Median = if ($Sorted.Count % 2 -eq 1) { $Sorted[$Mid] } else { ($Sorted[$Mid - 1] + $Sorted[$Mid]) / 2 }
        $Result.MedianBytesPerDay = [long][math]::Round($Median)
    }

    # ---- per-window rates -------------------------------------------------------------
    # ChangeBytes is the raw movement over the window - what actually happened, shown as-is.
    # BytesPerDay deliberately EXCLUDES days flagged as step changes and averages the rest.
    # Without that exclusion a one-off event inside the window sets the whole rate: a 50 GB
    # export on the final day of a 30-day window reads as 1.7 GB/day against a real trend of
    # 10 MB/day, and the projection is then wrong by two orders of magnitude. The step is not
    # hidden - it stays in ChangeBytes and in StepChanges - it just does not get a vote on
    # what happens next.
    function Get-WindowRate([int]$Span) {
        $Take = [math]::Min($Span, $Deltas.Count)
        $StartIdx = $Deltas.Count - $Take
        $KeptBytes = 0.0; $KeptDays = 0.0
        $RawBytes = 0.0; $RawDays = 0.0
        for ($j = $StartIdx; $j -lt $Deltas.Count; $j++) {
            $RawBytes += $Deltas[$j]; $RawDays += $Gaps[$j]
            if (-not $IsStep[$j]) { $KeptBytes += $Deltas[$j]; $KeptDays += $Gaps[$j] }
        }
        # Every day in the window was a step: nothing ordinary to average, so fall back to
        # the raw rate rather than claiming zero growth.
        if ($KeptDays -le 0) {
            if ($RawDays -le 0) { return 0L }
            return [long][math]::Round($RawBytes / $RawDays)
        }
        return [long][math]::Round($KeptBytes / $KeptDays)
    }

    $Windows = @{}
    foreach ($Span in @(30, 90, 180)) {
        if ($Points.Count -lt ($Span + 1)) { continue }
        $Start = $Points[$Points.Count - 1 - $Span]
        $Windows["$Span"] = [pscustomobject]@{
            Days        = $Span
            FromDate    = [string]$Start.Date
            ChangeBytes = [long]($Result.LatestBytes - $Start.$Property)
            BytesPerDay = Get-WindowRate $Span
        }
    }
    # Whole span too, when it is shorter than any named window - a two-week-old deployment
    # should still get a rate rather than nothing.
    if ($Windows.Count -eq 0) {
        $ElapsedDays = [math]::Max(1, [int][math]::Round(($Gaps | Measure-Object -Sum).Sum))
        $Windows['All'] = [pscustomobject]@{
            Days        = $ElapsedDays
            FromDate    = $Result.FirstDate
            ChangeBytes = $Result.ChangeBytes
            BytesPerDay = Get-WindowRate $Deltas.Count
        }
    }
    $Result.Windows = $Windows

    # ---- pick the projection basis ----------------------------------------------------
    $Basis = $null
    foreach ($Preferred in @('90', '30', '180', 'All')) {
        if ($Windows.ContainsKey($Preferred)) { $Basis = $Windows[$Preferred]; break }
    }
    $Result.BytesPerDay = [long]$Basis.BytesPerDay
    $Result.BasisWindowDays = [int]$Basis.Days

    $SpanDays = ($Gaps | Measure-Object -Sum).Sum
    $Result.Confidence = if ($SpanDays -ge 90) { 'High' } elseif ($SpanDays -ge 14) { 'Medium' } else { 'Low' }

    # ---- trend label -------------------------------------------------------------------
    $Short = if ($Windows.ContainsKey('30')) { $Windows['30'].BytesPerDay } else { $Result.BytesPerDay }
    $Long = if ($Windows.ContainsKey('90')) { $Windows['90'].BytesPerDay } else { $Result.BytesPerDay }
    # Accelerating needs BOTH a relative jump and an absolute one that matters.
    $Accelerating = $Long -gt 0 -and $Short -gt ($Long * 2) -and (($Short - $Long) -ge $MaterialityBytesPerDay)
    $Result.Trend = if ($Result.BytesPerDay -le 0 -and $Short -le 0) { 'Shrinking' }
    elseif ($Result.BytesPerDay -eq 0) { 'Flat' }
    elseif ($Accelerating) { 'Accelerating' }
    else { 'Growing' }

    if ($StepChanges.Count -gt 0) {
        $Result.Note = "$($StepChanges.Count) large single-day change(s) detected; whole-period figures may reflect a one-off event rather than a trend."
    }

    # ---- projection ---------------------------------------------------------------------
    if ($null -eq $QuotaBytes -or $QuotaBytes -le 0) {
        return $Result
    }
    if ($Result.BytesPerDay -le 0) {
        $Result.Note = "Consumption is flat or falling over the last $($Result.BasisWindowDays) days, so no exhaustion date is projected."
        return $Result
    }

    $Headroom = [double]$QuotaBytes - [double]$Result.LatestBytes
    if ($Headroom -le 0) {
        $Result.DaysUntilFull = 0
        $Result.ProjectedFullDate = $Result.LatestDate
        $Result.Note = 'Already at or over the quota.'
        return $Result
    }

    $DaysUntil = $Headroom / [double]$Result.BytesPerDay
    if ($DaysUntil -gt 3650) {
        $Result.Note = 'At the current rate the quota is more than ten years away.'
        return $Result
    }

    $Result.DaysUntilFull = [int][math]::Round($DaysUntil)
    $Result.ProjectedFullDate = ([datetime]::Parse($Result.LatestDate, [cultureinfo]::InvariantCulture)).AddDays($DaysUntil).ToString('yyyy-MM-dd')
    return $Result
}
