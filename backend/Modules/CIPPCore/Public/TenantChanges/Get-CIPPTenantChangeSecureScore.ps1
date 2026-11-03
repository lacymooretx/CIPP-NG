function Get-CIPPTenantChangeSecureScore {
    <#
    .SYNOPSIS
        Secure Score movement for one tenant across the window, reported only past a threshold.
    .DESCRIPTION
        Read only, from the nightly SecureScore cache that keeps about 14 daily points. The percentage is compared, not
        the points, because Microsoft moves the maximum as controls are added. A move smaller than Threshold percentage
        points is not a change. Nothing cached throws, so the caller can say "could not read".
        Aspendora fork addition (Vikunja CIPP-58).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Tenant,
        [int]$Days = 1,
        [double]$Threshold = 1,
        [int]$StaleDays = 3,
        [datetime]$Now = [datetime]::UtcNow
    )

    $Report = @(Get-CIPPSecureScoreReport -TenantFilter $Tenant -IncludeHistory) | Select-Object -First 1
    if (-not $Report) { throw 'No Secure Score is cached for this tenant.' }

    $Latest = ConvertTo-CIPPTenantChangeUtc -Value $Report.CapturedAt
    $Percent = [double]$Report.PercentageScore
    $LatestText = if ($Latest) { Format-CIPPCentralTime -Value $Latest } else { 'an unreadable date' }
    $IsStale = -not $Latest -or $Latest -lt $Now.AddDays(-$StaleDays)

    # Daily points are not exactly 24 hours apart, so allow six hours of slack when stepping back from the latest one.
    $Baseline = $null
    if ($Latest) {
        $StepBack = $Latest.AddDays(-$Days).AddHours(6)
        $Baseline = @($Report.History) |
            ForEach-Object { [pscustomobject]@{ When = (ConvertTo-CIPPTenantChangeUtc -Value $_.Date); Percent = [double]$_.PercentageScore } } |
            Where-Object { $_.When -and $_.When -le $StepBack } |
            Sort-Object -Property When -Descending |
            Select-Object -First 1
    }

    if (-not $Baseline) {
        return [pscustomobject]@{
            Status  = 'NotComparable'
            Detail  = "$Percent% on $LatestText. No earlier cached score to compare with."
            Changes = @()
            Percent = $Percent
            Delta   = $null
        }
    }

    $Delta = [math]::Round($Percent - $Baseline.Percent, 1)
    $BaselineText = Format-CIPPCentralTime -Value $Baseline.When
    $Changes = @()
    if ([math]::Abs($Delta) -ge $Threshold) {
        $Changes = @([pscustomobject]@{
                Source  = 'Secure Score'
                Change  = $(if ($Delta -gt 0) { 'Score up' } else { 'Score down' })
                Risk    = ''
                Title   = "Secure Score $Percent% (was $($Baseline.Percent)%)"
                Detail  = "$(if ($Delta -gt 0) { '+' })$Delta percentage points since $BaselineText"
                When    = $LatestText
                WhenUtc = $Latest.ToString('o')
                Link    = ''
            })
    }

    [pscustomobject]@{
        Status  = $(if ($IsStale) { 'Stale' } else { 'OK' })
        Detail  = "$Percent% on $LatestText, was $($Baseline.Percent)% on $BaselineText. Changes under $Threshold points are not listed."
        Changes = $Changes
        Percent = $Percent
        Delta   = $Delta
    }
}
