function Get-CIPPTenantChangeTests {
    <#
    .SYNOPSIS
        New and fixed CIPP test results for one tenant, compared with the stored posture snapshot.
    .DESCRIPTION
        Read only: uses Get-CIPPPostureChange without -Snapshot, so nothing is stored. Test rows carry no date of their
        own, so a change can only be dated to "since the snapshot". When the newest usable snapshot is older than the
        window, the differences go in OlderChanges and the source is NotComparable: they may be weeks old, and listing
        them as today's changes would keep a quiet tenant permanently noisy. Snapshots are monthly unless the
        PostureSnapshot alert is scheduled more often.

        No stored results at all, or a failed read, throws. Without that check an empty read would look like every
        test had stopped being assessed. Aspendora fork addition (Vikunja CIPP-58).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Tenant,
        [int]$Days = 1,
        [int]$StaleDays = 3,
        [datetime]$Now = [datetime]::UtcNow
    )

    $Diff = Get-CIPPPostureChange -TenantFilter $Tenant -MinDays $Days

    # A Secure Score failure in this list belongs to the Secure Score source, which reads the score itself.
    $Errors = @(@($Diff.Errors) | Where-Object { $_ -and [string]$_ -notlike 'Secure Score*' })
    if ($Errors.Count -gt 0) { throw ($Errors -join ' ') }
    if ([int]$Diff.Counts.Tests -eq 0) { throw 'No stored test results for this tenant. The nightly test run has not written any.' }

    $LastRun = ConvertTo-CIPPTenantChangeUtc -Value $Diff.TestsLastRun
    $IsStale = -not $LastRun -or $LastRun -lt $Now.AddDays(-$StaleDays)
    $LastRunText = if ($LastRun) { "Tests last ran $(Format-CIPPCentralTime -Value $LastRun)." } else { 'The last test run has no readable date.' }

    if (-not $Diff.HasPrevious) {
        return [pscustomobject]@{
            Status       = 'NotComparable'
            Detail       = "No earlier posture snapshot to compare with. $LastRunText"
            Changes      = @()
            OlderChanges = @()
            NewIssues    = $null
            Fixed        = $null
            BaselineDate = $null
            BaselineDays = $null
        }
    }

    $Baseline = [string]$Diff.PreviousDate
    $Rows = [System.Collections.Generic.List[object]]::new()
    foreach ($Item in @($Diff.NewIssues)) {
        if ($null -eq $Item) { continue }
        $Rows.Add([pscustomobject]@{
                Source  = 'Test results'
                Change  = 'New issue'
                Risk    = [string]$Item.Risk
                Title   = [string]$Item.Name
                Detail  = (@($Item.Suite, $Item.Category, $Item.Change) | Where-Object { $_ }) -join ' / '
                When    = "Since $Baseline"
                WhenUtc = ''
                Link    = ''
            })
    }
    foreach ($Item in @($Diff.Fixed)) {
        if ($null -eq $Item) { continue }
        $Rows.Add([pscustomobject]@{
                Source  = 'Test results'
                Change  = 'Fixed'
                Risk    = [string]$Item.Risk
                Title   = [string]$Item.Name
                Detail  = (@($Item.Suite, $Item.Category) | Where-Object { $_ }) -join ' / '
                When    = "Since $Baseline"
                WhenUtc = ''
                Link    = ''
            })
    }

    $Summary = "$([int]$Diff.Counts.NewIssues) new and $([int]$Diff.Counts.Fixed) fixed since the snapshot of $Baseline ($($Diff.DaysBetween) days ago)."
    if ([int]$Diff.Counts.NoLongerAssessed -gt 0) { $Summary += " $([int]$Diff.Counts.NoLongerAssessed) open tests are no longer assessed, which is not the same as fixed." }

    if ($null -eq $Diff.DaysBetween -or [int]$Diff.DaysBetween -gt $Days) {
        return [pscustomobject]@{
            Status       = 'NotComparable'
            Detail       = "Newest usable snapshot is older than this window, so these changes cannot be dated. $Summary $LastRunText"
            Changes      = @()
            OlderChanges = @($Rows)
            NewIssues    = $null
            Fixed        = $null
            BaselineDate = $Baseline
            BaselineDays = $Diff.DaysBetween
        }
    }

    [pscustomobject]@{
        Status       = $(if ($IsStale) { 'Stale' } else { 'OK' })
        Detail       = "$Summary $LastRunText"
        Changes      = @($Rows)
        OlderChanges = @()
        NewIssues    = [int]$Diff.Counts.NewIssues
        Fixed        = [int]$Diff.Counts.Fixed
        BaselineDate = $Baseline
        BaselineDays = $Diff.DaysBetween
    }
}
