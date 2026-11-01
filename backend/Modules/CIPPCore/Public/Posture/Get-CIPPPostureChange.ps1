function Get-CIPPPostureChange {
    <#
    .SYNOPSIS
        Month-over-month posture change for a tenant: current posture vs a stored snapshot from about a month ago.
    .DESCRIPTION
        Builds the current posture (Get-CIPPPostureCurrent), optionally stores it as today's snapshot, then picks the
        baseline from the stored snapshots older than today:
          1. the NEWEST snapshot at least MinDays (default 25) older than today, so a monthly report compares with
             last month even when a snapshot was also taken a few days ago;
          2. otherwise the OLDEST earlier snapshot (history is still shorter than a month: compare with what exists);
          3. otherwise none, and the result is a baseline (HasPrevious = $false).
        Returns Compare-CIPPPostureSnapshot output plus BaselineRule (MinAge / Oldest / None), SnapshotStored and
        Errors. Aspendora fork addition (Vikunja CIPP-16).
    .PARAMETER TenantFilter
        Tenant default domain name or customerId.
    .PARAMETER Snapshot
        Store the current posture as today's snapshot before comparing (the report and the scripted alert do; the
        read-only ListPostureChange endpoint does not).
    .PARAMETER MinDays
        Minimum age of the preferred baseline.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [switch]$Snapshot,
        [int]$MinDays = 25
    )

    $Current = Get-CIPPPostureCurrent -TenantFilter $TenantFilter
    $Errors = [System.Collections.Generic.List[string]]::new()
    foreach ($E in @($Current.Errors)) { if ($E) { $Errors.Add([string]$E) } }

    $Stored = $false
    if ($Snapshot) {
        try { $Stored = [bool](Save-CIPPPostureSnapshot -Snapshot $Current) } catch { $Errors.Add("Snapshot could not be stored: $($_.Exception.Message)") }
    }

    $Previous = $null
    $Rule = 'None'
    try {
        # Not wrapped in @(): the reader returns its list with the comma operator, and @() would nest it.
        $Index = Get-CIPPPostureSnapshot -TenantFilter $Current.Tenant
        $Earlier = @($Index | Where-Object { $_.Date -and $_.Date -lt $Current.Date -and $_.TestCount -gt 0 } | Sort-Object -Property Date)
        if ($Earlier.Count -gt 0) {
            $Cutoff = ([datetime]::ParseExact($Current.Date, 'yyyy-MM-dd', [cultureinfo]::InvariantCulture)).AddDays(-$MinDays).ToString('yyyy-MM-dd')
            $Old = @($Earlier | Where-Object { $_.Date -le $Cutoff })
            if ($Old.Count -gt 0) { $Pick = $Old[-1]; $Rule = 'MinAge' } else { $Pick = $Earlier[0]; $Rule = 'Oldest' }
            $Previous = Get-CIPPPostureSnapshot -TenantFilter $Current.Tenant -Date $Pick.Date
            if (-not $Previous) { $Rule = 'None' }
        }
    } catch {
        $Errors.Add("Previous snapshots could not be read: $($_.Exception.Message)")
        $Rule = 'None'
    }

    $Diff = Compare-CIPPPostureSnapshot -Current $Current -Previous $Previous
    $Diff | Add-Member -NotePropertyName 'BaselineRule' -NotePropertyValue $(if ($Diff.HasPrevious) { $Rule } else { 'None' }) -Force
    $Diff | Add-Member -NotePropertyName 'MinDays' -NotePropertyValue $MinDays -Force
    $Diff | Add-Member -NotePropertyName 'SnapshotStored' -NotePropertyValue $Stored -Force
    $Diff | Add-Member -NotePropertyName 'TestsLastRun' -NotePropertyValue $Current.TestsLastRun -Force
    $Diff | Add-Member -NotePropertyName 'Errors' -NotePropertyValue $Errors -Force
    return $Diff
}
