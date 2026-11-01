function Measure-CIPPAsrEvidence {
    <#
    .SYNOPSIS
        Summarises stored ASR evidence rows (table AsrEvidence) for one tenant over a window.
    .DESCRIPTION
        Pure. Rows are one per device per collection day: Device, Day (yyyyMMdd, UTC), Counts (JSON array of
        @{ RuleId; Audited; Blocked; Warned }) and RulesOnDevice. Rows older than WindowDays are ignored.
        Returns @{ Available; Source; CoverageDays; DevicesReporting; DevicesWithoutRules; ByRule; Notes } where
        ByRule maps upper-case rule GUID -> @{ Audited; Blocked; Warned; Devices }.
        CoverageDays counts back from Now to the oldest row inside the window, so a collector that has run every
        day for longer than the window reports the full window.
        Aspendora fork addition (Vikunja CIPP-26).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [object[]]$Rows = @(),
        [int]$WindowDays = 14,
        [datetime]$Now = [datetime]::UtcNow
    )
    $Today = $Now.Date
    $Cutoff = $Today.AddDays(-$WindowDays)
    $InWindow = [System.Collections.Generic.List[object]]::new()
    $Styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    foreach ($R in @($Rows)) {
        if ($null -eq $R -or -not $R.Day) { continue }
        $D = [datetime]::MinValue
        if (-not [datetime]::TryParseExact([string]$R.Day, 'yyyyMMdd', [cultureinfo]::InvariantCulture, $Styles, [ref]$D)) { continue }
        if ($D.Date -lt $Cutoff) { continue }
        $InWindow.Add([pscustomobject]@{ Row = $R; Date = $D.Date })
    }
    if ($InWindow.Count -eq 0) {
        return [pscustomobject]@{ Available = $false; Source = 'AsrEvidence table'; CoverageDays = 0; DevicesReporting = 0; DevicesWithoutRules = 0; ByRule = @{}; Notes = @("no collector data in the last $WindowDays day(s)") }
    }

    $Oldest = ($InWindow | Sort-Object Date | Select-Object -First 1).Date
    $Coverage = [int]($Today - $Oldest).TotalDays
    $Devices = @{}
    $ByRule = @{}
    $RuleDevices = @{}
    foreach ($E in $InWindow) {
        $Dev = ([string]$E.Row.Device).ToUpperInvariant()
        $Devices[$Dev] = $true
        $Counts = @()
        if ($E.Row.Counts) { $Counts = @(([string]$E.Row.Counts) | ConvertFrom-Json -ErrorAction SilentlyContinue) }
        foreach ($C in $Counts) {
            if ($null -eq $C -or -not $C.RuleId) { continue }
            $Id = ([string]$C.RuleId).Trim().ToUpperInvariant()
            if (-not $ByRule.ContainsKey($Id)) { $ByRule[$Id] = [pscustomobject]@{ Audited = 0; Blocked = 0; Warned = 0; Devices = 0 }; $RuleDevices[$Id] = @{} }
            $ByRule[$Id].Audited += [int]($C.Audited ?? 0)
            $ByRule[$Id].Blocked += [int]($C.Blocked ?? 0)
            $ByRule[$Id].Warned += [int]($C.Warned ?? 0)
            if (([int]($C.Audited ?? 0) + [int]($C.Blocked ?? 0) + [int]($C.Warned ?? 0)) -gt 0) { $RuleDevices[$Id][$Dev] = $true }
        }
    }
    foreach ($Id in @($ByRule.Keys)) { $ByRule[$Id].Devices = $RuleDevices[$Id].Count }
    # A device that later received rules is not "without rules".
    $Latest = @{}
    foreach ($E in ($InWindow | Sort-Object Date)) { $Latest[([string]$E.Row.Device).ToUpperInvariant()] = $E.Row }
    $WithoutRules = @($Latest.Values | Where-Object { $null -ne $_.RulesOnDevice -and [int]$_.RulesOnDevice -eq 0 }).Count

    [pscustomobject]@{
        Available           = $true
        Source              = 'AsrEvidence table'
        CoverageDays        = $Coverage
        DevicesReporting    = $Devices.Count
        DevicesWithoutRules = $WithoutRules
        ByRule              = $ByRule
        Notes               = @()
    }
}
