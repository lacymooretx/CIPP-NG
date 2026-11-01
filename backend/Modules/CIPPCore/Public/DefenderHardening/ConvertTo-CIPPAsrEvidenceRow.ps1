function ConvertTo-CIPPAsrEvidenceRow {
    <#
    .SYNOPSIS
        Turns one device's Get-AsrEvents output (the ControlR collector) into an AsrEvidence table row.
    .DESCRIPTION
        Pure. Report is the collector's JSON object: Device, CollectedUtc, WindowHours, RulesOnDevice, ConfiguredMix,
        Detections (each with RuleId and Mode Audited / Blocked / Warned). Only per-rule counts are kept, plus up to
        five distinct process names per rule for context: command lines, paths and user names are dropped so the
        table holds no per-user detail.
        One row per tenant, device and UTC collection day (RowKey 'DEVICE|yyyyMMdd'): a second run on the same day
        replaces the first, which matches the collector's rolling 24-hour window.
        Aspendora fork addition (Vikunja CIPP-26).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantFilter,
        [Parameter(Mandatory)]$Report
    )
    $Device = ([string]$Report.Device).Trim().ToUpperInvariant()
    if (-not $Device) { throw 'Report has no Device.' }
    if ($Device -match '[\\/#?|]') { throw "Device name '$Device' contains characters a table key cannot hold." }
    $Collected = [datetime]::UtcNow
    if ($Report.CollectedUtc) {
        try { $Collected = ([datetimeoffset]$Report.CollectedUtc).UtcDateTime } catch { throw "CollectedUtc '$($Report.CollectedUtc)' is not a date." }
    }
    $Day = $Collected.ToString('yyyyMMdd')

    $ByRule = [ordered]@{}
    foreach ($D in @($Report.Detections)) {
        if ($null -eq $D -or -not $D.RuleId) { continue }
        $Id = ([string]$D.RuleId).Trim().ToUpperInvariant()
        if (-not $ByRule.Contains($Id)) { $ByRule[$Id] = [ordered]@{ RuleId = $Id; Audited = 0; Blocked = 0; Warned = 0; Processes = [System.Collections.Generic.List[string]]::new() } }
        switch ([string]$D.Mode) {
            'Blocked' { $ByRule[$Id].Blocked++ }
            'Warned' { $ByRule[$Id].Warned++ }
            default { $ByRule[$Id].Audited++ }
        }
        $Proc = [string]$D.ProcessName
        if ($Proc) {
            $Leaf = ($Proc -split '[\\/]')[-1]
            if ($ByRule[$Id].Processes.Count -lt 5 -and -not $ByRule[$Id].Processes.Contains($Leaf)) { $ByRule[$Id].Processes.Add($Leaf) }
        }
    }
    $Counts = @($ByRule.Values | ForEach-Object { [pscustomobject]@{ RuleId = $_.RuleId; Audited = $_.Audited; Blocked = $_.Blocked; Warned = $_.Warned; Processes = @($_.Processes) } })

    @{
        PartitionKey  = $TenantFilter.ToLowerInvariant()
        RowKey        = "$Device|$Day"
        Device        = $Device
        Day           = $Day
        CollectedUtc  = $Collected.ToString('o')
        WindowHours   = [int]($Report.WindowHours ?? 24)
        RulesOnDevice = if ($null -ne $Report.RulesOnDevice) { [int]$Report.RulesOnDevice } else { -1 }
        ConfiguredMix = [string]$Report.ConfiguredMix
        Counts        = [string](ConvertTo-Json -InputObject @($Counts) -Depth 4 -Compress)
        Source        = 'ControlR Get-AsrEvents'
    }
}
