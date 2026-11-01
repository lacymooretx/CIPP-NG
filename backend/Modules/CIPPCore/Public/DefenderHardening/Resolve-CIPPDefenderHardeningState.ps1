function Resolve-CIPPDefenderHardeningState {
    <#
    .SYNOPSIS
        Tenant-level Network Protection and Device Control state from the Defender policy inventory.
    .DESCRIPTION
        Pure. Policies are Get-CIPPDefenderPolicyInventory policies (Assigned, AssignmentLabel, Name, Parsed).
        Only assigned policies count.
        NetworkProtection: Block (Pass), Audit (Warn), Disabled / NotConfigured / Conflict (Fail). Web content
        filtering and custom URL indicators are enforced in browsers other than Edge only by Network Protection in
        Block, so Audit means those categories are logged but not blocked.
        DeviceControl: Enforced (default deny, or a Deny rule entry), Audit (only AuditAllowed / AuditDenied entries
        under default allow), EnabledNoRules, Disabled, NotConfigured. Audit is the expected state for the CIPP-26
        ring plan's first ring and is reported as Info, not as a failure.
        Returns two rows: @{ Control; State; Status; Policies; Detail }. Aspendora fork addition (Vikunja CIPP-26).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([object[]]$Policies = @())

    $Assigned = @($Policies | Where-Object { $_ -and $_.Assigned -eq $true })

    # Network Protection
    $Np = @($Assigned | Where-Object { $_.Parsed.NetworkProtection } | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Mode = [string]$_.Parsed.NetworkProtection; Label = $_.AssignmentLabel } })
    $NpModes = @($Np | ForEach-Object { $_.Mode } | Sort-Object -Unique)
    $NpState = if ($NpModes.Count -eq 0) { 'NotConfigured' } elseif ($NpModes.Count -gt 1) { 'Conflict' } else { $NpModes[0] }
    $NpStatus = switch ($NpState) { 'Block' { 'Pass' } 'Audit' { 'Warn' } default { 'Fail' } }
    $NpDetail = switch ($NpState) {
        'Block' { 'Network Protection is in Block: web content filtering and URL indicators are enforced in all browsers.' }
        'Audit' { 'Network Protection is in Audit: web content filtering and URL indicators are only logged outside Edge. Move to Block.' }
        'Conflict' { 'Assigned policies set Network Protection to different values; devices may apply neither.' }
        'Disabled' { 'An assigned policy disables Network Protection.' }
        default { 'No assigned Settings Catalog / endpoint security policy sets Network Protection (Defender default is off).' }
    }

    # Device Control
    $Dc = @($Assigned | Where-Object { $_.Parsed.DeviceControl })
    $Enabled = @($Dc | Where-Object { $_.Parsed.DeviceControl.Enabled -eq $true })
    $DcState = 'NotConfigured'
    if ($Dc.Count -gt 0 -and $Enabled.Count -eq 0) { $DcState = 'Disabled' }
    if ($Enabled.Count -gt 0) {
        $Types = @($Enabled | ForEach-Object { @($_.Parsed.DeviceControl.EntryTypes) } | Sort-Object -Unique)
        $DefaultDeny = @($Enabled | Where-Object { $_.Parsed.DeviceControl.DefaultEnforcement -eq 'Deny' }).Count -gt 0
        $Audits = @($Types | Where-Object { $_ -in @('AuditAllowed', 'AuditDenied') }).Count
        $DcState = if ($DefaultDeny -or 'Deny' -in $Types) { 'Enforced' } elseif ($Audits -gt 0) { 'Audit' } else { 'EnabledNoRules' }
    }
    $DcStatus = switch ($DcState) { 'Enforced' { 'Pass' } 'Audit' { 'Info' } default { 'Fail' } }
    $DcDetail = switch ($DcState) {
        'Enforced' { 'Device Control enforces removable storage rules (default deny or Deny entries).' }
        'Audit' { 'Device Control is auditing removable storage only (ring 0 of the plan). Review the events, then move to default deny with approved serial/vendor exceptions.' }
        'EnabledNoRules' { 'Device Control is enabled but no removable storage rule is set, so nothing is audited or blocked.' }
        'Disabled' { 'An assigned policy turns Device Control off.' }
        default { 'No assigned policy configures Device Control.' }
    }

    @(
        [pscustomobject]@{ Control = 'NetworkProtection'; State = $NpState; Status = $NpStatus; Policies = (@($Np | ForEach-Object { "$($_.Name): $($_.Mode) -> $($_.Label)" }) -join '; '); Detail = $NpDetail }
        [pscustomobject]@{ Control = 'DeviceControl'; State = $DcState; Status = $DcStatus; Policies = (@($Dc | ForEach-Object { "$($_.Name) -> $($_.AssignmentLabel)" }) -join '; '); Detail = $DcDetail }
    )
}
