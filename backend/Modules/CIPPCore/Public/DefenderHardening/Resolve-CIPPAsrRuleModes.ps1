function Resolve-CIPPAsrRuleModes {
    <#
    .SYNOPSIS
        Effective mode of every ASR rule across a tenant's ASR policies.
    .DESCRIPTION
        Pure. Input: one entry per policy that sets ASR rules, @{ PolicyId; PolicyName; Assigned; AssignmentLabel;
        Rules } where Rules are ConvertFrom-CIPPDefenderPolicySettings AsrRules rows.
        Only assigned policies count (an unassigned or exclusion-only policy applies to nothing). Per rule:
          one mode across the assigned policies   -> that mode
          different modes in two assigned policies -> Conflict (Intune reports a conflict and the device may keep
                                                     neither value; this is not a "most restrictive wins" merge)
          not set by any assigned policy           -> NotConfigured
        Every catalog rule gets a row, plus any rule the catalog does not know. This is tenant-level: it does not
        resolve group membership per device (use ListIntuneEffectivePolicy for one device).
        Aspendora fork addition (Vikunja CIPP-26).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([object[]]$PolicyRules = @())

    $Catalog = @(Get-CIPPAsrRuleCatalog)
    $Keys = [System.Collections.Generic.List[string]]::new()
    $Info = @{}
    foreach ($R in $Catalog) { $Keys.Add($R.SettingName); $Info[$R.SettingName] = $R }
    foreach ($P in @($PolicyRules)) {
        foreach ($Rule in @($P.Rules)) {
            if ($Rule -and -not $Info.ContainsKey($Rule.SettingName)) {
                $Keys.Add($Rule.SettingName)
                $Info[$Rule.SettingName] = [pscustomobject]@{ RuleId = $Rule.RuleId; Name = $Rule.Name; SettingName = $Rule.SettingName }
            }
        }
    }

    foreach ($Key in $Keys) {
        $Assigned = [System.Collections.Generic.List[object]]::new()
        $Unassigned = [System.Collections.Generic.List[string]]::new()
        $Exclusions = 0
        foreach ($P in @($PolicyRules)) {
            $Rule = @($P.Rules) | Where-Object { $_.SettingName -eq $Key } | Select-Object -First 1
            if (-not $Rule) { continue }
            if ($P.Assigned -eq $true) {
                $Assigned.Add([pscustomobject]@{ Policy = [string]$P.PolicyName; Mode = [string]$Rule.Mode; Assignment = [string]$P.AssignmentLabel })
                $Exclusions += [int]$Rule.ExclusionCount
            } else {
                $Unassigned.Add("$($P.PolicyName): $($Rule.Mode) ($($P.AssignmentLabel))")
            }
        }
        $Modes = @($Assigned | ForEach-Object { $_.Mode } | Sort-Object -Unique)
        $Effective = if ($Modes.Count -eq 0) { 'NotConfigured' } elseif ($Modes.Count -eq 1) { $Modes[0] } else { 'Conflict' }
        [pscustomobject]@{
            RuleId             = [string]$Info[$Key].RuleId
            Name               = [string]$Info[$Key].Name
            SettingName        = $Key
            EffectiveMode      = $Effective
            Policies           = @($Assigned | ForEach-Object { "$($_.Policy): $($_.Mode) -> $($_.Assignment)" })
            UnassignedPolicies = @($Unassigned)
            ExclusionCount     = $Exclusions
        }
    }
}
