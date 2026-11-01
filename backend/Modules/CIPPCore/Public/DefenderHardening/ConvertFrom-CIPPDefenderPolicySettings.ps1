function ConvertFrom-CIPPDefenderPolicySettings {
    <#
    .SYNOPSIS
        Pulls the Defender hardening settings out of one Settings Catalog / endpoint security policy's settings.
    .DESCRIPTION
        Pure. Input is the 'value' array of GET /deviceManagement/configurationPolicies/{id}/settings. Walks every
        choice setting (nested group collections included) and returns:
          AsrRules          one row per ASR rule set by the policy: SettingName, RuleId, Name, Mode
                            (Block / Audit / Warn / Off), ExclusionCount (per-rule exclusions)
          NetworkProtection Block / Audit / Disabled, or $null when the policy does not set it
                            (device_vendor_msft_policy_config_defender_enablenetworkprotection _1 / _2 / _0)
          DeviceControl     $null, or @{ Enabled; DefaultEnforcement (Allow / Deny / $null); EntryTypes }
                            where EntryTypes are the rule entry types (Allow, Deny, AuditAllowed, AuditDenied)
        Aspendora fork addition (Vikunja CIPP-26).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([object[]]$Settings = @())

    $AsrPrefix = 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_'
    $Catalog = @{}
    foreach ($R in Get-CIPPAsrRuleCatalog) { $Catalog[$R.SettingName] = $R }

    $Choices = [System.Collections.Generic.List[object]]::new()
    $Exclusions = @{}
    $Walk = $null
    $Walk = {
        param($Instance)
        if ($null -eq $Instance) { return }
        $Def = [string]$Instance.settingDefinitionId
        if ($Instance.choiceSettingValue) {
            $Choices.Add([pscustomobject]@{ Id = $Def; Value = [string]$Instance.choiceSettingValue.value })
            foreach ($C in @($Instance.choiceSettingValue.children)) { & $Walk $C }
        }
        if ($Def -like "$AsrPrefix*_perruleexclusions") {
            $Exclusions[$Def.Substring($AsrPrefix.Length) -replace '_perruleexclusions$', ''] = @($Instance.simpleSettingCollectionValue).Count
        }
        foreach ($Group in @($Instance.groupSettingCollectionValue)) {
            foreach ($C in @($Group.children)) { & $Walk $C }
        }
        if ($Instance.groupSettingValue) {
            foreach ($C in @($Instance.groupSettingValue.children)) { & $Walk $C }
        }
    }
    foreach ($S in @($Settings)) {
        if ($null -eq $S) { continue }
        & $Walk ($S.settingInstance ?? $S)
    }

    $Asr = [System.Collections.Generic.List[object]]::new()
    $Network = $null
    $DcEnabled = $null
    $DcDefault = $null
    $EntryTypes = [System.Collections.Generic.List[string]]::new()

    foreach ($C in $Choices) {
        $Suffix = ($C.Value -split '_')[-1]
        if ($C.Id -like "$AsrPrefix*" -and $C.Id -notlike '*_perruleexclusions') {
            $Name = $C.Id.Substring($AsrPrefix.Length)
            $Mode = switch ($Suffix) { 'block' { 'Block' } 'audit' { 'Audit' } 'warn' { 'Warn' } 'off' { 'Off' } default { "Unknown ($Suffix)" } }
            $Known = $Catalog[$Name]
            $Asr.Add([pscustomobject]@{
                    SettingName    = $Name
                    RuleId         = if ($Known) { $Known.RuleId } else { '' }
                    Name           = if ($Known) { $Known.Name } else { $Name }
                    Mode           = $Mode
                    ExclusionCount = [int]($Exclusions[$Name] ?? 0)
                })
            continue
        }
        switch ($C.Id) {
            'device_vendor_msft_policy_config_defender_enablenetworkprotection' {
                $Network = switch ($Suffix) { '1' { 'Block' } '2' { 'Audit' } '0' { 'Disabled' } default { "Unknown ($Suffix)" } }
            }
            'device_vendor_msft_defender_configuration_devicecontrolenabled' { $DcEnabled = ($Suffix -eq '1') }
            'device_vendor_msft_defender_configuration_defaultenforcement' {
                $DcDefault = switch ($Suffix) { '1' { 'Allow' } '2' { 'Deny' } default { $null } }
            }
        }
        if ($C.Id -like 'device_vendor_msft_defender_configuration_devicecontrol_policyrules_*_ruledata_entry_type') {
            $T = switch ($Suffix) { 'allow' { 'Allow' } 'deny' { 'Deny' } 'auditallowed' { 'AuditAllowed' } 'auditdenied' { 'AuditDenied' } default { $Suffix } }
            if (-not $EntryTypes.Contains($T)) { $EntryTypes.Add($T) }
        }
    }

    $DeviceControl = $null
    if ($null -ne $DcEnabled -or $null -ne $DcDefault -or $EntryTypes.Count -gt 0) {
        $DeviceControl = [pscustomobject]@{ Enabled = $DcEnabled; DefaultEnforcement = $DcDefault; EntryTypes = @($EntryTypes) }
    }

    [pscustomobject]@{
        AsrRules          = @($Asr)
        NetworkProtection = $Network
        DeviceControl     = $DeviceControl
    }
}
