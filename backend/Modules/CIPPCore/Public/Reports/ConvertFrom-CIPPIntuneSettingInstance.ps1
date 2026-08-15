function ConvertFrom-CIPPIntuneSettingInstance {
    <#
    .SYNOPSIS
        Flatten a settings-catalog settingInstance tree into readable Setting/Value pairs.
    .DESCRIPTION
        Settings-catalog policies store their configuration as a recursive
        settingInstance tree keyed on Graph setting definition IDs, e.g.

          device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockwin32apicallsfromofficemacros

        and values that repeat the definition ID with the option appended
        (`..._blockwin32apicallsfromofficemacros_audit`).

        Resolving those IDs against Graph's own `deviceManagement/configurationSettings`
        catalogue gives the true display names, but costs a large extra fetch per tenant
        and a cache to hold it. The IDs are themselves descriptive, so this converts them
        directly: strip the vendor prefix, strip the definition prefix off the value, and
        split the remainder into a readable path. Good enough to document a tenant, with
        no additional Graph traffic.

        Handles every settingInstance shape Intune currently emits, and recurses through
        group collections and choice children.
    .PARAMETER Instance
        A settingInstance object (or a `settings` array element that contains one).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        # Not mandatory, and explicitly nullable: this is called in a loop over a policy's
        # settings array, where a null element must be skipped rather than throw and take
        # the whole section down with it.
        [AllowNull()]
        $Instance,

        # Recursion guard. Intune trees are shallow; this stops a malformed one dead.
        [int]$Depth = 0
    )

    $Results = [System.Collections.Generic.List[object]]::new()
    if ($null -eq $Instance -or $Depth -gt 8) { return $Results }

    # A `settings` array element wraps the real instance.
    if ($Instance.settingInstance) { $Instance = $Instance.settingInstance }

    $DefinitionId = [string]$Instance.settingDefinitionId
    if (-not $DefinitionId) { return $Results }

    $OdataType = [string]$Instance.'@odata.type'

    # ---- readable label from the definition ID -------------------------------------
    # device_vendor_msft_policy_config_defender_asr_blockfoo -> "Defender > Asr > Blockfoo"
    $Label = $DefinitionId
    foreach ($Prefix in @('device_vendor_msft_policy_config_', 'device_vendor_msft_', 'user_vendor_msft_policy_config_', 'user_vendor_msft_')) {
        if ($Label.StartsWith($Prefix)) { $Label = $Label.Substring($Prefix.Length); break }
    }
    $LabelText = ($Label -split '_' | Where-Object { $_ } | ForEach-Object {
            if ($_.Length -le 3) { $_.ToUpper() } else { (Get-Culture).TextInfo.ToTitleCase($_) }
        }) -join ' '

    # ---- strip the definition prefix off a value -----------------------------------
    function Format-SettingValue([string]$Value) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
        if ($Value.StartsWith("$DefinitionId`_")) { $Value = $Value.Substring($DefinitionId.Length + 1) }
        # values are frequently 0/1 or block/audit/enabled - title-case anything wordy
        if ($Value -match '^[a-z0-9]+$' -and $Value -notmatch '^\d+$') {
            return (Get-Culture).TextInfo.ToTitleCase($Value)
        }
        return $Value
    }

    switch -Wildcard ($OdataType) {
        '*ChoiceSettingInstance' {
            $Results.Add(@{ Setting = $LabelText; Value = (Format-SettingValue ([string]$Instance.choiceSettingValue.value)) })
            foreach ($Child in @($Instance.choiceSettingValue.children)) {
                foreach ($R in (ConvertFrom-CIPPIntuneSettingInstance -Instance $Child -Depth ($Depth + 1))) { $Results.Add($R) }
            }
        }
        '*SimpleSettingInstance' {
            $Results.Add(@{ Setting = $LabelText; Value = (Format-SettingValue ([string]$Instance.simpleSettingValue.value)) })
        }
        '*SimpleSettingCollectionInstance' {
            $Values = @($Instance.simpleSettingCollectionValue | ForEach-Object { [string]$_.value }) | Where-Object { $_ }
            $Results.Add(@{ Setting = $LabelText; Value = ($Values -join ', ') })
        }
        '*ChoiceSettingCollectionInstance' {
            foreach ($Choice in @($Instance.choiceSettingCollectionValue)) {
                $Results.Add(@{ Setting = $LabelText; Value = (Format-SettingValue ([string]$Choice.value)) })
                foreach ($Child in @($Choice.children)) {
                    foreach ($R in (ConvertFrom-CIPPIntuneSettingInstance -Instance $Child -Depth ($Depth + 1))) { $Results.Add($R) }
                }
            }
        }
        '*GroupSettingCollectionInstance' {
            # The group itself carries no value - its children are the settings.
            foreach ($Group in @($Instance.groupSettingCollectionValue)) {
                foreach ($Child in @($Group.children)) {
                    foreach ($R in (ConvertFrom-CIPPIntuneSettingInstance -Instance $Child -Depth ($Depth + 1))) { $Results.Add($R) }
                }
            }
        }
        '*GroupSettingInstance' {
            foreach ($Child in @($Instance.groupSettingValue.children)) {
                foreach ($R in (ConvertFrom-CIPPIntuneSettingInstance -Instance $Child -Depth ($Depth + 1))) { $Results.Add($R) }
            }
        }
        default {
            # Unknown shape: document that the setting is configured rather than drop it.
            $Results.Add(@{ Setting = $LabelText; Value = '(configured)' })
        }
    }

    return $Results
}
