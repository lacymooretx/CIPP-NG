function Find-CIPPIntuneSettingOverlap {
    <#
    .SYNOPSIS
        Flags Settings Catalog settings configured by more than one policy.
    .DESCRIPTION
        Pure function. Input is the /configurationPolicies/{id}/settings collection of each applicable policy.
        Settings are keyed on the top-level settingInstance.settingDefinitionId; the value is compared as a canonical
        JSON of the instance (children included, template references and @odata.type dropped). Two or more policies
        setting the same definition with different values is a Conflict; with the same value an Overlap (harmless
        but redundant, and a conflict waiting to happen when one of them is edited).
        Aspendora fork addition (Vikunja CIPP-19).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        # @{ PolicyId; PolicyName; Settings = Graph deviceManagementConfigurationSetting objects }
        [object[]]$PolicySettings = @()
    )

    $Drop = @('settingInstanceTemplateReference', 'settingValueTemplateReference', 'auditRuleInformation', '@odata.type')
    $Canon = $null
    $Canon = {
        param($Node)
        if ($null -eq $Node) { return 'null' }
        if ($Node -is [string]) { return ($Node | ConvertTo-Json -Compress) }
        if ($Node -is [bool] -or $Node -is [int] -or $Node -is [long] -or $Node -is [double] -or $Node -is [decimal] -or $Node -is [datetime] -or $Node -is [guid]) { return ($Node | ConvertTo-Json -Compress) }
        if ($Node -is [System.Collections.IDictionary]) {
            $Keys = @($Node.Keys | Where-Object { $_ -notin $Drop } | Sort-Object)
            return '{' + (@($Keys | ForEach-Object { "$($_ | ConvertTo-Json -Compress):$(& $Canon $Node[$_])" }) -join ',') + '}'
        }
        if ($Node -is [System.Collections.IEnumerable]) {
            return '[' + (@($Node | ForEach-Object { & $Canon $_ }) -join ',') + ']'
        }
        $Props = @($Node.PSObject.Properties | Where-Object { $_.Name -notin $Drop } | Sort-Object Name)
        return '{' + (@($Props | ForEach-Object { "$($_.Name | ConvertTo-Json -Compress):$(& $Canon $_.Value)" }) -join ',') + '}'
    }

    # Short human-readable value for the table; the canonical JSON is what is compared.
    $Friendly = {
        param($Instance, [string]$Def)
        $V = if ($null -ne $Instance.simpleSettingValue) { $Instance.simpleSettingValue.value }
             elseif ($null -ne $Instance.choiceSettingValue) { ([string]$Instance.choiceSettingValue.value) -replace ('^' + [regex]::Escape($Def) + '_'), '' }
             elseif ($null -ne $Instance.simpleSettingCollectionValue) { @($Instance.simpleSettingCollectionValue.value) -join ', ' }
             elseif ($null -ne $Instance.choiceSettingCollectionValue) { @($Instance.choiceSettingCollectionValue.value | ForEach-Object { ([string]$_) -replace ('^' + [regex]::Escape($Def) + '_'), '' }) -join ', ' }
             else { '(group of settings)' }
        $T = [string]$V
        if ($T.Length -gt 120) { $T = $T.Substring(0, 117) + '...' }
        $T
    }

    $BySetting = @{}
    foreach ($P in @($PolicySettings)) {
        foreach ($S in @($P.Settings)) {
            $Instance = $S.settingInstance
            $Def = [string]$Instance.settingDefinitionId
            if (-not $Def) { continue }
            if (-not $BySetting.ContainsKey($Def)) { $BySetting[$Def] = [System.Collections.Generic.List[object]]::new() }
            $BySetting[$Def].Add([pscustomobject]@{ PolicyId = [string]$P.PolicyId; PolicyName = [string]$P.PolicyName; Value = (& $Canon $Instance); Display = (& $Friendly $Instance $Def) })
        }
    }

    $Out = foreach ($Def in ($BySetting.Keys | Sort-Object)) {
        $Entries = @($BySetting[$Def])
        $Policies = @($Entries.PolicyId | Sort-Object -Unique)
        if ($Policies.Count -lt 2) { continue }
        $Values = @($Entries.Value | Sort-Object -Unique)
        [pscustomobject]@{
            SettingDefinitionId = $Def
            Severity            = if ($Values.Count -gt 1) { 'Conflict' } else { 'Overlap' }
            PolicyCount         = $Policies.Count
            Policies            = (@($Entries.PolicyName | Sort-Object -Unique) -join ' | ')
            Values              = (@($Entries | ForEach-Object { "$($_.PolicyName) = $($_.Display)" } | Sort-Object -Unique) -join ' | ')
        }
    }
    @($Out | Sort-Object @{ Expression = { if ($_.Severity -eq 'Conflict') { 0 } else { 1 } } }, SettingDefinitionId)
}
