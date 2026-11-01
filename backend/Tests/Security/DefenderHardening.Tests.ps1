# Aspendora fork (Vikunja CIPP-26 / CIPP-31): Defender hardening pack pure rules.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Dir = Join-Path $RepoRoot 'Modules/CIPPCore/Public/DefenderHardening'
    foreach ($F in @(
            'Get-CIPPAsrRuleCatalog', 'ConvertFrom-CIPPDefenderPolicySettings', 'Get-CIPPIntunePolicyAssignmentState',
            'Resolve-CIPPAsrRuleModes', 'Get-CIPPAsrRecommendation', 'Measure-CIPPAsrEvidence', 'ConvertTo-CIPPAsrEvidenceRow',
            'Resolve-CIPPDefenderHardeningState', 'Select-CIPPPendingRemediationAlerts'
        )) { . (Join-Path $Dir "$F.ps1") }

    $script:AsrPrefix = 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules'
    function AsrRule {
        param($Name, $Mode, [string[]]$Exclusions)
        $Children = @()
        if ($Exclusions) {
            $Children = @([pscustomobject]@{
                    '@odata.type'                = '#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance'
                    settingDefinitionId          = "$($script:AsrPrefix)_$($Name)_perruleexclusions"
                    simpleSettingCollectionValue = @($Exclusions | ForEach-Object { [pscustomobject]@{ value = $_ } })
                })
        }
        [pscustomobject]@{
            '@odata.type'      = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
            settingDefinitionId = "$($script:AsrPrefix)_$Name"
            choiceSettingValue  = [pscustomobject]@{ value = "$($script:AsrPrefix)_$($Name)_$Mode"; children = $Children }
        }
    }
    function AsrPolicySettings {
        param([object[]]$Rules)
        @([pscustomobject]@{
                id              = '0'
                settingInstance = [pscustomobject]@{
                    '@odata.type'               = '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'
                    settingDefinitionId         = $script:AsrPrefix
                    groupSettingCollectionValue = @([pscustomobject]@{ children = $Rules })
                }
            })
    }
    function Choice {
        param($Def, $Value)
        [pscustomobject]@{ settingInstance = [pscustomobject]@{ settingDefinitionId = $Def; choiceSettingValue = [pscustomobject]@{ value = "$($Def)_$Value"; children = @() } } }
    }
    function Target { param($Type, $GroupId) [pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = "#microsoft.graph.$Type"; groupId = $GroupId } } }
}

Describe 'Get-CIPPAsrRuleCatalog' {
    It 'lists 19 rules with unique ids and setting names' {
        $C = @(Get-CIPPAsrRuleCatalog)
        $C.Count | Should -Be 19
        @($C.RuleId | Sort-Object -Unique).Count | Should -Be 19
        @($C.SettingName | Sort-Object -Unique).Count | Should -Be 19
        ($C | Where-Object SettingName -EQ 'blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem').RuleId | Should -Be '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2'
    }
}

Describe 'ConvertFrom-CIPPDefenderPolicySettings' {
    It 'reads ASR rule modes and per-rule exclusions from the live policy shape' {
        $S = AsrPolicySettings @(
            (AsrRule 'blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem' 'block' @('C:\a', 'C:\b'))
            (AsrRule 'blockprocesscreationsfrompsexecandwmicommands' 'audit')
            (AsrRule 'blockrebootingmachineinsafemode' 'warn')
            (AsrRule 'somefuturerule' 'off')
        )
        $R = ConvertFrom-CIPPDefenderPolicySettings -Settings $S
        $R.AsrRules.Count | Should -Be 4
        $Lsass = $R.AsrRules | Where-Object SettingName -Like '*localsecurityauthority*'
        $Lsass.Mode | Should -Be 'Block'
        $Lsass.ExclusionCount | Should -Be 2
        $Lsass.RuleId | Should -Be '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2'
        ($R.AsrRules | Where-Object SettingName -EQ 'blockprocesscreationsfrompsexecandwmicommands').Mode | Should -Be 'Audit'
        ($R.AsrRules | Where-Object SettingName -EQ 'blockrebootingmachineinsafemode').Mode | Should -Be 'Warn'
        $Unknown = $R.AsrRules | Where-Object SettingName -EQ 'somefuturerule'
        $Unknown.RuleId | Should -Be ''
        $Unknown.Mode | Should -Be 'Off'
        $R.NetworkProtection | Should -BeNullOrEmpty
        $R.DeviceControl | Should -BeNullOrEmpty
    }

    It 'maps Network Protection _1 / _2 / _0 to Block / Audit / Disabled' {
        foreach ($Case in @(@('1', 'Block'), @('2', 'Audit'), @('0', 'Disabled'))) {
            $R = ConvertFrom-CIPPDefenderPolicySettings -Settings @(Choice 'device_vendor_msft_policy_config_defender_enablenetworkprotection' $Case[0])
            $R.NetworkProtection | Should -Be $Case[1]
        }
    }

    It 'reads Device Control enablement, default enforcement and nested rule entry types' {
        $Entry = [pscustomobject]@{
            settingDefinitionId         = 'device_vendor_msft_defender_configuration_devicecontrol_policyrules_{ruleid}_ruledata_entry'
            groupSettingCollectionValue = @([pscustomobject]@{ children = @(
                        [pscustomobject]@{ settingDefinitionId = 'device_vendor_msft_defender_configuration_devicecontrol_policyrules_{ruleid}_ruledata_entry_type'; choiceSettingValue = [pscustomobject]@{ value = 'device_vendor_msft_defender_configuration_devicecontrol_policyrules_{ruleid}_ruledata_entry_type_auditallowed'; children = @() } }
                    )
                })
        }
        $Rule = [pscustomobject]@{ settingInstance = [pscustomobject]@{
                settingDefinitionId         = 'device_vendor_msft_defender_configuration_devicecontrol_policyrules_{ruleid}'
                groupSettingCollectionValue = @([pscustomobject]@{ children = @([pscustomobject]@{ settingDefinitionId = 'device_vendor_msft_defender_configuration_devicecontrol_policyrules_{ruleid}_ruledata'; groupSettingCollectionValue = @([pscustomobject]@{ children = @($Entry) }) }) })
            }
        }
        $R = ConvertFrom-CIPPDefenderPolicySettings -Settings @(
            (Choice 'device_vendor_msft_defender_configuration_devicecontrolenabled' '1')
            (Choice 'device_vendor_msft_defender_configuration_defaultenforcement' '1')
            $Rule
        )
        $R.DeviceControl.Enabled | Should -BeTrue
        $R.DeviceControl.DefaultEnforcement | Should -Be 'Allow'
        $R.DeviceControl.EntryTypes | Should -Be @('AuditAllowed')
    }

    It 'parses the shipped audit-only Device Control template as Audit' {
        $Path = Join-Path (Split-Path -Parent $RepoRoot) 'docs/defender-templates/02-device-control-removable-storage-audit.configurationPolicy.json'
        $Policy = Get-Content -Raw $Path | ConvertFrom-Json -Depth 50
        $R = ConvertFrom-CIPPDefenderPolicySettings -Settings @($Policy.settings)
        $R.DeviceControl.Enabled | Should -BeTrue
        $R.DeviceControl.DefaultEnforcement | Should -Be 'Allow'
        $R.DeviceControl.EntryTypes | Should -Be @('AuditAllowed')
        $State = Resolve-CIPPDefenderHardeningState -Policies @([pscustomobject]@{ Name = 'DC'; Assigned = $true; AssignmentLabel = 'All Devices'; Parsed = $R })
        ($State | Where-Object Control -EQ 'DeviceControl').State | Should -Be 'Audit'
    }
}

Describe 'Get-CIPPIntunePolicyAssignmentState' {
    It 'treats include targets as assigned and names them' {
        $S = Get-CIPPIntunePolicyAssignmentState -Assignments @((Target 'allDevicesAssignmentTarget'), (Target 'groupAssignmentTarget' 'g1')) -GroupNames @{ g1 = 'Pilot' }
        $S.Assigned | Should -BeTrue
        $S.Label | Should -Be "All Devices, Group 'Pilot'"
    }
    It 'does not count an exclusion group as an include (wildcard overlap)' {
        $S = Get-CIPPIntunePolicyAssignmentState -Assignments @(Target 'exclusionGroupAssignmentTarget' 'x')
        $S.Assigned | Should -BeFalse
        $S.Label | Should -Be 'Exclusions only'
    }
    It 'reports an unassigned policy' {
        (Get-CIPPIntunePolicyAssignmentState -Assignments @()).Label | Should -Be 'Not assigned'
    }
}

Describe 'Resolve-CIPPAsrRuleModes' {
    BeforeAll {
        function PR { param($Name, $Assigned, [object[]]$Rules) [pscustomobject]@{ PolicyId = $Name; PolicyName = $Name; Assigned = $Assigned; AssignmentLabel = 'All Devices'; Rules = $Rules } }
        function NewAsrRuleRow { param($SettingName, $Mode) [pscustomobject]@{ SettingName = $SettingName; RuleId = ''; Name = $SettingName; Mode = $Mode; ExclusionCount = 0 } }
    }
    It 'returns a row for every catalog rule, NotConfigured when nothing sets it' {
        $Rows = @(Resolve-CIPPAsrRuleModes -PolicyRules @())
        $Rows.Count | Should -Be 19
        @($Rows.EffectiveMode | Sort-Object -Unique) | Should -Be @('NotConfigured')
    }
    It 'ignores unassigned policies but lists them' {
        $Rows = Resolve-CIPPAsrRuleModes -PolicyRules @((PR 'Old' $false @(NewAsrRuleRow 'blockrebootingmachineinsafemode' 'Block')))
        $Row = $Rows | Where-Object SettingName -EQ 'blockrebootingmachineinsafemode'
        $Row.EffectiveMode | Should -Be 'NotConfigured'
        $Row.UnassignedPolicies | Should -Match 'Old: Block'
    }
    It 'agrees when assigned policies agree and flags Conflict when they differ' {
        $Rows = Resolve-CIPPAsrRuleModes -PolicyRules @(
            (PR 'A' $true @((NewAsrRuleRow 'blockrebootingmachineinsafemode' 'Audit'), (NewAsrRuleRow 'blockwebshellcreationforservers' 'Block')))
            (PR 'B' $true @((NewAsrRuleRow 'blockrebootingmachineinsafemode' 'Audit'), (NewAsrRuleRow 'blockwebshellcreationforservers' 'Audit')))
        )
        ($Rows | Where-Object SettingName -EQ 'blockrebootingmachineinsafemode').EffectiveMode | Should -Be 'Audit'
        ($Rows | Where-Object SettingName -EQ 'blockwebshellcreationforservers').EffectiveMode | Should -Be 'Conflict'
    }
    It 'keeps rules the catalog does not know' {
        $Rows = @(Resolve-CIPPAsrRuleModes -PolicyRules @((PR 'A' $true @(NewAsrRuleRow 'brandnewrule' 'Audit'))))
        $Rows.Count | Should -Be 20
        ($Rows | Where-Object SettingName -EQ 'brandnewrule').EffectiveMode | Should -Be 'Audit'
    }
}

Describe 'Get-CIPPAsrRecommendation' {
    BeforeAll { $script:Good = [pscustomobject]@{ Available = $true; CoverageDays = 14; DevicesReporting = 10; Notes = @() } }
    It 'calls an audit rule with no hits over a covered window ready for block' {
        (Get-CIPPAsrRecommendation -Mode 'Audit' -Evidence $script:Good -RuleEvidence $null -WindowDays 14).Recommendation | Should -Be 'ReadyForBlock'
    }
    It 'never treats missing evidence as no hits' {
        $None = [pscustomobject]@{ Available = $false; CoverageDays = 0; DevicesReporting = 0; Notes = @('advanced hunting device tables are not provisioned') }
        $R = Get-CIPPAsrRecommendation -Mode 'Audit' -Evidence $None -RuleEvidence $null
        $R.Recommendation | Should -Be 'KeepAudit'
        $R.Reason | Should -Match 'not provisioned'
        (Get-CIPPAsrRecommendation -Mode 'Audit' -Evidence $null -RuleEvidence $null).Recommendation | Should -Be 'KeepAudit'
    }
    It 'needs the full window of evidence' {
        $Short = [pscustomobject]@{ Available = $true; CoverageDays = 3; DevicesReporting = 10 }
        (Get-CIPPAsrRecommendation -Mode 'Audit' -Evidence $Short -RuleEvidence $null -WindowDays 14).Reason | Should -Match 'Only 3 day'
    }
    It 'keeps audit when there are audit or warn hits' {
        $R = Get-CIPPAsrRecommendation -Mode 'Warn' -Evidence $script:Good -RuleEvidence ([pscustomobject]@{ Audited = 4; Warned = 1; Blocked = 0; Devices = 2 })
        $R.Recommendation | Should -Be 'KeepAudit'
        $R.Reason | Should -Match '^5 audit hit\(s\) on 2 device'
    }
    It 'handles Block, Conflict, NotConfigured and Off' {
        (Get-CIPPAsrRecommendation -Mode 'Block' -Evidence $script:Good -RuleEvidence ([pscustomobject]@{ Blocked = 3; Devices = 1 })).Reason | Should -Match '3 block'
        (Get-CIPPAsrRecommendation -Mode 'Conflict' -Evidence $script:Good).Recommendation | Should -Be 'FixConflict'
        (Get-CIPPAsrRecommendation -Mode 'NotConfigured' -Evidence $script:Good).Recommendation | Should -Be 'NotConfigured'
        (Get-CIPPAsrRecommendation -Mode 'Off' -Evidence $script:Good).Recommendation | Should -Be 'NotConfigured'
    }
}

Describe 'ConvertTo-CIPPAsrEvidenceRow and Measure-CIPPAsrEvidence' {
    BeforeAll {
        $script:Now = [datetime]::new(2026, 10, 31, 12, 0, 0, [DateTimeKind]::Utc)
        function Report {
            param($Device, $Day, [object[]]$Detections = @(), $Rules = 19)
            [pscustomobject]@{ Device = $Device; CollectedUtc = "$($Day)T11:00:00Z"; WindowHours = 24; RulesOnDevice = $Rules; ConfiguredMix = 'Audit=19'; Detections = $Detections }
        }
        function Det { param($RuleId, $Mode, $Proc = 'C:\Program Files\X\x.exe') [pscustomobject]@{ RuleId = $RuleId; Mode = $Mode; ProcessName = $Proc; CommandLine = 'secret args'; User = 'CONTOSO\bob'; Path = 'C:\Users\bob\file' } }
    }
    It 'keeps counts and process leaf names only' {
        $Row = ConvertTo-CIPPAsrEvidenceRow -TenantFilter 'Contoso.com' -Report (Report 'pc-1' '2026-10-30' @((Det 'd1e49aac-8f56-4280-b9ba-993a6d77406c' 'Audited'), (Det 'D1E49AAC-8F56-4280-B9BA-993A6D77406C' 'Blocked')))
        $Row.PartitionKey | Should -Be 'contoso.com'
        $Row.RowKey | Should -Be 'PC-1|20261030'
        $Row.Counts | Should -Not -Match 'secret|bob'
        $C = $Row.Counts | ConvertFrom-Json
        $C.RuleId | Should -Be 'D1E49AAC-8F56-4280-B9BA-993A6D77406C'
        $C.Audited | Should -Be 1
        $C.Blocked | Should -Be 1
        @($C.Processes) | Should -Be @('x.exe')
    }
    It 'rejects a device name a table key cannot hold' {
        { ConvertTo-CIPPAsrEvidenceRow -TenantFilter 't' -Report (Report 'a/b' '2026-10-30') } | Should -Throw
    }
    It 'summarises devices, coverage and per-rule hits inside the window' {
        $Rows = @(
            (ConvertTo-CIPPAsrEvidenceRow -TenantFilter 't' -Report (Report 'PC-1' '2026-10-17'))
            (ConvertTo-CIPPAsrEvidenceRow -TenantFilter 't' -Report (Report 'PC-1' '2026-10-30' @(Det 'D1E49AAC-8F56-4280-B9BA-993A6D77406C' 'Audited')))
            (ConvertTo-CIPPAsrEvidenceRow -TenantFilter 't' -Report (Report 'PC-2' '2026-10-30' @() 0))
            (ConvertTo-CIPPAsrEvidenceRow -TenantFilter 't' -Report (Report 'PC-3' '2026-09-01' @(Det 'D1E49AAC-8F56-4280-B9BA-993A6D77406C' 'Audited')))
        )
        $M = Measure-CIPPAsrEvidence -Rows $Rows -WindowDays 14 -Now $script:Now
        $M.Available | Should -BeTrue
        $M.CoverageDays | Should -Be 14
        $M.DevicesReporting | Should -Be 2
        $M.DevicesWithoutRules | Should -Be 1
        $M.ByRule['D1E49AAC-8F56-4280-B9BA-993A6D77406C'].Audited | Should -Be 1
        $M.ByRule['D1E49AAC-8F56-4280-B9BA-993A6D77406C'].Devices | Should -Be 1
    }
    It 'reports no evidence when nothing is inside the window' {
        $M = Measure-CIPPAsrEvidence -Rows @((ConvertTo-CIPPAsrEvidenceRow -TenantFilter 't' -Report (Report 'PC-1' '2026-09-01'))) -WindowDays 14 -Now $script:Now
        $M.Available | Should -BeFalse
        $M.DevicesReporting | Should -Be 0
    }
}

Describe 'Resolve-CIPPDefenderHardeningState' {
    BeforeAll {
        function Pol { param($Name, $Assigned, $Np, $Dc) [pscustomobject]@{ Name = $Name; Assigned = $Assigned; AssignmentLabel = 'All Devices'; Parsed = [pscustomobject]@{ AsrRules = @(); NetworkProtection = $Np; DeviceControl = $Dc } } }
        function NpState { param([object[]]$P) (Resolve-CIPPDefenderHardeningState -Policies $P | Where-Object Control -EQ 'NetworkProtection') }
    }
    It 'passes Block, warns on Audit, fails when unset or conflicting' {
        (NpState @(Pol 'AV' $true 'Block' $null)).Status | Should -Be 'Pass'
        (NpState @(Pol 'AV' $true 'Audit' $null)).Status | Should -Be 'Warn'
        (NpState @()).State | Should -Be 'NotConfigured'
        (NpState @((Pol 'A' $true 'Block' $null), (Pol 'B' $true 'Audit' $null))).State | Should -Be 'Conflict'
    }
    It 'ignores Network Protection in an unassigned policy' {
        (NpState @(Pol 'AV' $false 'Block' $null)).State | Should -Be 'NotConfigured'
    }
    It 'classifies Device Control' {
        $Dc = { param($P) (Resolve-CIPPDefenderHardeningState -Policies $P | Where-Object Control -EQ 'DeviceControl').State }
        & $Dc @(Pol 'DC' $true $null ([pscustomobject]@{ Enabled = $true; DefaultEnforcement = 'Deny'; EntryTypes = @('Allow') })) | Should -Be 'Enforced'
        & $Dc @(Pol 'DC' $true $null ([pscustomobject]@{ Enabled = $true; DefaultEnforcement = 'Allow'; EntryTypes = @('AuditAllowed') })) | Should -Be 'Audit'
        & $Dc @(Pol 'DC' $true $null ([pscustomobject]@{ Enabled = $true; DefaultEnforcement = 'Allow'; EntryTypes = @() })) | Should -Be 'EnabledNoRules'
        & $Dc @(Pol 'DC' $true $null ([pscustomobject]@{ Enabled = $false; DefaultEnforcement = $null; EntryTypes = @() })) | Should -Be 'Disabled'
        & $Dc @() | Should -Be 'NotConfigured'
    }
}

Describe 'Select-CIPPPendingRemediationAlerts' {
    BeforeAll {
        $script:Now = [datetime]::new(2026, 10, 31, 12, 0, 0, [DateTimeKind]::Utc)
        function Alert { param($Id, $State, $Created, $Status = 'new', $Evidence) $A = [pscustomobject]@{ id = $Id; investigationState = $State; createdDateTime = $Created; status = $Status; title = "Email messages containing malicious URL removed after delivery$([char]0x200B)"; serviceSource = 'microsoftDefenderForOffice365'; incidentId = '602' }; if ($null -ne $Evidence) { $A | Add-Member -NotePropertyName evidence -NotePropertyValue $Evidence }; $A }
    }
    It 'keeps only unresolved pendingApproval alerts and measures age from creation' {
        $R = @(Select-CIPPPendingRemediationAlerts -Now $script:Now -Alerts @(
                (Alert 'a1' 'pendingApproval' '2026-10-29T14:01:21Z')
                (Alert 'a2' 'successfullyRemediated' '2026-10-01T00:00:00Z')
                (Alert 'a3' 'pendingApproval' '2026-10-31T06:00:00Z')
                (Alert 'a4' 'pendingApproval' '2026-08-26T23:43:08Z' 'resolved')
            ))
        $R.AlertId | Should -Be @('a1', 'a3')
        $R[0].OverThreshold | Should -BeTrue
        $R[1].OverThreshold | Should -BeFalse
        $R[1].AgeHours | Should -Be 6
        $R[0].Title | Should -Be 'Email messages containing malicious URL removed after delivery'
        $R[0].PendingActions | Should -BeNullOrEmpty
    }
    It 'counts evidence awaiting approval when evidence is present' {
        $E = @([pscustomobject]@{ remediationStatus = 'pendingApproval' }, [pscustomobject]@{ remediationStatus = 'pendingApproval' }, [pscustomobject]@{ remediationStatus = 'none' })
        (Select-CIPPPendingRemediationAlerts -Now $script:Now -Alerts @(Alert 'a1' 'pendingApproval' '2026-10-30T00:00:00Z' 'new' $E)).PendingActions | Should -Be 2
    }
}
