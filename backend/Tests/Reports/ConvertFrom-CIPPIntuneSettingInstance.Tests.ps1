# Settings-catalog policies are the reason the Intune configuration document is worth
# having: everything else is a name and an assignment, but the settings are the actual
# configuration. Graph returns them as a recursive tree keyed on definition IDs, and we
# deliberately do NOT fetch Graph's settingDefinitions catalogue to resolve display names
# (a large per-tenant fetch plus a cache). Instead the IDs are converted directly.
#
# That trade-off is only defensible if the conversion is right, so these tests pin it:
# every settingInstance shape Intune emits, the prefix stripping on both the definition ID
# and its value, and the recursion guard.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Reports/ConvertFrom-CIPPIntuneSettingInstance.ps1')

    function New-Choice([string]$Def, [string]$Value, $Children = @()) {
        [pscustomobject]@{
            '@odata.type'      = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
            settingDefinitionId = $Def
            choiceSettingValue  = [pscustomobject]@{ value = $Value; children = $Children }
        }
    }
}

Describe 'ConvertFrom-CIPPIntuneSettingInstance' {

    It 'converts a choice setting into a readable label and value' {
        $Instance = New-Choice 'device_vendor_msft_policy_config_defender_allowrealtimemonitoring' 'device_vendor_msft_policy_config_defender_allowrealtimemonitoring_1'
        $Result = @(ConvertFrom-CIPPIntuneSettingInstance -Instance $Instance)

        $Result.Count | Should -Be 1
        $Result[0].Setting | Should -Be 'Defender Allowrealtimemonitoring'
        # The value repeats the whole definition ID; only the option should survive.
        $Result[0].Value | Should -Be '1'
    }

    It 'title-cases a wordy option value but leaves numeric values alone' {
        $Def = 'device_vendor_msft_policy_config_defender_asr_blockwin32apicallsfromofficemacros'
        (@(ConvertFrom-CIPPIntuneSettingInstance -Instance (New-Choice $Def "${Def}_audit")))[0].Value | Should -Be 'Audit'
        (@(ConvertFrom-CIPPIntuneSettingInstance -Instance (New-Choice $Def "${Def}_2")))[0].Value | Should -Be '2'
    }

    It 'unwraps a settings-array element that wraps the instance' {
        $Wrapper = [pscustomobject]@{
            id              = '0'
            settingInstance = (New-Choice 'device_vendor_msft_policy_config_test_setting' 'device_vendor_msft_policy_config_test_setting_block')
        }
        $Result = @(ConvertFrom-CIPPIntuneSettingInstance -Instance $Wrapper)
        $Result.Count | Should -Be 1
        $Result[0].Value | Should -Be 'Block'
    }

    It 'flattens a group setting collection into one row per child - the real ASR shape' {
        # This is the exact shape 3E NDT's "ASR Default rules" policy returns: a single
        # group instance whose children are the individual rules. Reporting it as one
        # row would document an ASR policy as having "1 setting".
        $Instance = [pscustomobject]@{
            '@odata.type'                = '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'
            settingDefinitionId          = 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules'
            groupSettingCollectionValue  = @(
                [pscustomobject]@{
                    children = @(
                        (New-Choice 'device_vendor_msft_policy_config_defender_asr_blockobfuscatedscripts' 'device_vendor_msft_policy_config_defender_asr_blockobfuscatedscripts_audit'),
                        (New-Choice 'device_vendor_msft_policy_config_defender_asr_blockadobechildprocesses' 'device_vendor_msft_policy_config_defender_asr_blockadobechildprocesses_block')
                    )
                }
            )
        }
        $Result = @(ConvertFrom-CIPPIntuneSettingInstance -Instance $Instance)

        $Result.Count | Should -Be 2
        $Result[0].Setting | Should -Be 'Defender ASR Blockobfuscatedscripts'
        $Result[0].Value | Should -Be 'Audit'
        $Result[1].Value | Should -Be 'Block'
    }

    It 'includes children nested under a choice value' {
        $Child = New-Choice 'device_vendor_msft_policy_config_child_setting' 'device_vendor_msft_policy_config_child_setting_on'
        $Instance = New-Choice 'device_vendor_msft_policy_config_parent_setting' 'device_vendor_msft_policy_config_parent_setting_enabled' @($Child)
        $Result = @(ConvertFrom-CIPPIntuneSettingInstance -Instance $Instance)

        $Result.Count | Should -Be 2
        $Result[0].Value | Should -Be 'Enabled'
        $Result[1].Setting | Should -Be 'Child Setting'
    }

    It 'renders a simple setting and a simple collection' {
        $Simple = [pscustomobject]@{
            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
            settingDefinitionId = 'device_vendor_msft_policy_config_defender_scanmaxcpu'
            simpleSettingValue  = [pscustomobject]@{ value = 50 }
        }
        (@(ConvertFrom-CIPPIntuneSettingInstance -Instance $Simple))[0].Value | Should -Be '50'

        $Collection = [pscustomobject]@{
            '@odata.type'                  = '#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance'
            settingDefinitionId            = 'device_vendor_msft_policy_config_defender_excludedpaths'
            simpleSettingCollectionValue   = @(
                [pscustomobject]@{ value = 'C:\Temp' },
                [pscustomobject]@{ value = 'C:\Build' }
            )
        }
        (@(ConvertFrom-CIPPIntuneSettingInstance -Instance $Collection))[0].Value | Should -Be 'C:\Temp, C:\Build'
    }

    It 'records an unknown instance shape as configured rather than dropping it' {
        $Unknown = [pscustomobject]@{
            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSomethingNewInstance'
            settingDefinitionId = 'device_vendor_msft_policy_config_future_setting'
        }
        $Result = @(ConvertFrom-CIPPIntuneSettingInstance -Instance $Unknown)
        $Result.Count | Should -Be 1
        $Result[0].Value | Should -Be '(configured)'
    }

    It 'returns nothing for null input or an instance with no definition id' {
        @(ConvertFrom-CIPPIntuneSettingInstance -Instance $null).Count | Should -Be 0
        @(ConvertFrom-CIPPIntuneSettingInstance -Instance ([pscustomobject]@{ '@odata.type' = 'x' })).Count | Should -Be 0
    }

    It 'stops on a self-referencing tree instead of recursing forever' {
        # Build a group nested well past the depth guard.
        $Leaf = New-Choice 'device_vendor_msft_policy_config_deep_leaf' 'device_vendor_msft_policy_config_deep_leaf_on'
        $Node = $Leaf
        foreach ($i in 1..15) {
            $Node = [pscustomobject]@{
                '@odata.type'               = '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'
                settingDefinitionId         = "device_vendor_msft_policy_config_level$i"
                groupSettingCollectionValue = @([pscustomobject]@{ children = @($Node) })
            }
        }
        # The guard trims the tree; the call must return rather than blow the stack.
        { ConvertFrom-CIPPIntuneSettingInstance -Instance $Node } | Should -Not -Throw
        @(ConvertFrom-CIPPIntuneSettingInstance -Instance $Node).Count | Should -Be 0
    }
}
