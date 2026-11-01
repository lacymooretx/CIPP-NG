# Aspendora fork (Vikunja CIPP-28): cloud-only Intune lint.
# Pins rule matching for every policy shape (Settings Catalog with nested children, custom OMA-URI including
# encrypted values, Administrative Templates as a CIPP template payload and as live definition values),
# value-sensitive rules (enabled vs disabled, LAPS AD vs Entra backup), relevance from tenant context, that the
# shipped rules file is well formed and sourced, and that unknown shapes never throw.

BeforeAll {
    $ErrorActionPreference = 'Stop'
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Reports/ConvertFrom-CIPPIntuneSettingInstance.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/IntuneEffective/Test-CIPPIntuneCloudOnlyLint.ps1')
    $script:RulesFile = Join-Path $RepoRoot 'Config/IntuneCloudOnlyLintRules.json'
    $script:Rules = @((Get-Content -Path $script:RulesFile -Raw | ConvertFrom-Json).rules)

    $script:LastLogon = 'device_vendor_msft_policy_config_admx_winlogon_displaylastlogoninfodescription'

    function New-Choice([string]$Def, [string]$Option, $Children = @()) {
        [pscustomobject]@{
            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
            settingDefinitionId = $Def
            choiceSettingValue  = [pscustomobject]@{ value = "${Def}_$Option"; children = @($Children) }
        }
    }
    function New-Simple([string]$Def, $Value) {
        [pscustomobject]@{
            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
            settingDefinitionId = $Def
            simpleSettingValue  = [pscustomobject]@{ value = $Value }
        }
    }
    # A Settings Catalog policy body as /configurationPolicies/{id}/settings returns it: settings[].settingInstance.
    function New-Catalog([object[]]$Instances) {
        $i = 0
        [pscustomobject]@{ settings = @($Instances | ForEach-Object { [pscustomobject]@{ id = [string]($i++); settingInstance = $_ } }) }
    }
    function Invoke-Lint {
        param($Body, $Context, [string]$Name = 'Policy A', $Assigned = $true)
        $Policy = [pscustomobject]@{ Id = 'p1'; Name = $Name; Type = 'Settings Catalog'; Assigned = $Assigned; Body = $Body }
        if ($PSBoundParameters.ContainsKey('Context')) {
            @(Test-CIPPIntuneCloudOnlyLint -Policies @($Policy) -Rules $script:Rules -Context $Context)
        } else {
            @(Test-CIPPIntuneCloudOnlyLint -Policies @($Policy) -Rules $script:Rules)
        }
    }
    $script:CloudOnly = @{ CloudOnlyDevices = 12; HybridDevices = 0; DirectorySynced = $false }
}

Describe 'IntuneCloudOnlyLintRules.json' {
    It 'is valid JSON with unique rule ids, a severity and a Microsoft Learn source on every rule' {
        $script:Rules.Count | Should -BeGreaterThan 0
        @($script:Rules.id | Sort-Object -Unique).Count | Should -Be $script:Rules.Count
        foreach ($Rule in $script:Rules) {
            $Rule.severity | Should -BeIn @('High', 'Medium', 'Low', 'Info')
            $Rule.appliesWhen | Should -BeIn @('CloudOnlyDevices', 'NoOnPremisesDirectory')
            @($Rule.sources).Count | Should -BeGreaterThan 0
            foreach ($S in @($Rule.sources)) { $S | Should -BeLike 'https://learn.microsoft.com/*' }
            $Rule.symptom | Should -Not -BeNullOrEmpty
            $Rule.alternative | Should -Not -BeNullOrEmpty
        }
    }

    It 'seeds the last-logon rule with the real Settings Catalog id' {
        ($script:Rules | Where-Object id -EQ 'CLOUDONLY-001').match.settingDefinitionIds | Should -Contain $script:LastLogon
    }
}

Describe 'Test-CIPPIntuneCloudOnlyLint: Settings Catalog' {
    It 'flags Display last logon info when enabled' {
        $F = Invoke-Lint (New-Catalog @(New-Choice $script:LastLogon '1')) $script:CloudOnly
        $F.Count | Should -Be 1
        $F[0].RuleId | Should -Be 'CLOUDONLY-001'
        $F[0].Severity | Should -Be 'High'
        $F[0].MatchedVia | Should -Be 'Settings Catalog'
        $F[0].Relevance | Should -Be 'Applies'
        $F[0].Source | Should -BeLike 'https://learn.microsoft.com/*'
        $F[0].Alternative | Should -BeLike '*sign-in logs*'
    }

    It 'does not flag Display last logon info when disabled' {
        Invoke-Lint (New-Catalog @(New-Choice $script:LastLogon '0')) $script:CloudOnly | Should -BeNullOrEmpty
    }

    It 'finds a match nested under a choice value (LAPS AD backup and its AD-only children)' {
        $Laps = New-Choice 'device_vendor_msft_laps_policies_backupdirectory' '2' @(
            (New-Choice 'device_vendor_msft_laps_policies_adpasswordencryptionenabled' 'true'),
            (New-Simple 'device_vendor_msft_laps_policies_passwordagedays' 30)
        )
        $F = Invoke-Lint (New-Catalog @($Laps)) $script:CloudOnly
        @($F.RuleId) | Should -Be @('CLOUDONLY-002', 'CLOUDONLY-003')
        ($F | Where-Object RuleId -EQ 'CLOUDONLY-003').Settings | Should -BeLike '*Adpasswordencryptionenabled*'
    }

    It 'does not flag LAPS backed up to Entra ID (the real Aspendora LAPS shape)' {
        $Laps = New-Choice 'device_vendor_msft_laps_policies_backupdirectory' '1' @(New-Simple 'device_vendor_msft_laps_policies_passwordagedays_aad' 30)
        Invoke-Lint (New-Catalog @($Laps, (New-Simple 'device_vendor_msft_laps_policies_passwordlength' 24))) $script:CloudOnly | Should -BeNullOrEmpty
    }

    It 'finds a match inside a group setting collection (Windows Hello for Business {tenantid} shape)' {
        $Whfb = [pscustomobject]@{
            '@odata.type'               = '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'
            settingDefinitionId         = 'device_vendor_msft_passportforwork_{tenantid}'
            groupSettingCollectionValue = @([pscustomobject]@{ children = @(
                        (New-Choice 'device_vendor_msft_passportforwork_{tenantid}_policies_usepassportforwork' 'true'),
                        (New-Choice 'device_vendor_msft_passportforwork_{tenantid}_policies_usecloudtrustforonpremauth' 'true')
                    )
                })
        }
        $F = Invoke-Lint (New-Catalog @($Whfb)) $script:CloudOnly
        $F.Count | Should -Be 1
        $F[0].RuleId | Should -Be 'CLOUDONLY-006'
        $F[0].Relevance | Should -Be 'Applies'
    }

    It 'matches every Net Logon setting by prefix and reports one finding per policy per rule' {
        $Body = New-Catalog @(
            (New-Choice 'device_vendor_msft_policy_config_admx_netlogon_netlogon_trynextclosestsite' '1'),
            (New-Choice 'device_vendor_msft_policy_config_admx_netlogon_netlogon_sitename' '1')
        )
        $F = Invoke-Lint $Body $script:CloudOnly
        $F.Count | Should -Be 1
        $F[0].RuleId | Should -Be 'CLOUDONLY-005'
        @($F[0].Settings -split ' \| ').Count | Should -Be 2
    }

    It 'returns nothing for a policy with no known-problem settings' {
        $Body = New-Catalog @(
            (New-Choice 'device_vendor_msft_policy_config_defender_allowrealtimemonitoring' '1'),
            (New-Simple 'device_vendor_msft_policy_config_devicelock_maxinactivitytimedevicelock' 10)
        )
        Invoke-Lint $Body $script:CloudOnly | Should -BeNullOrEmpty
    }

    It 'sorts High findings before Info findings across policies' {
        $Policies = @(
            [pscustomobject]@{ Id = 'a'; Name = 'A Net Logon'; Type = 'Settings Catalog'; Assigned = $true; Body = (New-Catalog @(New-Choice 'device_vendor_msft_policy_config_admx_netlogon_netlogon_sitename' '1')) },
            [pscustomobject]@{ Id = 'b'; Name = 'B Last logon'; Type = 'Settings Catalog'; Assigned = $true; Body = (New-Catalog @(New-Choice $script:LastLogon '1')) }
        )
        $F = @(Test-CIPPIntuneCloudOnlyLint -Policies $Policies -Rules $script:Rules -Context $script:CloudOnly)
        @($F.Severity) | Should -Be @('High', 'Info')
    }
}

Describe 'Test-CIPPIntuneCloudOnlyLint: custom OMA-URI' {
    It 'flags an enabled ADMX-backed OMA-URI, case-insensitively' {
        $Body = [pscustomobject]@{ omaSettings = @(
                [pscustomobject]@{ omaUri = './device/vendor/msft/policy/config/admx_winlogon/displaylastlogoninfodescription'; value = '<enabled/>' }
            )
        }
        $F = Invoke-Lint $Body $script:CloudOnly
        $F.Count | Should -Be 1
        $F[0].RuleId | Should -Be 'CLOUDONLY-001'
        $F[0].MatchedVia | Should -Be 'OMA-URI'
        $F[0].ValueVerified | Should -BeTrue
    }

    It 'does not flag the same OMA-URI when disabled' {
        $Body = [pscustomobject]@{ omaSettings = @([pscustomobject]@{ omaUri = './Device/Vendor/MSFT/Policy/Config/ADMX_WinLogon/DisplayLastLogonInfoDescription'; value = '<disabled/>' }) }
        Invoke-Lint $Body $script:CloudOnly | Should -BeNullOrEmpty
    }

    It 'matches a {TenantId} path through the wildcard and an integer value' {
        $Body = [pscustomobject]@{ omaSettings = @(
                [pscustomobject]@{ omaUri = './Device/Vendor/MSFT/PassportForWork/7b0c1b8e-1111-2222-3333-444455556666/Policies/UseCertificateForOnPremAuth'; value = $true },
                [pscustomobject]@{ omaUri = './Device/Vendor/MSFT/LAPS/Policies/BackupDirectory'; value = 2 }
            )
        }
        @((Invoke-Lint $Body $script:CloudOnly).RuleId | Sort-Object) | Should -Be @('CLOUDONLY-002', 'CLOUDONLY-007')
    }

    It 'still flags an encrypted value on its URI, marked as not verified' {
        $Body = [pscustomobject]@{ omaSettings = @([pscustomobject]@{ omaUri = './Device/Vendor/MSFT/Policy/Config/ADMX_WinLogon/DisplayLastLogonInfoDescription'; value = 'PGEvPg=='; isEncrypted = $true }) }
        $F = Invoke-Lint $Body $script:CloudOnly
        $F.Count | Should -Be 1
        $F[0].ValueVerified | Should -BeFalse
        $F[0].Settings | Should -BeLike '*not checked*'
    }
}

Describe 'Test-CIPPIntuneCloudOnlyLint: Administrative Templates' {
    It 'flags an enabled setting in a CIPP Admin template payload by its definition bind' {
        $Body = [pscustomobject]@{ added = @([pscustomobject]@{
                    'definition@odata.bind' = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('c888f824-9937-46f5-a797-6a9e08a8b290')"
                    enabled                 = $true
                    presentationValues      = @()
                }); updated = @(); deletedIds = @()
        }
        $F = Invoke-Lint $Body $script:CloudOnly
        $F.Count | Should -Be 1
        $F[0].RuleId | Should -Be 'CLOUDONLY-001'
        $F[0].MatchedVia | Should -Be 'Administrative Template'
    }

    It 'does not flag it when the ADMX setting is disabled' {
        $Body = [pscustomobject]@{ added = @([pscustomobject]@{ enabled = $false; definition = [pscustomobject]@{ id = 'x'; displayName = 'Display information about previous logons during user logon' } }) }
        Invoke-Lint $Body $script:CloudOnly | Should -BeNullOrEmpty
    }

    It 'flags live definition values by display name and by category path' {
        $Body = [pscustomobject]@{ definitionValues = @(
                [pscustomobject]@{ enabled = $true; definition = [pscustomobject]@{ id = 'other-tenant-id'; displayName = 'Always wait for the network at computer startup and logon'; categoryPath = '\System\Logon' } },
                [pscustomobject]@{ enabled = $false; definition = [pscustomobject]@{ id = 'n1'; displayName = 'Try Next Closest Site'; categoryPath = '\System\Net Logon\DC Locator DNS Records' } }
            )
        }
        @((Invoke-Lint $Body $script:CloudOnly).RuleId | Sort-Object) | Should -Be @('CLOUDONLY-004', 'CLOUDONLY-005')
    }

    It 'does not overwrite the caller''s $Matches' {
        $null = 'keep-me' -match 'keep'
        $Body = [pscustomobject]@{ added = @([pscustomobject]@{ 'definition@odata.bind' = "x/groupPolicyDefinitions('c888f824-9937-46f5-a797-6a9e08a8b290')"; enabled = $true }) }
        $null = Invoke-Lint $Body $script:CloudOnly
        $Matches[0] | Should -Be 'keep'
    }
}

Describe 'Test-CIPPIntuneCloudOnlyLint: relevance' {
    BeforeAll {
        $script:LastLogonBody = New-Catalog @(New-Choice $script:LastLogon '1')
        $script:KerberosBody = New-Catalog @(New-Choice 'device_vendor_msft_policy_config_kerberos_cloudkerberosticketretrievalenabled' '1')
    }

    It 'marks a cloud-only rule Not applicable when every Windows device is hybrid joined' {
        (Invoke-Lint $script:LastLogonBody @{ CloudOnlyDevices = 0; HybridDevices = 40; DirectorySynced = $true })[0].Relevance | Should -Be 'Not applicable'
    }

    It 'marks an on-premises rule Check when the tenant syncs from AD' {
        (Invoke-Lint $script:KerberosBody @{ CloudOnlyDevices = 5; HybridDevices = 5; DirectorySynced = $true })[0].Relevance | Should -Be 'Check'
    }

    It 'reports Unknown without a context (template mode)' {
        (Invoke-Lint $script:LastLogonBody)[0].Relevance | Should -Be 'Unknown'
    }

    It 'reports Unknown when the device read failed' {
        (Invoke-Lint $script:LastLogonBody @{ CloudOnlyDevices = $null; DirectorySynced = $false })[0].Relevance | Should -Be 'Unknown'
    }
}

Describe 'Test-CIPPIntuneCloudOnlyLint: robustness' {
    It 'accepts a template RAWJson string, the way template mode passes it' {
        $Json = New-Catalog @(New-Choice $script:LastLogon '1') | ConvertTo-Json -Depth 20 -Compress
        (Invoke-Lint $Json)[0].RuleId | Should -Be 'CLOUDONLY-001'
    }

    It 'does not throw on shapes it does not understand' {
        $Odd = @(
            'not json {',
            42,
            [pscustomobject]@{ scheduledActionsForRule = @(); displayName = 'Compliance' },
            [pscustomobject]@{ settings = @($null, [pscustomobject]@{ settingInstance = $null }, [pscustomobject]@{ settingInstance = [pscustomobject]@{ settingDefinitionId = $script:LastLogon } }) },
            [pscustomobject]@{ omaSettings = @($null, [pscustomobject]@{ value = 'x' }) },
            [pscustomobject]@{ added = @($null, [pscustomobject]@{ enabled = $true }) },
            @{ settings = 'oops' }
        )
        foreach ($Body in $Odd) {
            { Invoke-Lint $Body $script:CloudOnly } | Should -Not -Throw
        }
        Test-CIPPIntuneCloudOnlyLint -Policies @($null) -Rules $script:Rules | Should -BeNullOrEmpty
        Test-CIPPIntuneCloudOnlyLint -Rules $script:Rules | Should -BeNullOrEmpty
    }

    It 'loads the rules from the Config folder when none are passed' {
        $Saved = $env:CIPPRootPath
        try {
            $env:CIPPRootPath = Split-Path -Parent (Split-Path -Parent $script:RulesFile)
            $Policy = [pscustomobject]@{ Id = 'p'; Name = 'P'; Type = 'Settings Catalog'; Body = (New-Catalog @(New-Choice $script:LastLogon '1')) }
            @(Test-CIPPIntuneCloudOnlyLint -Policies @($Policy))[0].RuleId | Should -Be 'CLOUDONLY-001'
        } finally { $env:CIPPRootPath = $Saved }
    }
}

Describe 'ConvertFrom-CIPPIntuneSettingInstance identifiers' {
    It 'returns the definition id and raw value alongside the readable label' {
        $Row = @(ConvertFrom-CIPPIntuneSettingInstance -Instance (New-Choice $script:LastLogon '1'))[0]
        $Row.DefinitionId | Should -Be $script:LastLogon
        $Row.RawValue | Should -Be "$($script:LastLogon)_1"
        $Row.Value | Should -Be '1'
    }
}
