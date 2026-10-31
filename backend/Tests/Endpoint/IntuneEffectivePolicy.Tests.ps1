# Aspendora fork (Vikunja CIPP-19): Intune effective policy + assignment hygiene rules.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Dir = Join-Path $RepoRoot 'Modules/CIPPCore/Public/IntuneEffective'
    . (Join-Path $Dir 'Test-CIPPIntuneAssignmentFilterRule.ps1')
    . (Join-Path $Dir 'Get-CIPPIntunePolicyPlatform.ps1')
    . (Join-Path $Dir 'Resolve-CIPPIntuneAssignments.ps1')
    . (Join-Path $Dir 'Find-CIPPIntuneSettingOverlap.ps1')
    . (Join-Path $Dir 'Test-CIPPIntunePolicyHygiene.ps1')

    function T {
        param($Type, $GroupId, $FilterId, $FilterType = 'none', $Intent)
        $A = [pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = "#microsoft.graph.$Type"; groupId = $GroupId; deviceAndAppManagementAssignmentFilterId = $FilterId; deviceAndAppManagementAssignmentFilterType = $FilterType } }
        if ($Intent) { $A | Add-Member -NotePropertyName intent -NotePropertyValue $Intent }
        $A
    }
    function P {
        param($Id, [object[]]$Assignments, $Platforms = @('windows'), $Family = 'ConfigurationPolicies', $Type = 'Settings Catalog')
        [pscustomobject]@{ Id = $Id; Name = "Policy $Id"; Type = $Type; Family = $Family; Platforms = $Platforms; Assignments = $Assignments }
    }
    $script:Device = @{ deviceName = 'LACY-3E'; manufacturer = 'Dell Inc.'; model = 'Latitude 9520'; osVersion = '10.0.26100.4500'; deviceOwnership = 'Corporate' }
    function Invoke-Resolve {
        param([object[]]$Policies, $DeviceGroups = @('dg'), $UserGroups = @('ug'), $HasUser = $true, $Platform = 'windows', $Filters = @{})
        Resolve-CIPPIntuneAssignments -Policies $Policies -DevicePlatform $Platform -DeviceProperties $script:Device -DeviceGroupIds $DeviceGroups `
            -UserGroupIds $UserGroups -HasUser $HasUser -UserName 'lacy@contoso.com' -GroupNames @{ dg = 'Device Group'; ug = 'User Group'; xg = 'Excl Group' } -Filters $Filters
    }
}

Describe 'Resolve-CIPPIntuneAssignments' {
    It 'includes through a device group and a user group, and names the path' {
        $Rows = (Invoke-Resolve @((P 'a' @(T 'groupAssignmentTarget' 'dg')), (P 'b' @(T 'groupAssignmentTarget' 'ug')))).Rows
        $Rows.Count | Should -Be 2
        ($Rows | Where-Object PolicyId -EQ 'a').TargetedVia | Should -Be "Group 'Device Group' (device member)"
        ($Rows | Where-Object PolicyId -EQ 'b').TargetedVia | Should -Be "Group 'User Group' (user lacy@contoso.com member)"
        @($Rows.Status | Sort-Object -Unique) | Should -Be @('Applies')
    }

    It 'ignores groups the device and user are not in' {
        (Invoke-Resolve @(P 'a' @(T 'groupAssignmentTarget' 'other'))).Rows | Should -BeNullOrEmpty
    }

    It 'lets an exclusion win over an include' {
        $Row = (Invoke-Resolve @(P 'a' @((T 'allDevicesAssignmentTarget'), (T 'exclusionGroupAssignmentTarget' 'dg')))).Rows[0]
        $Row.Status | Should -Be 'Excluded'
        $Row.Applies | Should -BeFalse
        $Row.ExcludedBy | Should -Match 'Device Group'
        $Row.Notes | Should -BeNullOrEmpty
    }

    It 'notes a user-group exclusion of a device-targeted include' {
        $Row = (Invoke-Resolve @(P 'a' @((T 'allDevicesAssignmentTarget'), (T 'exclusionGroupAssignmentTarget' 'ug')))).Rows[0]
        $Row.Status | Should -Be 'Excluded'
        $Row.Notes | Should -Match 'mixing user and device groups'
    }

    It 'skips an exclusion with nothing to cancel' {
        (Invoke-Resolve @(P 'a' @(T 'exclusionGroupAssignmentTarget' 'dg'))).Rows | Should -BeNullOrEmpty
    }

    It 'applies All Devices always and All Users only with a primary user' {
        (Invoke-Resolve @(P 'a' @(T 'allDevicesAssignmentTarget')) -HasUser $false).Rows[0].TargetedVia | Should -Be 'All Devices'
        (Invoke-Resolve @(P 'b' @(T 'allLicensedUsersAssignmentTarget')) -HasUser $false).Rows | Should -BeNullOrEmpty
        (Invoke-Resolve @(P 'b' @(T 'allLicensedUsersAssignmentTarget'))).Rows[0].TargetedVia | Should -Be 'All Users (via user lacy@contoso.com)'
    }

    It 'does not match user groups when there is no primary user' {
        (Invoke-Resolve @(P 'a' @(T 'groupAssignmentTarget' 'ug')) -HasUser $false).Rows | Should -BeNullOrEmpty
    }

    It 'skips policies for another platform but never on an unknown platform' {
        $Out = Invoke-Resolve @((P 'mac' @(T 'allDevicesAssignmentTarget') -Platforms @('macOS')), (P 'unk' @(T 'allDevicesAssignmentTarget') -Platforms @()))
        $Out.PlatformSkipped | Should -Be 1
        $Out.Rows.PolicyId | Should -Be 'unk'
        # Unknown device platform: skip nothing.
        (Invoke-Resolve @(P 'mac' @(T 'allDevicesAssignmentTarget') -Platforms @('macOS')) -Platform $null).Rows.Count | Should -Be 1
    }

    It 'evaluates include and exclude filters it can compute' {
        $Filters = @{ f1 = @{ displayName = 'Dells'; rule = '(device.manufacturer -eq "Dell Inc.")' }; f2 = @{ displayName = 'Cloud PCs'; rule = '(device.model -startsWith "Cloud PC")' } }
        $Rows = (Invoke-Resolve @(
                (P 'inc-match' @(T 'allDevicesAssignmentTarget' -FilterId 'f1' -FilterType 'include')),
                (P 'inc-miss' @(T 'allDevicesAssignmentTarget' -FilterId 'f2' -FilterType 'include')),
                (P 'exc-match' @(T 'allDevicesAssignmentTarget' -FilterId 'f1' -FilterType 'exclude')),
                (P 'exc-miss' @(T 'allDevicesAssignmentTarget' -FilterId 'f2' -FilterType 'exclude'))
            ) -Filters $Filters).Rows
        ($Rows | Where-Object PolicyId -EQ 'inc-match').Status | Should -Be 'Applies'
        ($Rows | Where-Object PolicyId -EQ 'inc-miss').Status | Should -Be 'Filtered out'
        ($Rows | Where-Object PolicyId -EQ 'exc-match').Status | Should -Be 'Filtered out'
        ($Rows | Where-Object PolicyId -EQ 'exc-miss').Status | Should -Be 'Applies'
        ($Rows | Where-Object PolicyId -EQ 'inc-match').Filter | Should -Be 'Dells'
        ($Rows | Where-Object PolicyId -EQ 'inc-match').FilterResult | Should -Be 'Device matches rule'
    }

    It 'never claims a result for a filter it cannot evaluate' {
        $Filters = @{ f3 = @{ displayName = 'SKU'; rule = '(device.operatingSystemSKU -eq "Enterprise")' }; f4 = @{ displayName = 'Regex'; rule = '(device.deviceName -match "^LACY")' } }
        $Rows = (Invoke-Resolve @((P 'a' @(T 'allDevicesAssignmentTarget' -FilterId 'f3' -FilterType 'include')), (P 'b' @(T 'allDevicesAssignmentTarget' -FilterId 'f4' -FilterType 'exclude')), (P 'c' @(T 'allDevicesAssignmentTarget' -FilterId 'gone' -FilterType 'include'))) -Filters $Filters).Rows
        @($Rows.Status | Sort-Object -Unique) | Should -Be @('Applies unless filter excludes (not evaluated)')
        ($Rows | Where-Object PolicyId -EQ 'c').FilterResult | Should -Be 'Not evaluated (filter not found)'
    }

    It 'prefers a definite include over an unevaluated one' {
        $Filters = @{ f3 = @{ displayName = 'SKU'; rule = '(device.operatingSystemSKU -eq "Enterprise")' } }
        $Row = (Invoke-Resolve @(P 'a' @((T 'allDevicesAssignmentTarget' -FilterId 'f3' -FilterType 'include'), (T 'groupAssignmentTarget' 'dg'))) -Filters $Filters).Rows[0]
        $Row.Status | Should -Be 'Applies'
    }

    It 'only cancels app includes of the same intent' {
        $App = P 'app' @((T 'allDevicesAssignmentTarget' -Intent 'required'), (T 'groupAssignmentTarget' 'ug' -Intent 'available'), (T 'exclusionGroupAssignmentTarget' 'dg' -Intent 'required')) -Family 'MobileApps' -Type 'App'
        $Rows = (Invoke-Resolve @($App)).Rows
        ($Rows | Where-Object Intent -EQ 'required').Status | Should -Be 'Excluded'
        ($Rows | Where-Object Intent -EQ 'available').Status | Should -Be 'Applies'
    }

    It 'sorts applying rows first' {
        $Rows = (Invoke-Resolve @((P 'z' @((T 'allDevicesAssignmentTarget'), (T 'exclusionGroupAssignmentTarget' 'dg'))), (P 'y' @(T 'allDevicesAssignmentTarget')))).Rows
        $Rows[0].Status | Should -Be 'Applies'
        $Rows[1].Status | Should -Be 'Excluded'
    }
}

Describe 'Test-CIPPIntuneAssignmentFilterRule' {
    It 'evaluates <Rule> as <Expected>' -ForEach @(
        @{ Rule = '(device.model -startsWith "Cloud PC")'; Expected = $false }
        @{ Rule = '(device.model -eq "latitude 9520")'; Expected = $true }
        @{ Rule = '(device.deviceName -in ["LACY-3E", "OTHER"])'; Expected = $true }
        @{ Rule = '(device.deviceName -notIn ["LACY-3E"])'; Expected = $false }
        @{ Rule = '(device.manufacturer -contains "dell") and (device.deviceOwnership -eq "Corporate")'; Expected = $true }
        @{ Rule = '(device.manufacturer -ne "Dell Inc.") or (device.model -endsWith "9520")'; Expected = $true }
        @{ Rule = '((device.operatingSystemVersion -ge 10.0.26100.4484) and (device.operatingSystemVersion -le 10.0.27000))'; Expected = $true }
        @{ Rule = '(device.operatingSystemVersion -lt 10.0.22621.0)'; Expected = $false }
        @{ Rule = 'not (device.model -eq "Latitude 9520")'; Expected = $false }
    ) {
        Test-CIPPIntuneAssignmentFilterRule -Rule $Rule -Device $script:Device | Should -Be $Expected
    }

    It 'returns null for <Why>' -ForEach @(
        @{ Why = 'an unknown property'; Rule = '(device.operatingSystemSKU -eq "Enterprise")' }
        @{ Why = 'a regex operator'; Rule = '(device.deviceName -match "^LACY")' }
        @{ Why = 'an empty device property'; Rule = '(device.enrollmentProfileName -eq "Autopilot")' }
        @{ Why = 'a non-device property'; Rule = '(app.version -eq "1")' }
        @{ Why = 'an unparseable rule'; Rule = '(device.model -eq "unterminated' }
        @{ Why = 'an unbalanced rule'; Rule = '(device.model -eq "x"' }
        @{ Why = 'version compare on a string property'; Rule = '(device.model -gt "A")' }
    ) {
        Test-CIPPIntuneAssignmentFilterRule -Rule $Rule -Device $script:Device | Should -BeNullOrEmpty
    }

    It 'uses three-valued logic so an unknown clause only matters when it can' {
        Test-CIPPIntuneAssignmentFilterRule -Rule '(device.model -eq "Latitude 9520") or (device.operatingSystemSKU -eq "X")' -Device $script:Device | Should -BeTrue
        Test-CIPPIntuneAssignmentFilterRule -Rule '(device.model -eq "Nope") and (device.operatingSystemSKU -eq "X")' -Device $script:Device | Should -BeFalse
        Test-CIPPIntuneAssignmentFilterRule -Rule '(device.model -eq "Latitude 9520") and (device.operatingSystemSKU -eq "X")' -Device $script:Device | Should -BeNullOrEmpty
    }
}

Describe 'Get-CIPPIntunePolicyPlatform' {
    It 'maps a <Family> policy to <Out>' -ForEach @(
        @{ Policy = [pscustomobject]@{ platforms = 'windows10' }; Family = 'ConfigurationPolicies'; Out = @('windows') }
        @{ Policy = [pscustomobject]@{ platforms = 'macOS' }; Family = 'ConfigurationPolicies'; Out = @('macOS') }
        @{ Policy = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.iosCompliancePolicy' }; Family = 'deviceCompliancePolicies'; Out = @('iOS') }
        @{ Policy = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.androidWorkProfileGeneralDeviceConfiguration' }; Family = 'DeviceConfigurations'; Out = @('android') }
        @{ Policy = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.windows81TrustedRootCertificate' }; Family = 'DeviceConfigurations'; Out = @('windows') }
        @{ Policy = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.win32LobApp' }; Family = 'MobileApps'; Out = @('windows') }
        @{ Policy = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.managedIOSStoreApp' }; Family = 'MobileApps'; Out = @('iOS') }
        @{ Policy = [pscustomobject]@{ id = 'x' }; Family = 'GroupPolicyConfigurations'; Out = @('windows') }
    ) {
        @(Get-CIPPIntunePolicyPlatform -Policy $Policy -Family $Family) | Should -Be $Out
    }

    It 'returns nothing for web links and unknown types' {
        @(Get-CIPPIntunePolicyPlatform -Policy ([pscustomobject]@{ '@odata.type' = '#microsoft.graph.webApp' }) -Family 'MobileApps').Count | Should -Be 0
        @(Get-CIPPIntunePolicyPlatform -Policy ([pscustomobject]@{ '@odata.type' = '#microsoft.graph.somethingNew' }) -Family 'DeviceConfigurations').Count | Should -Be 0
    }

    It 'normalises device operating systems' {
        Get-CIPPIntunePolicyPlatform -OperatingSystem 'Windows' | Should -Be 'windows'
        Get-CIPPIntunePolicyPlatform -OperatingSystem 'iPadOS' | Should -Be 'iOS'
        Get-CIPPIntunePolicyPlatform -OperatingSystem 'AndroidEnterprise' | Should -Be 'android'
        Get-CIPPIntunePolicyPlatform -OperatingSystem 'Plan9' | Should -BeNullOrEmpty
    }
}

Describe 'Find-CIPPIntuneSettingOverlap' {
    BeforeAll {
        function S { param($Def, $Value) [pscustomobject]@{ id = '0'; settingInstance = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'; settingDefinitionId = $Def; settingInstanceTemplateReference = $null; choiceSettingValue = [pscustomobject]@{ value = "${Def}_$Value"; settingValueTemplateReference = [pscustomobject]@{ x = (New-Guid).Guid }; children = @() } } } }
    }
    It 'flags differing values as a conflict and equal values as an overlap' {
        $Out = Find-CIPPIntuneSettingOverlap -PolicySettings @(
            [pscustomobject]@{ PolicyId = 'a'; PolicyName = 'A'; Settings = @((S 'tz' 'central'), (S 'tamper' '1'), (S 'onlyA' '1')) }
            [pscustomobject]@{ PolicyId = 'b'; PolicyName = 'B'; Settings = @((S 'tz' 'eastern'), (S 'tamper' '1')) }
        )
        $Out.Count | Should -Be 2
        $Out[0].SettingDefinitionId | Should -Be 'tz'
        $Out[0].Severity | Should -Be 'Conflict'
        $Out[0].Values | Should -Be 'A = central | B = eastern'
        $Out[1].Severity | Should -Be 'Overlap'
    }
    It 'returns nothing for a single policy' {
        @(Find-CIPPIntuneSettingOverlap -PolicySettings @([pscustomobject]@{ PolicyId = 'a'; PolicyName = 'A'; Settings = @(S 'tz' 'central') })).Count | Should -Be 0
    }
}

Describe 'Test-CIPPIntunePolicyHygiene' {
    BeforeAll {
        $script:Groups = @{
            live  = @{ Exists = $true; DisplayName = 'Live'; MemberCount = 1; Dynamic = $false }
            empty = @{ Exists = $true; DisplayName = 'Empty'; MemberCount = 0; Dynamic = $true }
            gone  = @{ Exists = $false; DisplayName = $null; MemberCount = $null; Dynamic = $false }
            unk   = @{ Exists = $null; DisplayName = $null; MemberCount = $null; Dynamic = $false }
            unkm  = @{ Exists = $true; DisplayName = 'Members unreadable'; MemberCount = $null; Dynamic = $false }
        }
    }
    It 'is clean for a policy assigned to a live group' {
        (Test-CIPPIntunePolicyHygiene -Policies @(P 'a' @(T 'groupAssignmentTarget' 'live')) -Groups $script:Groups).Findings | Should -BeNullOrEmpty
    }
    It 'flags unassigned policies but not apps or unreadable intents' {
        $Intent = P 'i' @() -Family 'Intents'
        $Intent | Add-Member -NotePropertyName AssignmentsUnknown -NotePropertyValue $true
        $R = Test-CIPPIntunePolicyHygiene -Policies @((P 'a' @()), (P 'app' @() -Family 'MobileApps'), $Intent) -Groups $script:Groups
        $R.Findings.Key | Should -Be @('Unassigned|a')
        $R.Summary.ByCategory.Unassigned | Should -Be 1
        $R.Summary.PoliciesChecked | Should -Be 3
    }
    It 'flags exclusion-only policies' {
        $F = (Test-CIPPIntunePolicyHygiene -Policies @(P 'a' @(T 'exclusionGroupAssignmentTarget' 'live')) -Groups $script:Groups).Findings
        $F.Category | Should -Be @('ExclusionOnly')
        $F.Severity | Should -Be 'Warning'
    }
    It 'flags missing groups (error for include, warning for exclusion) and empty groups' {
        $R = Test-CIPPIntunePolicyHygiene -Policies @(P 'a' @((T 'groupAssignmentTarget' 'gone'), (T 'groupAssignmentTarget' 'empty'), (T 'exclusionGroupAssignmentTarget' 'gone'), (T 'exclusionGroupAssignmentTarget' 'empty'))) -Groups $script:Groups
        $Keys = @($R.Findings | ForEach-Object { "$($_.Category)/$($_.Severity)" })
        $Keys | Should -Be @('MissingGroup/Error', 'EmptyGroup/Warning', 'MissingGroup/Warning', 'EmptyGroup/Info')
        ($R.Findings | Where-Object { $_.Category -eq 'EmptyGroup' -and $_.Severity -eq 'Warning' }).Message | Should -Match 'dynamic group'
        $R.Summary.Errors | Should -Be 1
    }
    It 'never reports a group it could not read as missing or empty' {
        (Test-CIPPIntunePolicyHygiene -Policies @(P 'a' @((T 'groupAssignmentTarget' 'unk'), (T 'groupAssignmentTarget' 'unkm'), (T 'groupAssignmentTarget' 'notlooked'))) -Groups $script:Groups).Findings | Should -BeNullOrEmpty
    }
    It 'counts findings by policy type' {
        $R = Test-CIPPIntunePolicyHygiene -Policies @((P 'a' @()), (P 'b' @() -Type 'Compliance Policy' -Family 'deviceCompliancePolicies'), (P 'c' @())) -Groups @{}
        $R.Summary.ByPolicyType.'Settings Catalog' | Should -Be 2
        $R.Summary.ByPolicyType.'Compliance Policy' | Should -Be 1
    }
}
