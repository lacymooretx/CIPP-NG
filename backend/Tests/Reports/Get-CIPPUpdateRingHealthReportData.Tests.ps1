# Windows Update Ring Health Report.
#
# The rules that earn this report are the CROSS-POLICY ones: a deferral or driver exclusion on a ring
# silently neutralises a Feature Update or Driver Update profile that looks healthy on its own page.
# Neither view alone shows it, so both are asserted here.
#
# The Autopatch exclusion is equally load-bearing. Microsoft sets values on its own rings that trip
# these rules by design - the Autopatch "Last" ring legitimately defers quality updates 11 days -
# and findings we cannot act on would make this report noise on every Autopatch tenant.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Join-Path $RepoRoot 'Modules/CIPPCore/Public/Reports/Get-CIPPUpdateRingHealthReportData.ps1'

    function New-GraphGetRequest {
        param($uri, $tenantid)
        switch -Regex ($uri) {
            '/organization$' { return @([pscustomobject]@{ displayName = 'Contoso'; verifiedDomains = @([pscustomobject]@{ name = 'contoso.com'; isDefault = $true }) }) }
            'windowsFeatureUpdateProfiles' { return $script:FeatureProfiles }
            'windowsDriverUpdateProfiles' { return $script:DriverProfiles }
            'deviceConfigurations' { return $script:Rings }
        }
        return @()
    }

    . $FunctionPath

    function New-Ring {
        param(
            $Name = 'Ring 1', $QualityPaused = $false, $FeaturePaused = $false,
            $QualityDeferral = 0, $FeatureDeferral = 0, $DriversExcluded = $false,
            $QualityDeadline = 3, $FeatureDeadline = 5, $Grace = 2,
            $DO = 'userDefined', $Assignments = $null
        )
        if ($null -eq $Assignments) {
            $Assignments = @([pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget' } })
        }
        [pscustomobject]@{
            displayName = $Name
            qualityUpdatesPaused = $QualityPaused; featureUpdatesPaused = $FeaturePaused
            qualityUpdatesDeferralPeriodInDays = $QualityDeferral
            featureUpdatesDeferralPeriodInDays = $FeatureDeferral
            driversExcluded = $DriversExcluded
            deadlineForQualityUpdatesInDays = $QualityDeadline
            deadlineForFeatureUpdatesInDays = $FeatureDeadline
            deadlineGracePeriodInDays = $Grace
            deliveryOptimizationMode = $DO
            assignments = $Assignments
        }
    }
    function Get-Section { param($Model, $Title) $Model.Sections | Where-Object { $_.Title -eq $Title } }
    function Get-Rules { param($Model) @((Get-Section $Model 'Findings').Rows | ForEach-Object { $_[2] }) }
}

Describe 'Get-CIPPUpdateRingHealthReportData' {
    BeforeEach {
        $script:Rings = @(New-Ring)
        $script:FeatureProfiles = @()
        $script:DriverProfiles = @()
    }

    It 'returns the model shape the renderer expects' {
        $m = Get-CIPPUpdateRingHealthReportData -TenantFilter 'contoso.com'

        $m.Title | Should -Be 'Windows Update Ring Health Report'
        $m.TenantName | Should -Be 'Contoso'
        $m.TenantDomain | Should -Be 'contoso.com'
        $m.Keys | Should -Contain 'GeneratedDate'
    }

    It 'a clean ring produces no findings' {
        $m = Get-CIPPUpdateRingHealthReportData -TenantFilter 'contoso.com'

        Get-Rules $m | Should -BeNullOrEmpty
        (Get-Section $m 'Findings').Status | Should -Be 'pass'
    }

    It 'flags paused quality updates as Critical and fails the section' {
        $script:Rings = @(New-Ring -QualityPaused $true)

        $m = Get-CIPPUpdateRingHealthReportData -TenantFilter 'contoso.com'

        (Get-Section $m 'Findings').Rows[0][0] | Should -Be 'Critical'
        Get-Rules $m | Should -Contain 'Quality updates paused'
        (Get-Section $m 'Findings').Status | Should -Be 'fail'
    }

    Context 'cross-policy rules - the reason this report exists' {
        It 'flags a feature deferral ONLY when a Feature Update profile exists' {
            $script:Rings = @(New-Ring -FeatureDeferral 5)

            $Without = Get-CIPPUpdateRingHealthReportData -TenantFilter 'contoso.com'
            Get-Rules $Without | Should -Not -Contain 'Feature deferral blocks a Feature Update profile'

            $script:FeatureProfiles = @([pscustomobject]@{ id = 'f1'; displayName = 'Win11 23H2' })
            $With = Get-CIPPUpdateRingHealthReportData -TenantFilter 'contoso.com'
            Get-Rules $With | Should -Contain 'Feature deferral blocks a Feature Update profile'
        }

        It 'flags excluded drivers ONLY when a Driver Update profile exists' {
            $script:Rings = @(New-Ring -DriversExcluded $true)

            $Without = Get-CIPPUpdateRingHealthReportData -TenantFilter 'contoso.com'
            Get-Rules $Without | Should -Not -Contain 'Drivers excluded while Driver Update profiles exist'

            $script:DriverProfiles = @([pscustomobject]@{ id = 'd1'; displayName = 'Drivers' })
            $With = Get-CIPPUpdateRingHealthReportData -TenantFilter 'contoso.com'
            Get-Rules $With | Should -Contain 'Drivers excluded while Driver Update profiles exist'
        }
    }

    It 'flags a missing quality update deadline' {
        $script:Rings = @(New-Ring -QualityDeadline $null)
        Get-Rules (Get-CIPPUpdateRingHealthReportData -TenantFilter 'contoso.com') | Should -Contain 'No quality update deadline'
    }

    It 'does not flag a missing deadline when quality updates are paused' {
        # Already reported as Critical; a second finding for the same ring is noise.
        $script:Rings = @(New-Ring -QualityDeadline $null -QualityPaused $true)
        Get-Rules (Get-CIPPUpdateRingHealthReportData -TenantFilter 'contoso.com') | Should -Not -Contain 'No quality update deadline'
    }

    It 'flags a quality deferral above the maximum' {
        $script:Rings = @(New-Ring -QualityDeferral 14)
        Get-Rules (Get-CIPPUpdateRingHealthReportData -TenantFilter 'contoso.com') | Should -Contain 'Quality deferral exceeds recommended maximum'
    }

    It 'flags a ring with no assignments' {
        $script:Rings = @(New-Ring -Assignments @())
        Get-Rules (Get-CIPPUpdateRingHealthReportData -TenantFilter 'contoso.com') | Should -Contain 'Ring has no assignments'
    }

    It 'flags All Devices with no exclusions, but not when an exclusion exists' {
        $All = @([pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } })
        $script:Rings = @(New-Ring -Assignments $All)
        Get-Rules (Get-CIPPUpdateRingHealthReportData -TenantFilter 'contoso.com') | Should -Contain 'Targets All Devices with no exclusions'

        $script:Rings = @(New-Ring -Assignments ($All + [pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget' } }))
        Get-Rules (Get-CIPPUpdateRingHealthReportData -TenantFilter 'contoso.com') | Should -Not -Contain 'Targets All Devices with no exclusions'
    }

    It 'flags a zero grace period but not an absent one' {
        $script:Rings = @(New-Ring -Grace 0)
        Get-Rules (Get-CIPPUpdateRingHealthReportData -TenantFilter 'contoso.com') | Should -Contain 'Zero grace period'

        $script:Rings = @(New-Ring -Grace $null)
        Get-Rules (Get-CIPPUpdateRingHealthReportData -TenantFilter 'contoso.com') | Should -Not -Contain 'Zero grace period'
    }

    It 'flags HTTP-only Delivery Optimization as Low' {
        $script:Rings = @(New-Ring -DO 'httpOnly')
        $m = Get-CIPPUpdateRingHealthReportData -TenantFilter 'contoso.com'
        Get-Rules $m | Should -Contain 'Delivery Optimization is HTTP-only'
        ((Get-Section $m 'Findings').Rows | Where-Object { $_[2] -eq 'Delivery Optimization is HTTP-only' })[0] | Should -Be 'Low'
    }

    Context 'Autopatch-managed rings' {
        It 'lists them but raises no findings against them' {
            # Every one of these would otherwise fire. Microsoft owns them; we cannot act.
            $script:FeatureProfiles = @([pscustomobject]@{ id = 'f1' })
            $script:DriverProfiles = @([pscustomobject]@{ id = 'd1' })
            $script:Rings = @(New-Ring -Name 'Windows Autopatch Update Policy - Default - Last' `
                    -QualityDeferral 11 -FeatureDeferral 7 -DriversExcluded $true -QualityDeadline $null -Grace 0 -Assignments @())

            $m = Get-CIPPUpdateRingHealthReportData -TenantFilter 'contoso.com'

            Get-Rules $m | Should -BeNullOrEmpty
            (Get-Section $m 'Update Rings').Rows[0][1] | Should -Be 'Autopatch-managed'
            (Get-Section $m 'Update Rings').Description | Should -Match '1 managed by Windows Autopatch'
        }

        It 'still flags a manual ring alongside a managed one' {
            $script:Rings = @(
                (New-Ring -Name 'Windows Autopatch Update Policy - Default - Test' -QualityPaused $true)
                (New-Ring -Name 'Manual Ring' -QualityPaused $true)
            )

            $m = Get-CIPPUpdateRingHealthReportData -TenantFilter 'contoso.com'
            $Rows = @((Get-Section $m 'Findings').Rows)

            $Rows | Should -HaveCount 1
            $Rows[0][1] | Should -Be 'Manual Ring'
        }
    }

    It 'reports no WUfB rings as an observation, NOT as "patching is unmanaged"' {
        # This report sees Intune through Graph and cannot see a third-party patch manager. Most of
        # this estate is patched by Action1, where having no WUfB rings is the intended
        # architecture - an earlier wording called that "unmanaged" and reported healthy tenants as
        # a patching failure.
        $script:Rings = @()

        $m = Get-CIPPUpdateRingHealthReportData -TenantFilter 'contoso.com'
        $Finding = $m.Findings | Where-Object { $_.Title -match 'No Windows Update for Business rings' }

        (Get-Section $m 'Update Rings').Status | Should -Be 'warn'
        $Finding.Status | Should -Be 'warn'
        $Finding.Detail | Should -Match 'Confirm patching is handled elsewhere'
        $Finding.Detail | Should -Not -Match 'unmanaged'
        (Get-Section $m 'Update Rings').Empty | Should -Match 'another tool'
    }
}
