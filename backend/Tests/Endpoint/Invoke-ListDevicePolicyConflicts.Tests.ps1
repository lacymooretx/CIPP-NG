# Device policy conflict surfacing (enhancement A2).
#
# Grouping key matters: settingStates carries BOTH 'setting' (the CSP path, which is what actually
# collides) and 'settingName' (a type label like "Windows10CustomConfiguration", shared by every
# custom setting in a profile). Grouping on settingName would report every custom OMA-URI in a
# profile as conflicting with every other. Verified against live data on 2026-09-17.
#
# deviceConfigurationConflictSummary is deliberately NOT load-bearing: tested against four tenants,
# it returned HTTP 500 on two and empty on the other two, producing usable data on none. It is
# queried best-effort and a failure there must never fail the request.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Join-Path $RepoRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/Endpoint/MEM/Invoke-ListDevicePolicyConflicts.ps1'

    ([PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')).GetMethod('Add').Invoke(
        $null, @('HttpStatusCode', [System.Net.HttpStatusCode]))
    class HttpResponseContext { [int]$StatusCode; [object]$Body }

    function New-GraphGetRequest {
        param($uri, $tenantid)
        if ($uri -match 'conflictSummary') { if ($script:SummaryThrows) { throw 'boom' } ; return $script:TenantSummary }
        if ($uri -match '/settingStates$') {
            $PolicyId = ([regex]::Match($uri, '/(?:deviceConfigurationStates|deviceCompliancePolicyStates)/([^/]+)/settingStates')).Groups[1].Value
            return $script:SettingStates[$PolicyId]
        }
        if ($uri -match 'deviceConfigurationStates$') { return $script:ConfigStates }
        if ($uri -match 'deviceCompliancePolicyStates$') { return $script:ComplianceStates }
        return @()
    }
    function Write-LogMessage { param($headers, $API, $tenant, $message, $Sev, $LogData) $script:Logs += $message }
    function Get-CippException { param($Exception) @{ NormalizedError = $Exception.Exception.Message } }

    . $FunctionPath

    function New-State { param($Id, $Name) [pscustomobject]@{ id = $Id; displayName = $Name } }
    function New-Setting {
        param($Setting, $State = 'compliant', $Sources = 1, $CurrentValue = $null, $ErrorDescription = '0')
        [pscustomobject]@{
            setting = $Setting; settingName = 'Windows10CustomConfiguration'
            instanceDisplayName = $Setting; state = $State
            errorCode = 0; errorDescription = $ErrorDescription; currentValue = $CurrentValue
            sources = @(1..$Sources | ForEach-Object { [pscustomobject]@{ id = "src$_"; sourceType = 'deviceConfiguration' } })
        }
    }
    function Invoke-Conflicts {
        Invoke-ListDevicePolicyConflicts -Request ([pscustomobject]@{
                Params = @{ CIPPEndpoint = 'ListDevicePolicyConflicts' }; Headers = @{}
                Query = [pscustomobject]@{ TenantFilter = 'contoso.com'; DeviceId = 'dev-1' }
                Body = [pscustomobject]@{}
            })
    }
}

Describe 'Invoke-ListDevicePolicyConflicts' {
    BeforeEach {
        $script:Logs = @()
        $script:ConfigStates = @()
        $script:ComplianceStates = @()
        $script:SettingStates = @{}
        $script:TenantSummary = @()
        $script:SummaryThrows = $false
    }

    It 'requires a tenant and a device' {
        $r = Invoke-ListDevicePolicyConflicts -Request ([pscustomobject]@{ Params = @{}; Headers = @{}; Query = [pscustomobject]@{ TenantFilter = 'contoso.com' }; Body = [pscustomobject]@{} })
        $r.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
    }

    It 'reports nothing when every setting is cleanly applied by one policy' {
        $script:ConfigStates = @(New-State 'p1' 'Edge Policy')
        $script:SettingStates = @{ p1 = @(New-Setting './Device/Vendor/MSFT/Policy/Config/A') }

        $r = Invoke-Conflicts

        $r.Body.Results | Should -BeNullOrEmpty
        $r.Body.Metadata.SettingsInspected | Should -Be 1
    }

    It 'reports a setting Intune itself flagged as conflict, at the highest severity' {
        $script:ConfigStates = @(New-State 'p1' 'Edge Policy')
        $script:SettingStates = @{ p1 = @(New-Setting './Device/Config/A' -State 'conflict') }

        $r = Invoke-Conflicts

        $r.Body.Results[0].Severity | Should -Be 'Conflict'
        $r.Body.Results[0].Reasons | Should -Match 'Intune reported a conflict'
        $r.Body.Metadata.ConflictCount | Should -Be 1
    }

    It 'reports a setting claimed by two different policies even when both report success' {
        # Each policy looks healthy alone; only the cross-policy view shows the contention.
        $script:ConfigStates = @((New-State 'p1' 'Policy One'), (New-State 'p2' 'Policy Two'))
        $script:SettingStates = @{
            p1 = @(New-Setting './Device/Config/Shared')
            p2 = @(New-Setting './Device/Config/Shared')
        }

        $r = Invoke-Conflicts

        $r.Body.Results | Should -HaveCount 1
        $r.Body.Results[0].Severity | Should -Be 'Contested'
        $r.Body.Results[0].PolicyCount | Should -Be 2
        $r.Body.Results[0].Policies | Should -Match 'Policy One'
        $r.Body.Results[0].Policies | Should -Match 'Policy Two'
    }

    It "reports Intune's own multi-source record even within a single policy" {
        $script:ConfigStates = @(New-State 'p1' 'Policy One')
        $script:SettingStates = @{ p1 = @(New-Setting './Device/Config/A' -Sources 2) }

        $r = Invoke-Conflicts

        $r.Body.Results[0].Reasons | Should -Match 'Multiple policies claim this setting'
    }

    It 'groups on the CSP path, not the coarse settingName type label' {
        # Both settings share settingName 'Windows10CustomConfiguration'. Grouping on that would
        # report every custom OMA-URI in a profile as conflicting with every other.
        $script:ConfigStates = @(New-State 'p1' 'Policy One')
        $script:SettingStates = @{ p1 = @((New-Setting './Device/Config/A'), (New-Setting './Device/Config/B')) }

        (Invoke-Conflicts).Body.Results | Should -BeNullOrEmpty
    }

    It 'covers compliance policies as well as configuration profiles' {
        $script:ConfigStates = @(New-State 'p1' 'Config Policy')
        $script:ComplianceStates = @(New-State 'c1' 'Compliance Policy')
        $script:SettingStates = @{
            p1 = @(New-Setting './Device/Config/Shared')
            c1 = @(New-Setting './Device/Config/Shared')
        }

        $r = Invoke-Conflicts

        $r.Body.Results[0].Policies | Should -Match 'Compliance'
        $r.Body.Results[0].Policies | Should -Match 'Configuration'
    }

    It 'reports a failed setting as an Error finding' {
        $script:ConfigStates = @(New-State 'p1' 'Policy One')
        $script:SettingStates = @{ p1 = @(New-Setting './Device/Config/A' -State 'error' -ErrorDescription 'Access denied') }

        $r = Invoke-Conflicts

        $r.Body.Results[0].Severity | Should -Be 'Error'
        $r.Body.Results[0].ErrorDetail | Should -Be 'Access denied'
    }

    It 'sorts conflicts above contested above errors' {
        $script:ConfigStates = @((New-State 'p1' 'One'), (New-State 'p2' 'Two'))
        $script:SettingStates = @{
            p1 = @((New-Setting './E' -State 'error'), (New-Setting './C' -State 'conflict'), (New-Setting './X'))
            p2 = @(New-Setting './X')
        }

        $Sev = @((Invoke-Conflicts).Body.Results.Severity)

        $Sev[0] | Should -Be 'Conflict'
        $Sev[1] | Should -Be 'Contested'
        $Sev[2] | Should -Be 'Error'
    }

    Context 'the flaky tenant-wide summary' {
        It 'does not fail the request when the summary endpoint errors' {
            # It returned HTTP 500 on two of four real tenants.
            $script:SummaryThrows = $true
            $script:ConfigStates = @(New-State 'p1' 'Policy One')
            $script:SettingStates = @{ p1 = @(New-Setting './Device/Config/A' -State 'conflict') }

            $r = Invoke-Conflicts

            $r.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
            $r.Body.Results | Should -HaveCount 1
            $r.Body.Metadata.TenantSummaryError | Should -Match 'unavailable for this tenant'
        }
    }

    It 'keeps going when one policy has unreadable setting states' {
        $script:ConfigStates = @((New-State 'p1' 'Good'), (New-State 'bad' 'Bad'))
        $script:SettingStates = @{ p1 = @(New-Setting './Device/Config/A' -State 'conflict') }
        Mock New-GraphGetRequest {
            if ($uri -match '/bad/settingStates') { throw 'unreadable' }
            if ($uri -match 'conflictSummary') { return @() }
            if ($uri -match '/settingStates$') { return $script:SettingStates['p1'] }
            if ($uri -match 'deviceConfigurationStates$') { return $script:ConfigStates }
            return @()
        }

        $r = Invoke-Conflicts

        $r.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $r.Body.Results | Should -Not -BeNullOrEmpty
    }
}
