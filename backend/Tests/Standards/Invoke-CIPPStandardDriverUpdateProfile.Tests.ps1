# Aspendora fork (Vikunja CIPP-24): the DriverUpdateProfile standard. Report and alert must never write; remediation
# creates a missing profile, corrects an automatic profile's deferral, and never touches the approval type or an
# Autopatch-managed tenant.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPStandards/Public/Standards/Invoke-CIPPStandardDriverUpdateProfile.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/IntuneOps/Test-CIPPDriverUpdateProfileState.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Tools/ConvertTo-CIPPBoolean.ps1')

    function Test-CIPPStandardLicense { param($StandardName, $TenantFilter, $Preset) $true }
    function New-GraphGetRequest { [CmdletBinding()] param($uri, $tenantid, $AsApp) }
    function New-GraphPostRequest { [CmdletBinding()] param($tenantid, $uri, $type, $body, $ContentType, $AsApp) }
    function Get-CIPPDriverBlockingPolicies { param($TenantFilter) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData) }
    function Write-StandardsAlert { param($message, $object, $tenant, $standardName, $standardId) }
    function Set-CIPPStandardsCompareField { param($FieldName, $CurrentValue, $ExpectedValue, $TenantFilter) }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }

    $script:Tenant = 'contoso.onmicrosoft.com'
    $script:Managed = { param($Deferral = 7, $Type = 'automatic') [pscustomobject]@{ id = 'm1'; displayName = 'CIPP - Windows Driver Updates'; description = ''; approvalType = $Type; deploymentDeferralInDays = $Deferral } }
    $script:Autopatch = [pscustomobject]@{ id = 'ap1'; displayName = 'Windows Autopatch Driver Update Policy - G - Last'; description = 'Driver update policy, created by Windows Autopatch'; approvalType = 'automatic'; deploymentDeferralInDays = 11 }
}

Describe 'Invoke-CIPPStandardDriverUpdateProfile' {
    BeforeEach {
        $script:Profiles = @()
        Mock New-GraphGetRequest { $script:Profiles }
        Mock New-GraphPostRequest { [pscustomobject]@{ id = 'new1' } }
        Mock Get-CIPPDriverBlockingPolicies { [pscustomobject]@{ Findings = @(); Errors = @() } }
        Mock Write-LogMessage {}
        Mock Write-StandardsAlert {}
        Mock Set-CIPPStandardsCompareField {}
    }

    It 'reports drift without writing anything when only report and alert are on' {
        Invoke-CIPPStandardDriverUpdateProfile -Tenant $script:Tenant -Settings @{ report = $true; alert = $true }
        Should -Invoke New-GraphPostRequest -Times 0
        Should -Invoke Write-StandardsAlert -Times 1
        Should -Invoke Set-CIPPStandardsCompareField -Times 1 -ParameterFilter { $CurrentValue.ProfilePresent -eq $false -and $ExpectedValue.ProfilePresent -eq $true }
    }

    It 'creates the profile with the default automatic / 7 days on remediate' {
        Mock New-GraphPostRequest { $script:Posted = @{ Uri = $uri; Type = $type; Body = ($body | ConvertFrom-Json) }; $script:Profiles = @(& $script:Managed); [pscustomobject]@{ id = 'm1' } }
        Invoke-CIPPStandardDriverUpdateProfile -Tenant $script:Tenant -Settings @{ remediate = $true; report = $true }
        $script:Posted.Type | Should -Be 'POST'
        $script:Posted.Body.approvalType | Should -Be 'automatic'
        $script:Posted.Body.deploymentDeferralInDays | Should -Be 7
        $script:Posted.Body.displayName | Should -Be 'CIPP - Windows Driver Updates'
        Should -Invoke Set-CIPPStandardsCompareField -Times 1 -ParameterFilter { $CurrentValue.ProfilePresent -eq $true }
    }

    It 'creates a manual profile without a deferral' {
        Mock New-GraphPostRequest { $script:Posted = ($body | ConvertFrom-Json); [pscustomobject]@{ id = 'm1' } }
        Invoke-CIPPStandardDriverUpdateProfile -Tenant $script:Tenant -Settings @{ remediate = $true; ApprovalType = @{ label = 'Manual'; value = 'manual' } }
        $script:Posted.approvalType | Should -Be 'manual'
        $script:Posted.PSObject.Properties.Name | Should -Not -Contain 'deploymentDeferralInDays'
    }

    It 'patches only the deferral of an existing automatic profile' {
        $script:Profiles = @(& $script:Managed 2)
        Mock New-GraphPostRequest { $script:Posted = @{ Uri = $uri; Type = $type; Body = ($body | ConvertFrom-Json) }; $script:Profiles = @(& $script:Managed 7) }
        Invoke-CIPPStandardDriverUpdateProfile -Tenant $script:Tenant -Settings @{ remediate = $true }
        $script:Posted.Type | Should -Be 'PATCH'
        $script:Posted.Uri | Should -Match 'windowsDriverUpdateProfiles/m1$'
        @($script:Posted.Body.PSObject.Properties.Name) | Should -Be @('deploymentDeferralInDays')
    }

    It 'never writes when the approval type differs' {
        $script:Profiles = @(& $script:Managed 7 'manual')
        Invoke-CIPPStandardDriverUpdateProfile -Tenant $script:Tenant -Settings @{ remediate = $true }
        Should -Invoke New-GraphPostRequest -Times 0
        Should -Invoke Write-LogMessage -ParameterFilter { $message -match 'cannot change the approval type' }
    }

    It 'treats an Autopatch-managed tenant as compliant and creates nothing' {
        $script:Profiles = @($script:Autopatch)
        Invoke-CIPPStandardDriverUpdateProfile -Tenant $script:Tenant -Settings @{ remediate = $true; alert = $true; report = $true }
        Should -Invoke New-GraphPostRequest -Times 0
        Should -Invoke Write-StandardsAlert -Times 0
    }

    It 'creates alongside Autopatch when AcceptAutopatch is off' {
        $script:Profiles = @($script:Autopatch)
        Invoke-CIPPStandardDriverUpdateProfile -Tenant $script:Tenant -Settings @{ remediate = $true; AcceptAutopatch = 'false' }
        Should -Invoke New-GraphPostRequest -Times 1 -ParameterFilter { $type -eq 'POST' }
    }

    It 'alerts when an assigned policy blocks drivers even if the profile is fine' {
        $script:Profiles = @(& $script:Managed)
        Mock Get-CIPPDriverBlockingPolicies { [pscustomobject]@{ Findings = @([pscustomobject]@{ PolicyName = 'Ring A'; Assigned = $true }); Errors = @() } }
        Invoke-CIPPStandardDriverUpdateProfile -Tenant $script:Tenant -Settings @{ alert = $true }
        Should -Invoke Write-StandardsAlert -Times 1 -ParameterFilter { $message -match 'Ring A' }
    }

    It 'stops quietly when driver profiles cannot be read (licence / onboarding)' {
        Mock New-GraphGetRequest { throw 'Forbidden' }
        Invoke-CIPPStandardDriverUpdateProfile -Tenant $script:Tenant -Settings @{ remediate = $true; report = $true }
        Should -Invoke New-GraphPostRequest -Times 0
        Should -Invoke Set-CIPPStandardsCompareField -Times 0
    }
}
