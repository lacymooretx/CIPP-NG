# Pester tests for Invoke-CIPPStandardMDMEnrollmentDuringRegistration (Vikunja CIPP-21)
#   - report / alert runs never PATCH the MDM policy;
#   - remediation PATCHes isMdmEnrollmentDuringRegistrationDisabled and only claims success after reading it back;
#   - a policy that is already correct is a no-op;
#   - an unlicensed tenant reads nothing; a string 'false' in the settings does not count as true.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $StandardPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Invoke-CIPPStandardMDMEnrollmentDuringRegistration.ps1' -File |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $StandardPath) { throw 'Could not locate Invoke-CIPPStandardMDMEnrollmentDuringRegistration.ps1' }

    function Test-CIPPStandardLicense { [CmdletBinding()] param($StandardName, $TenantFilter, $Preset, [switch]$SkipLog) }
    function New-GraphGetRequest { [CmdletBinding()] param($uri, $tenantid, $AsApp) }
    function New-GraphPostRequest { [CmdletBinding()] param($tenantid, $Uri, $AsApp, $type, $Body, $ContentType) }
    function Write-LogMessage { [CmdletBinding()] param($API, $tenant, $message, $sev, $LogData) }
    function Write-StandardsAlert { [CmdletBinding()] param($message, $object, $tenant, $standardName, $standardId) }
    function Set-CIPPStandardsCompareField { [CmdletBinding()] param($FieldName, $CurrentValue, $ExpectedValue, $TenantFilter) }
    function Get-CippException { [CmdletBinding()] param($Exception) @{ NormalizedError = "$Exception" } }
    . $StandardPath

    $script:Tenant = 'contoso.onmicrosoft.com'
    $script:Uri = 'https://graph.microsoft.com/beta/policies/mobileDeviceManagementPolicies/0000000a-0000-0000-c000-000000000000'

    # $Disabled: stored isMdmEnrollmentDuringRegistrationDisabled ($null = property absent).
    # $AfterWrite: what the policy reads as once a PATCH has happened.
    function script:Set-Tenant {
        param($Disabled, $AfterWrite = $true, $Licensed = $true)
        $script:State = @{ Disabled = $Disabled; AfterWrite = $AfterWrite; Written = $false; Licensed = $Licensed }
    }
}

Describe 'Invoke-CIPPStandardMDMEnrollmentDuringRegistration' {
    BeforeEach {
        $script:logs = [System.Collections.Generic.List[object]]::new()
        $script:alerts = [System.Collections.Generic.List[object]]::new()
        $script:compare = [System.Collections.Generic.List[object]]::new()
        $script:writes = [System.Collections.Generic.List[object]]::new()
        $script:reads = 0

        Mock Test-CIPPStandardLicense { $script:State.Licensed }
        Mock New-GraphGetRequest {
            if ($uri -ne $script:Uri) { throw "unexpected GET $uri" }
            $script:reads++
            $Value = if ($script:State.Written) { $script:State.AfterWrite } else { $script:State.Disabled }
            $Policy = [pscustomobject]@{ id = '0000000a-0000-0000-c000-000000000000'; appliesTo = 'all' }
            if ($null -ne $Value) { $Policy | Add-Member -NotePropertyName isMdmEnrollmentDuringRegistrationDisabled -NotePropertyValue $Value }
            $Policy
        }
        Mock New-GraphPostRequest { $script:writes.Add([pscustomobject]@{ Uri = $Uri; Type = $type; Body = $Body }); $script:State.Written = $true }
        Mock Write-LogMessage { $script:logs.Add([pscustomobject]@{ Message = $message; Sev = $sev }) }
        Mock Write-StandardsAlert { $script:alerts.Add([pscustomobject]@{ Message = $message; Object = $object }) }
        Mock Set-CIPPStandardsCompareField { $script:compare.Add([pscustomobject]@{ Field = $FieldName; Current = $CurrentValue; Expected = $ExpectedValue }) }
    }

    It 'reports drift and writes nothing in report and alert mode' {
        Set-Tenant -Disabled $false
        Invoke-CIPPStandardMDMEnrollmentDuringRegistration -Tenant $script:Tenant -Settings ([pscustomobject]@{ report = $true; alert = $true; disableEnrollment = $true })
        $script:writes.Count | Should -Be 0
        $script:compare[0].Field | Should -Be 'standards.MDMEnrollmentDuringRegistration'
        $script:compare[0].Current.isMdmEnrollmentDuringRegistrationDisabled | Should -BeFalse
        $script:compare[0].Expected.isMdmEnrollmentDuringRegistrationDisabled | Should -BeTrue
        $script:alerts.Count | Should -Be 1
    }

    It 'treats a policy without the property as enrollment enabled (the Microsoft default)' {
        Set-Tenant -Disabled $null
        Invoke-CIPPStandardMDMEnrollmentDuringRegistration -Tenant $script:Tenant -Settings ([pscustomobject]@{ report = $true; disableEnrollment = $true })
        $script:writes.Count | Should -Be 0
        $script:compare[0].Current.isMdmEnrollmentDuringRegistrationDisabled | Should -BeFalse
    }

    It 'PATCHes the MDM policy and reports success only after reading it back' {
        Set-Tenant -Disabled $false
        Invoke-CIPPStandardMDMEnrollmentDuringRegistration -Tenant $script:Tenant -Settings ([pscustomobject]@{ remediate = $true; alert = $true; report = $true; disableEnrollment = $true })
        $script:writes.Count | Should -Be 1
        $script:writes[0].Type | Should -Be 'PATCH'
        $script:writes[0].Uri | Should -Be $script:Uri
        ($script:writes[0].Body | ConvertFrom-Json).isMdmEnrollmentDuringRegistrationDisabled | Should -BeTrue
        $script:reads | Should -Be 2
        $script:alerts.Count | Should -Be 0
        $script:compare[0].Current.isMdmEnrollmentDuringRegistrationDisabled | Should -BeTrue
        @($script:logs | Where-Object { $_.Message -like '*read back*' }).Count | Should -Be 1
    }

    It 'logs an error and keeps reporting drift when Graph accepts the PATCH but the value does not change' {
        Set-Tenant -Disabled $false -AfterWrite $false
        Invoke-CIPPStandardMDMEnrollmentDuringRegistration -Tenant $script:Tenant -Settings ([pscustomobject]@{ remediate = $true; alert = $true; report = $true; disableEnrollment = $true })
        $script:writes.Count | Should -Be 1
        @($script:logs | Where-Object { $_.Sev -eq 'Error' -and $_.Message -like '*still reads*' }).Count | Should -Be 1
        $script:alerts.Count | Should -Be 1
        $script:compare[0].Current.isMdmEnrollmentDuringRegistrationDisabled | Should -BeFalse
    }

    It 'does nothing when the policy is already correct' {
        Set-Tenant -Disabled $true
        Invoke-CIPPStandardMDMEnrollmentDuringRegistration -Tenant $script:Tenant -Settings ([pscustomobject]@{ remediate = $true; alert = $true; report = $true; disableEnrollment = $true })
        $script:writes.Count | Should -Be 0
        $script:alerts.Count | Should -Be 0
        $script:reads | Should -Be 1
        $script:compare[0].Current.isMdmEnrollmentDuringRegistrationDisabled | Should -BeTrue
    }

    It "does not read a string 'false' switch value as true" {
        Set-Tenant -Disabled $false
        Invoke-CIPPStandardMDMEnrollmentDuringRegistration -Tenant $script:Tenant -Settings ([pscustomobject]@{ remediate = $true; report = $true; disableEnrollment = 'false' })
        $script:writes.Count | Should -Be 0
        $script:compare[0].Expected.isMdmEnrollmentDuringRegistrationDisabled | Should -BeFalse
    }

    It 'skips an unlicensed tenant without reading Graph' {
        Set-Tenant -Disabled $false -Licensed $false
        Invoke-CIPPStandardMDMEnrollmentDuringRegistration -Tenant $script:Tenant -Settings ([pscustomobject]@{ remediate = $true; report = $true; disableEnrollment = $true })
        $script:reads | Should -Be 0
        $script:writes.Count | Should -Be 0
    }

    It 'stops without writing when the policy cannot be read' {
        Set-Tenant -Disabled $false
        Mock New-GraphGetRequest { throw 'Forbidden' }
        Invoke-CIPPStandardMDMEnrollmentDuringRegistration -Tenant $script:Tenant -Settings ([pscustomobject]@{ remediate = $true; report = $true; disableEnrollment = $true })
        $script:writes.Count | Should -Be 0
        $script:compare.Count | Should -Be 0
        @($script:logs | Where-Object { $_.Sev -eq 'Error' }).Count | Should -Be 1
    }
}
