# Pester tests for Invoke-CIPPStandardDisableKeepMeSignedIn (Vikunja CIPP-18)
#   - report / alert runs never write branding, even when the tenant has no default localization;
#   - a tenant with no default localization counts as "prompt shown";
#   - remediation PATCHes localization 0 when it exists, POSTs it when it does not, and only claims success
#     after reading isKeepMeSignedInDisabled back as true;
#   - only ENFORCED CA session policies change the alert wording; report-only ones are listed but not counted.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $StandardPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Invoke-CIPPStandardDisableKeepMeSignedIn.ps1' -File |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $StandardPath) { throw 'Could not locate Invoke-CIPPStandardDisableKeepMeSignedIn.ps1' }

    function Get-Tenants { [CmdletBinding()] param($TenantFilter) [pscustomobject]@{ customerId = '11111111-1111-1111-1111-111111111111' } }
    function New-GraphGetRequest { [CmdletBinding()] param($uri, $tenantid, $AsApp) }
    function New-GraphPostRequest { [CmdletBinding()] param($tenantid, $uri, $AsApp, $type, $body, $ContentType) }
    function Write-LogMessage { [CmdletBinding()] param($API, $tenant, $message, $sev, $LogData) }
    function Write-StandardsAlert { [CmdletBinding()] param($message, $object, $tenant, $standardName, $standardId) }
    function Set-CIPPStandardsCompareField { [CmdletBinding()] param($FieldName, $CurrentValue, $ExpectedValue, $Tenant) }
    function Get-CippException { [CmdletBinding()] param($Exception) @{ NormalizedError = "$Exception" } }
    . $StandardPath

    $script:Tenant = 'contoso.onmicrosoft.com'
    $script:Base = 'https://graph.microsoft.com/beta/organization/11111111-1111-1111-1111-111111111111/branding/localizations'

    # $Kmsi: $null = no default localization; otherwise the stored isKeepMeSignedInDisabled value.
    # $AfterWrite: what localization 0 reads as once a write has happened.
    function script:Set-Tenant {
        param($Kmsi, $Policies = @(), $AfterWrite = $true, [switch]$CaFails)
        $script:State = @{ Kmsi = $Kmsi; Written = $false; AfterWrite = $AfterWrite; Policies = $Policies; CaFails = [bool]$CaFails }
    }
    function script:New-Policy {
        param($Name, $State = 'enabled', $SifHours, [switch]$NeverPersist)
        $Sc = @{}
        if ($SifHours) { $Sc.signInFrequency = @{ isEnabled = $true; value = $SifHours; type = 'hours'; frequencyInterval = 'timeBased' } }
        if ($NeverPersist) { $Sc.persistentBrowser = @{ isEnabled = $true; mode = 'never' } }
        [pscustomobject]@{ displayName = $Name; state = $State; sessionControls = [pscustomobject]$Sc } | ConvertTo-Json -Depth 5 | ConvertFrom-Json
    }
}

Describe 'Invoke-CIPPStandardDisableKeepMeSignedIn' {
    BeforeEach {
        $script:logs = [System.Collections.Generic.List[object]]::new()
        $script:alerts = [System.Collections.Generic.List[object]]::new()
        $script:compare = [System.Collections.Generic.List[object]]::new()
        $script:writes = [System.Collections.Generic.List[object]]::new()

        Mock New-GraphGetRequest {
            if ($uri -eq $script:Base) {
                if ($null -eq $script:State.Kmsi -and -not $script:State.Written) { return @() }
                return @([pscustomobject]@{ id = '0' })
            }
            if ($uri -eq "$script:Base/0") {
                if ($script:State.Written) { return [pscustomobject]@{ id = '0'; isKeepMeSignedInDisabled = $script:State.AfterWrite } }
                return [pscustomobject]@{ id = '0'; isKeepMeSignedInDisabled = $script:State.Kmsi }
            }
            if ($uri -like '*conditionalAccess/policies') {
                if ($script:State.CaFails) { throw 'Forbidden' }
                return $script:State.Policies
            }
            throw "unexpected GET $uri"
        }
        Mock New-GraphPostRequest { $script:writes.Add([pscustomobject]@{ Uri = $uri; Type = $type; Body = $body }); $script:State.Written = $true }
        Mock Write-LogMessage { $script:logs.Add([pscustomobject]@{ Message = $message; Sev = $sev }) }
        Mock Write-StandardsAlert { $script:alerts.Add([pscustomobject]@{ Message = $message; Object = $object }) }
        Mock Set-CIPPStandardsCompareField { $script:compare.Add([pscustomobject]@{ Field = $FieldName; Current = $CurrentValue; Expected = $ExpectedValue }) }
    }

    It 'reports the prompt as shown and writes nothing in report mode' {
        Set-Tenant -Kmsi $false
        Invoke-CIPPStandardDisableKeepMeSignedIn -Tenant $script:Tenant -Settings ([pscustomobject]@{ report = $true })
        $script:writes.Count | Should -Be 0
        $script:compare[0].Field | Should -Be 'standards.DisableKeepMeSignedIn'
        $script:compare[0].Current.isKeepMeSignedInDisabled | Should -BeFalse
        $script:compare[0].Expected.isKeepMeSignedInDisabled | Should -BeTrue
    }

    It 'treats a tenant with no default branding localization as prompt shown and does not create one when alerting' {
        Set-Tenant -Kmsi $null
        Invoke-CIPPStandardDisableKeepMeSignedIn -Tenant $script:Tenant -Settings ([pscustomobject]@{ report = $true; alert = $true })
        $script:writes.Count | Should -Be 0
        $script:compare[0].Current.isKeepMeSignedInDisabled | Should -BeFalse
        $script:alerts.Count | Should -Be 1
        $script:alerts[0].Object.BrandingConfigured | Should -BeFalse
    }

    It 'says up to 90 days when no enforced session policy exists, counting report-only policies as not enforced' {
        Set-Tenant -Kmsi $false -Policies @(New-Policy -Name 'RO 12h' -State 'enabledForReportingButNotEnforced' -SifHours 12 -NeverPersist)
        Invoke-CIPPStandardDisableKeepMeSignedIn -Tenant $script:Tenant -Settings ([pscustomobject]@{ alert = $true })
        $script:alerts[0].Message | Should -BeLike '*no enforced Conditional Access policy*90 days*'
        @($script:alerts[0].Object.SessionPolicies).Count | Should -Be 1
    }

    It 'mentions enforced session policies when there are some' {
        Set-Tenant -Kmsi $false -Policies @(
            (New-Policy -Name 'Admins 4h' -SifHours 4 -NeverPersist),
            (New-Policy -Name 'No session controls')
        )
        Invoke-CIPPStandardDisableKeepMeSignedIn -Tenant $script:Tenant -Settings ([pscustomobject]@{ alert = $true })
        $script:alerts[0].Message | Should -BeLike '*limited by 1 enforced*'
        @($script:alerts[0].Object.SessionPolicies).Name | Should -Be @('Admins 4h')
    }

    It 'does not alert or write when the prompt is already hidden' {
        Set-Tenant -Kmsi $true
        Invoke-CIPPStandardDisableKeepMeSignedIn -Tenant $script:Tenant -Settings ([pscustomobject]@{ remediate = $true; alert = $true; report = $true })
        $script:writes.Count | Should -Be 0
        $script:alerts.Count | Should -Be 0
        $script:compare[0].Current.isKeepMeSignedInDisabled | Should -BeTrue
    }

    It 'PATCHes localization 0 when it exists and reports success only after reading it back' {
        Set-Tenant -Kmsi $false
        Invoke-CIPPStandardDisableKeepMeSignedIn -Tenant $script:Tenant -Settings ([pscustomobject]@{ remediate = $true; alert = $true; report = $true })
        $script:writes.Count | Should -Be 1
        $script:writes[0].Type | Should -Be 'PATCH'
        $script:writes[0].Uri | Should -Be "$script:Base/0"
        ($script:writes[0].Body | ConvertFrom-Json).isKeepMeSignedInDisabled | Should -BeTrue
        $script:alerts.Count | Should -Be 0
        $script:compare[0].Current.isKeepMeSignedInDisabled | Should -BeTrue
        @($script:logs | Where-Object { $_.Message -like '*read back*' }).Count | Should -Be 1
    }

    It 'POSTs the default localization when the tenant has none' {
        Set-Tenant -Kmsi $null
        Invoke-CIPPStandardDisableKeepMeSignedIn -Tenant $script:Tenant -Settings ([pscustomobject]@{ remediate = $true })
        $script:writes.Count | Should -Be 1
        $script:writes[0].Type | Should -Be 'POST'
        $script:writes[0].Uri | Should -Be $script:Base
    }

    It 'logs an error and keeps reporting drift when Graph accepts the write but the value does not change' {
        Set-Tenant -Kmsi $false -AfterWrite $false
        Invoke-CIPPStandardDisableKeepMeSignedIn -Tenant $script:Tenant -Settings ([pscustomobject]@{ remediate = $true; report = $true })
        @($script:logs | Where-Object { $_.Sev -eq 'Error' -and $_.Message -like '*still reads*' }).Count | Should -Be 1
        $script:compare[0].Current.isKeepMeSignedInDisabled | Should -BeFalse
    }

    It 'still reports when the Conditional Access read fails' {
        Set-Tenant -Kmsi $false -CaFails
        Invoke-CIPPStandardDisableKeepMeSignedIn -Tenant $script:Tenant -Settings ([pscustomobject]@{ alert = $true; report = $true })
        $script:compare.Count | Should -Be 1
        $script:alerts.Count | Should -Be 1
        $script:alerts[0].Message | Should -BeLike '*no enforced*'
    }
}
