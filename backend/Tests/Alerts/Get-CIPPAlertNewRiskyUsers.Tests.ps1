# Aspendora fork (Vikunja CIPP-8): tenants without Entra ID P2 cannot read riskyUsers ("Required license not
# available"), but riskDetections still answers, so the alert falls back to new risk detections there.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))

    function Get-CIPPTable { param($Table, $tablename) @{ Table = $Table } }
    function Get-CIPPAzDataTableEntity { param($Table, $Filter) $null }
    function Add-CIPPAzDataTableEntity { param($Table, $Entity, [switch]$Force) }
    function Get-CIPPTenantCapabilities { param($TenantFilter) [pscustomobject]@{ AAD_PREMIUM_P2 = $script:P2 } }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData) $script:Logs.Add($message) }
    function Write-AlertTrace { param($cmdletName, $tenantFilter, $data, [switch]$Append) $script:Traced = @{ Data = @($data); Append = [bool]$Append }; $data }
    function New-GraphGetRequest {
        param($uri, $tenantid, $ErrorAction)
        $script:Uris.Add($uri)
        if ($uri -match 'riskDetections') {
            if ($script:DetectionsThrow) { throw $script:DetectionsThrow }
            return $script:Detections
        }
        if ($uri -match 'riskyUsers') { return @() }
    }

    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertNewRiskyUsers.ps1')

    function Det {
        param($Id, $Level = 'medium', $State = 'atRisk', $Upn = 'user@contoso.com')
        [pscustomobject]@{ id = $Id; userPrincipalName = $Upn; riskEventType = 'unfamiliarFeatures'; riskLevel = $Level; riskState = $State
            detectedDateTime = '2026-10-31T17:53:10Z'; ipAddress = '1.2.3.4'; location = @{ city = 'Atlanta'; countryOrRegion = 'US' } }
    }
}

Describe 'Get-CIPPAlertNewRiskyUsers' {
    BeforeEach {
        $script:Uris = [System.Collections.Generic.List[string]]::new()
        $script:Logs = [System.Collections.Generic.List[string]]::new()
        $script:P2 = $false
        $script:Detections = @()
        $script:DetectionsThrow = $null
        $script:Traced = $null
    }

    It 'falls back to risk detections without P2, keeping medium, high and hidden open detections' {
        $script:Detections = @(
            (Det 'd1' 'high')
            (Det 'd2' 'medium')
            (Det 'd3' 'hidden')
            (Det 'd4' 'low')
            (Det 'd5' 'high' 'remediated')
            (Det 'd6' 'high' 'dismissed')
        )
        $R = @(Get-CIPPAlertNewRiskyUsers -TenantFilter 'contoso.com')
        $R.Id | Should -Be @('RiskDetection|d1', 'RiskDetection|d2', 'RiskDetection|d3')
        $R[0].Details.Severity | Should -Be 'Critical'
        $R[1].Details.Severity | Should -Be 'Warning'
        $R[0].Details.Location | Should -Be 'Atlanta, US'
        $script:Traced.Append | Should -BeTrue
        ($script:Uris | Where-Object { $_ -match 'riskyUsers' }) | Should -BeNullOrEmpty
        ($script:Uris | Where-Object { $_ -match 'riskDetections' }) | Should -Match 'detectedDateTime ge '
    }

    It 'still reconciles an empty run without P2 so nothing is left half-checked' {
        Get-CIPPAlertNewRiskyUsers -TenantFilter 'contoso.com' | Should -BeNullOrEmpty
        $script:Traced | Should -Not -BeNullOrEmpty
        $script:Traced.Data.Count | Should -Be 0
    }

    It 'logs a warning and does not reconcile when risk detections cannot be read' {
        $script:DetectionsThrow = 'Required license not available'
        Get-CIPPAlertNewRiskyUsers -TenantFilter 'contoso.com' | Should -BeNullOrEmpty
        $script:Traced | Should -BeNullOrEmpty
        $script:Logs | Should -Match 'no Entra ID P2'
    }

    It 'keeps using riskyUsers on P2 tenants' {
        $script:P2 = $true
        Get-CIPPAlertNewRiskyUsers -TenantFilter 'contoso.com' | Out-Null
        ($script:Uris | Where-Object { $_ -match 'riskyUsers' }) | Should -Not -BeNullOrEmpty
        ($script:Uris | Where-Object { $_ -match 'riskDetections' }) | Should -BeNullOrEmpty
    }
}
