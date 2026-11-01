# Aspendora fork (Vikunja CIPP-31): Defender remediations pending approval longer than the threshold.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertDefenderPendingRemediation.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Alerts/Get-CIPPAlertFailureSeverity.ps1')

    function Get-CIPPDefenderPendingRemediation {
        param($TenantFilter, $MinAgeHours)
        $script:MinAge = $MinAgeHours
        if ($script:Fail) { throw $script:FailWith }
        [pscustomobject]@{ Alerts = $script:Alerts }
    }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData) $script:Logs.Add($message); $script:Sevs.Add([string]$sev) }
    function Write-AlertTrace { param($cmdletName, $tenantFilter, $data) $script:Traced = @($data); $script:TraceCalls++; $data }
}

Describe 'Get-CIPPAlertDefenderPendingRemediation' {
    BeforeEach {
        $script:Logs = [System.Collections.Generic.List[string]]::new()
        $script:Sevs = [System.Collections.Generic.List[string]]::new()
        $script:FailWith = 'Forbidden'
        $script:Traced = $null; $script:TraceCalls = 0; $script:Fail = $false; $script:MinAge = $null
        $script:Alerts = @(
            [pscustomobject]@{ AlertId = 'fa1'; IncidentId = '602'; Title = 'Email messages containing malicious URL removed after delivery'; ServiceSource = 'microsoftDefenderForOffice365'; Created = '2026-08-26 18:43 CDT (23:43 UTC)'; AgeHours = 1572.3; OverThreshold = $true; PendingActions = 3; IncidentUrl = 'https://security.microsoft.com/incidents/602' }
            [pscustomobject]@{ AlertId = 'fa2'; IncidentId = '949'; Title = 'Email messages containing malicious URL removed after delivery'; ServiceSource = 'microsoftDefenderForOffice365'; Created = ''; AgeHours = 5; OverThreshold = $false; PendingActions = $null; IncidentUrl = '' }
            [pscustomobject]@{ AlertId = 'da1'; IncidentId = '700'; Title = 'Suspicious process'; ServiceSource = 'microsoftDefenderForEndpoint'; Created = ''; AgeHours = 30; OverThreshold = $true; PendingActions = $null; IncidentUrl = '' }
        )
    }

    It 'raises only alerts over the threshold, with a stable Id per alert' {
        $R = @(Get-CIPPAlertDefenderPendingRemediation -TenantFilter 'contoso.com')
        $R.Id | Should -Be @('PendingApproval|fa1', 'PendingApproval|da1')
        $R[0].Message | Should -Match 'email \(MDO\).*1572h\+.*incident 602.*3 action\(s\)'
        $R[1].Source | Should -Be 'device (MDE)'
        $script:MinAge | Should -Be 24
    }

    It 'reads the threshold bare or as a named input' {
        $null = Get-CIPPAlertDefenderPendingRemediation -TenantFilter 'contoso.com' -InputValue 48
        $script:MinAge | Should -Be 48
        $null = Get-CIPPAlertDefenderPendingRemediation -TenantFilter 'contoso.com' -InputValue ([pscustomobject]@{ PendingRemediationHours = '12' })
        $script:MinAge | Should -Be 12
        $null = Get-CIPPAlertDefenderPendingRemediation -TenantFilter 'contoso.com' -InputValue @{ PendingRemediationHours = 6 }
        $script:MinAge | Should -Be 6
        $null = Get-CIPPAlertDefenderPendingRemediation -TenantFilter 'contoso.com' -InputValue 'nonsense'
        $script:MinAge | Should -Be 24
    }

    It 'resolves everything when nothing is pending (empty trace, not skipped)' {
        $script:Alerts = @()
        Get-CIPPAlertDefenderPendingRemediation -TenantFilter 'contoso.com' | Should -BeNullOrEmpty
        $script:TraceCalls | Should -Be 1
    }

    It 'does not reconcile when the alert list cannot be read' {
        $script:Fail = $true
        Get-CIPPAlertDefenderPendingRemediation -TenantFilter 'contoso.com' | Should -BeNullOrEmpty
        $script:TraceCalls | Should -Be 0
        $script:Logs[0] | Should -Match 'Forbidden'
        $script:Sevs[0] | Should -Be 'Error'
    }

    It 'logs a tenant without the licence at Info, so the logbook rule does not email every run' {
        $script:Fail = $true
        $script:FailWith = 'The account is not provisioned. You do not the correct M365 license to access this information..'
        Get-CIPPAlertDefenderPendingRemediation -TenantFilter 'contoso.com' | Should -BeNullOrEmpty
        $script:TraceCalls | Should -Be 0
        $script:Sevs[0] | Should -Be 'Info'
    }
}
