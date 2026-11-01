# Aspendora fork (Vikunja CIPP-26): monthly ASR audit-to-block readiness alert.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertAsrReadiness.ps1')

    function Get-CIPPAsrReadiness { param($TenantFilter, $WindowDays) $script:Report }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData) $script:Logs.Add($message) }
    function Write-AlertTrace { param($cmdletName, $tenantFilter, $data) $script:Traced = @($data); $script:TraceCalls++; $data }
    function Rule { param($Id, $Mode, $Rec, $Reason = 'r', $Policies = 'ASR Default rules: Audit -> All Devices') [pscustomobject]@{ RuleId = $Id; Rule = "Rule $Id"; Mode = $Mode; Recommendation = $Rec; Reason = $Reason; Policies = $Policies } }
    function Rep { param([object[]]$Rules, $Available = $true, [object[]]$Errors = @(), $Policies = 1) [pscustomobject]@{ Rules = $Rules; Errors = $Errors; Notes = @('advanced hunting device tables are not provisioned'); Evidence = [pscustomobject]@{ Available = $Available }; Summary = [pscustomobject]@{ AsrPolicies = $Policies } } }
}

Describe 'Get-CIPPAlertAsrReadiness' {
    BeforeEach {
        $script:Logs = [System.Collections.Generic.List[string]]::new()
        $script:Traced = $null; $script:TraceCalls = 0
    }

    It 'raises ready rules and conflicts with stable Ids' {
        $script:Report = Rep @((Rule 'A' 'Audit' 'ReadyForBlock' 'Ready for block: no audit hits in 14 day(s)'), (Rule 'B' 'Audit' 'KeepAudit'), (Rule 'C' 'Conflict' 'FixConflict'), (Rule 'D' 'Block' 'AlreadyBlock'))
        $R = @(Get-CIPPAlertAsrReadiness -TenantFilter 'contoso.com')
        $R.Id | Should -Be @('Ready|A', 'Conflict|C')
        $R[0].Severity | Should -Be 'Info'
        $R[1].Severity | Should -Be 'Warning'
    }

    It 'adds one NoEvidence row instead of a row per audit rule' {
        $script:Report = Rep @((Rule 'A' 'Audit' 'KeepAudit'), (Rule 'B' 'Warn' 'KeepAudit')) $false
        $R = @(Get-CIPPAlertAsrReadiness -TenantFilter 'contoso.com')
        $R.Id | Should -Be @('NoEvidence')
        $R[0].Message | Should -Match '^2 ASR rule\(s\).*not provisioned'
    }

    It 'skips reporting when the policy read had errors' {
        $script:Report = Rep @((Rule 'A' 'Audit' 'ReadyForBlock')) $true @('policy X: only 3 of 9 settings were returned')
        Get-CIPPAlertAsrReadiness -TenantFilter 'contoso.com' | Should -BeNullOrEmpty
        $script:TraceCalls | Should -Be 0
        $script:Logs[0] | Should -Match 'skipped'
    }

    It 'reconciles to empty for a tenant with no ASR policy' {
        $script:Report = Rep @((Rule 'A' 'NotConfigured' 'NotConfigured')) $false @() 0
        Get-CIPPAlertAsrReadiness -TenantFilter 'contoso.com' | Should -BeNullOrEmpty
        $script:TraceCalls | Should -Be 1
    }
}
