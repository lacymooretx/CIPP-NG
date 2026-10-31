# Aspendora fork (Vikunja CIPP-29): EWS status rules.
BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Ews/Test-CIPPEwsStatus.ps1')
}
Describe 'Test-CIPPEwsStatus' {
    It 'is an error when EWS is off and apps still have EWS permissions' {
        $R = Test-CIPPEwsStatus -EwsEnabled $false -AppOnlyConsumers @('Veeam M365')
        $R.EwsEnabled | Should -Be 'False'
        $R.Findings.Key | Should -Be @('EwsDisabled')
        $R.Findings[0].Severity | Should -Be 'Error'
    }
    It 'warns when unset with consumers, naming them once' {
        $R = Test-CIPPEwsStatus -EwsEnabled $null -AppOnlyConsumers @('Avanan', 'Veeam M365') -DelegatedConsumers @('Veeam M365', 'iOS Accounts')
        $R.EwsEnabled | Should -Be 'unset'
        $R.Consumers | Should -Be @('Avanan', 'iOS Accounts', 'Veeam M365')
        $R.Findings[0].Severity | Should -Be 'Warning'
    }
    It 'is clean when pinned and in use, and info when pinned with no consumers' {
        (Test-CIPPEwsStatus -EwsEnabled $true -AppOnlyConsumers @('Veeam M365')).Findings | Should -BeNullOrEmpty
        (Test-CIPPEwsStatus -EwsEnabled $true).Findings.Key | Should -Be @('EwsUnneeded')
    }
    It 'says nothing when unset and nothing uses EWS' {
        (Test-CIPPEwsStatus -EwsEnabled $null).Findings | Should -BeNullOrEmpty
    }
    It 'reports audit usage when it was checked' {
        $R = Test-CIPPEwsStatus -EwsEnabled $true -AppOnlyConsumers @('Veeam M365') -RecentUsage @{ 'Client=WebServices | app x' = 12 }
        $R.Findings.Key | Should -Be @('EwsUsage')
        $R.Findings[0].Message | Should -Match '\(12\)'
        (Test-CIPPEwsStatus -EwsEnabled $true -AppOnlyConsumers @('Veeam M365') -RecentUsage @{}).Findings[0].Message | Should -Match 'No EWS mailbox reads'
    }
}
