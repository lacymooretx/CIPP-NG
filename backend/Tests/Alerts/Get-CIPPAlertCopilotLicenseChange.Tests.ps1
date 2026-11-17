# Aspendora fork (Vikunja CIPP-42): Copilot licence appears or changes seat count. First run seeds silently (also
# when the tenant has no Copilot at all); afterwards each change notifies once, labelled ours / bought elsewhere.
# Runs on the real AlertLifecycle.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Tests/Alerts/AlertLifecycleHarness.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertCopilotLicenseChange.ps1')

    function New-GraphGetRequest {
        [CmdletBinding()] param($uri, $tenantid)
        if ($script:GraphThrows) { throw 'Forbidden' }
        $script:Skus
    }
    function Get-CIPPCSPProvider { param($TenantFilter) $script:Provider }
    function Get-Pax8Subscriptions { param($TenantFilter) if ($script:Pax8Throws) { throw 'Pax8 down' } $script:Pax8 }
    function Get-SherwebCurrentSubscription { param($TenantFilter) @() }
    function Sku { param($Id, $Part, $Enabled, $Consumed = 0, $Plans = @()) [pscustomobject]@{ skuId = $Id; skuPartNumber = $Part; prepaidUnits = [pscustomobject]@{ enabled = $Enabled; warning = 0; suspended = 0 }; consumedUnits = $Consumed; capabilityStatus = 'Enabled'; servicePlans = @($Plans | ForEach-Object { [pscustomobject]@{ servicePlanName = $_ } }) } }
    function Run { @(Get-CIPPAlertCopilotLicenseChange -TenantFilter 'contoso.com' | Where-Object { $_ }) }
}

Describe 'Get-CIPPAlertCopilotLicenseChange' {
    BeforeEach {
        Reset-AlertStore
        $script:GraphThrows = $false
        $script:Pax8Throws = $false
        $script:Provider = 'Pax8'
        $script:Pax8 = @()
        $script:Skus = @((Sku 'bp' 'SPB' 10 9))
    }

    It 'seeds silently on the first run, even with no Copilot SKU' {
        Run | Should -BeNullOrEmpty
        $script:Store['KnownCopilotSkus'].Keys | Should -Contain 'contoso.com|_seeded'
        $script:Store['AlertLifecycle'] | Should -BeNullOrEmpty
    }

    It 'does not treat a base SKU with Copilot Studio agent plans as Copilot' {
        $script:Skus = @((Sku 'bp' 'SPB' 10 9 @('POWER_VIRTUAL_AGENTS_O365_P3')))
        $null = Run
        @($script:Store['KnownCopilotSkus'].Values).Count | Should -Be 1
    }

    It 'raises a Copilot SKU bought elsewhere once as a Warning' {
        $null = Run
        $script:Skus += Sku 'cp' 'Microsoft_365_Copilot' 3 1
        $Out = Run
        $Out.Id | Should -Be @('CopilotSku|cp|3')
        $Out[0].Severity | Should -Be 'Warning'
        $Out[0].Source | Should -Be 'bought elsewhere'
        $Out[0].Message | Should -Match 'appeared \(1 assigned of 3 purchased\)'
        Run | Should -BeNullOrEmpty
    }

    It 'labels it ours when Pax8 has a Copilot subscription' {
        $null = Run
        $script:Pax8 = @([pscustomobject]@{ productName = 'Microsoft 365 Copilot Business'; quantity = 3 })
        $script:Skus += Sku 'cp' 'Microsoft_365_Copilot' 3
        $Out = Run
        $Out[0].Source | Should -Be 'ours'
        $Out[0].SourceDetail | Should -Be 'Microsoft 365 Copilot Business x3'
    }

    It 'does not count a Dragon Copilot Pax8 subscription as M365 Copilot' {
        $null = Run
        $script:Pax8 = @([pscustomobject]@{ productName = 'Microsoft Dragon Copilot'; quantity = 5 })
        $script:Skus += Sku 'cp' 'Microsoft_365_Copilot' 1
        (Run)[0].Source | Should -Be 'bought elsewhere'
    }

    It 'says unknown when the tenant is not mapped or Pax8 fails, and still alerts' {
        $null = Run
        $script:Provider = $null
        $script:Skus += Sku 'cp' 'Microsoft_365_Copilot' 1
        $Out = Run
        $Out[0].Source | Should -Be 'unknown'
        $Out[0].Message | Should -Match 'not mapped'

        $script:Provider = 'Pax8'; $script:Pax8Throws = $true
        $script:Skus = @((Sku 'bp' 'SPB' 10), (Sku 'cp' 'Microsoft_365_Copilot' 2))
        $Out = Run
        $Out[0].Source | Should -Be 'unknown'
        $Out[0].SourceDetail | Should -Match 'Pax8 down'
    }

    It 'raises seat increases as Warning and decreases and removals as Info, once each' {
        $script:Skus += Sku 'cp' 'Microsoft_365_Copilot' 1
        $null = Run
        $script:Skus = @((Sku 'bp' 'SPB' 10), (Sku 'cp' 'Microsoft_365_Copilot' 5))
        $Up = Run
        $Up.Id | Should -Be @('CopilotSku|cp|5')
        $Up[0].Severity | Should -Be 'Warning'
        $Up[0].Message | Should -Match 'from 1 to 5'

        $script:Skus = @((Sku 'bp' 'SPB' 10), (Sku 'cp' 'Microsoft_365_Copilot' 2))
        (Run)[0].Severity | Should -Be 'Info'

        $script:Skus = @((Sku 'bp' 'SPB' 10))
        $Gone = Run
        $Gone.Id | Should -Be @('CopilotSku|cp|removed')
        $Gone[0].Severity | Should -Be 'Info'
        Run | Should -BeNullOrEmpty
    }

    It 'does not alert when only assigned seats change' {
        $script:Skus += Sku 'cp' 'Microsoft_365_Copilot' 5 1
        $null = Run
        $script:Skus = @((Sku 'bp' 'SPB' 10), (Sku 'cp' 'Microsoft_365_Copilot' 5 4))
        Run | Should -BeNullOrEmpty
        $script:Store['KnownCopilotSkus']['contoso.com|cp'].Consumed | Should -Be 4
    }

    It 'matches bundles by their M365_COPILOT service plan' {
        $null = Run
        $script:Skus += Sku 'e7' 'Microsoft_365_E7' 4 0 @('M365_COPILOT_APPS', 'EXCHANGE_S_ENTERPRISE')
        (Run).Id | Should -Be @('CopilotSku|e7|4')
    }

    It 'does not seed or alert when Graph fails' {
        $script:GraphThrows = $true
        Run | Should -BeNullOrEmpty
        $script:Store['KnownCopilotSkus'] | Should -BeNullOrEmpty
        $script:Logs.Message | Should -Match 'check failed'
    }
}
