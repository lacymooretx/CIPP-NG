# Printer deployment failure alert on CIPP 11.0's AlertLifecycle.
#
# The message says "failing for N hours", which changes every run. Before the lifecycle that was
# harmless noise; after it, the message would be the hash key and every run would notify again.
# Items therefore carry a stable Id (printer|device). Asserted here across consecutive runs,
# with the real Write-AlertTrace (see AlertLifecycleHarness.ps1).

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Tests/Alerts/AlertLifecycleHarness.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertPrinterDeployFailure.ps1')

    function New-GraphGetRequest {
        param($uri, $tenantid)
        if ($uri -match 'deviceManagementScripts/([^/]+)/deviceRunStates') {
            $Id = $Matches[1]
            if ($script:StatesThrow -contains $Id) { throw 'states unavailable' }
            return $script:States[$Id]
        }
        if ($script:ListThrows) { throw 'list unavailable' }
        $script:Scripts
    }
    function New-State {
        param($Device, $RunState = 'fail', [double]$HoursAgo = 30)
        [pscustomobject]@{
            runState                = $RunState
            errorCode               = -2147024891
            lastStateUpdateDateTime = [datetime]::UtcNow.AddHours(-$HoursAgo).ToString('o')
            managedDevice           = [pscustomobject]@{ deviceName = $Device }
        }
    }
    function Set-Printers {
        $script:Scripts = @(
            [pscustomobject]@{ id = 's1'; displayName = 'CIPP: Printer - Front Desk' }
            [pscustomobject]@{ id = 's2'; displayName = 'CIPP: Printer - Warehouse' }
        )
    }
    function Invoke-Alert { @(Get-CIPPAlertPrinterDeployFailure -TenantFilter 'contoso.com') }
    function Get-PrinterState { Get-LifecycleState 'Get-CIPPAlertPrinterDeployFailure' }
    # Get past the one-time hand-over with nothing failing.
    function Set-Migrated { $null = Invoke-Alert }
}

Describe 'Get-CIPPAlertPrinterDeployFailure' {
    BeforeEach {
        Reset-AlertStore
        Set-Printers
        $script:States = @{ s1 = @(); s2 = @() }
        $script:StatesThrow = @()
        $script:ListThrows = $false
    }

    It 'seeds failures silently on the first run after the upgrade (the old trace had re-alerted them daily)' {
        $script:States.s1 = @(New-State 'PC-01')

        Invoke-Alert | Should -BeNullOrEmpty
        (Get-PrinterState)['Front Desk|PC-01'] | Should -Be 'Open'
    }

    Context 'after hand-over' {
        BeforeEach { Set-Migrated }

        It 'notifies a sustained failure once, even though its hours-failing text changes every run' {
            $script:States.s1 = @(New-State 'PC-01' -HoursAgo 30)
            $First = Invoke-Alert
            $First | Should -HaveCount 1
            $First[0].Message | Should -Match "Front Desk.*PC-01.*30 hours"

            $script:States.s1 = @(New-State 'PC-01' -HoursAgo 31)
            Invoke-Alert | Should -BeNullOrEmpty
        }

        It 'ignores failures younger than the minimum age, and non-failures' {
            $script:States.s1 = @((New-State 'PC-01' -HoursAgo 2), (New-State 'PC-02' -RunState 'success'))

            Invoke-Alert | Should -BeNullOrEmpty
        }

        It 'resolves a device that recovers and notifies again if it fails again' {
            $script:States.s1 = @(New-State 'PC-01')
            $null = Invoke-Alert
            $script:States.s1 = @()
            $null = Invoke-Alert
            (Get-PrinterState)['Front Desk|PC-01'] | Should -Be 'Resolved'

            $script:States.s1 = @(New-State 'PC-01')
            Invoke-Alert | Should -HaveCount 1
        }

        It 'resolves everything when the printer scripts are gone' {
            $script:States.s1 = @(New-State 'PC-01')
            $null = Invoke-Alert
            $script:Scripts = @()

            $null = Invoke-Alert
            (Get-PrinterState)['Front Desk|PC-01'] | Should -Be 'Resolved'
        }

        It 'does not resolve failures on a printer whose states could not be read' {
            $script:States.s1 = @(New-State 'PC-01')
            $script:States.s2 = @(New-State 'PC-09')
            $null = Invoke-Alert
            $script:StatesThrow = @('s2')

            Invoke-Alert | Should -BeNullOrEmpty
            (Get-PrinterState)['Warehouse|PC-09'] | Should -Be 'Open'
        }

        It 'does not reconcile at all when the script list cannot be read' {
            $script:States.s1 = @(New-State 'PC-01')
            $null = Invoke-Alert
            $script:ListThrows = $true

            Invoke-Alert | Should -BeNullOrEmpty
            (Get-PrinterState)['Front Desk|PC-01'] | Should -Be 'Open'
        }
    }
}
