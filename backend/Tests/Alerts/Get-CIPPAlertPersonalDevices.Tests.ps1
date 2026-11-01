# Pester tests for Get-CIPPAlertPersonalDevices (Vikunja CIPP-21). Get-CIPPPersonalDevices is stubbed; Write-AlertTrace
# is stubbed to capture the rows handed to the alert lifecycle (state mode, stable Id, no UserPrincipalName key).

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertPersonalDevices.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/IntuneOps/Test-CIPPManagedDeviceActive.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Tools/ConvertTo-CIPPBoolean.ps1')

    function Get-CIPPPersonalDevices { [CmdletBinding()] param($TenantFilter, $NewDays) }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData) }
    function Write-AlertTrace {
        param($cmdletName, $tenantFilter, $data, [switch]$Append)
        $script:Traced = @($data)
        $script:Appended = [bool]$Append
        $script:TraceCalls++
    }

    function script:New-Row([string]$Id, [string]$Os = 'Windows', [bool]$ViaWork = $true, [string]$State = 'managed') {
        [pscustomobject]@{
            id = $Id; deviceName = "DEV-$Id"; operatingSystem = $Os; userPrincipalName = "$Id@contoso.com"
            deviceEnrollmentType = 'windowsAutoEnrollment'; enrollmentType = 'Windows automatic enrollment (work account added)'
            joinType = if ($ViaWork) { 'azureADRegistered' } else { 'unknown' }; viaWorkAccount = $ViaWork
            enrolledDateTime = '2026-10-01T00:00:00.0000000Z'; managementState = $State
        }
    }
}

Describe 'Get-CIPPAlertPersonalDevices' {
    BeforeEach {
        $script:Traced = $null; $script:Appended = $null; $script:TraceCalls = 0
        $script:Summary = [pscustomobject]@{ PersonalBlockedWindows = $false; MdmEnrollmentDuringRegistrationDisabled = $false }
        Mock Write-LogMessage {}
        Mock Get-CIPPPersonalDevices {
            [pscustomobject]@{
                Tenants = @($script:Summary)
                Devices = @((New-Row 'w1'), (New-Row 'i1' -Os 'iOS' -ViaWork $false), (New-Row 'r1' -State 'retirePending'))
            }
        }
    }

    It 'raises active personal devices in state mode with a stable Id and no UserPrincipalName key' {
        Get-CIPPAlertPersonalDevices -TenantFilter 'contoso.com'
        $script:Appended | Should -BeFalse
        $script:Traced.Id | Should -Be @('PersonalDevice|w1', 'PersonalDevice|i1')
        $script:Traced[0].PSObject.Properties.Name | Should -Not -Contain 'UserPrincipalName'
    }

    It 'explains a work-account enrollment and names both controls that are off' {
        Get-CIPPAlertPersonalDevices -TenantFilter 'contoso.com'
        $script:Traced[0].Message | Should -BeLike '*added a work account*'
        $script:Traced[0].Message | Should -BeLike '*default platform restriction*'
        $script:Traced[0].Message | Should -BeLike '*Disable MDM enrollment when adding work or school account*'
    }

    It 'does not suggest controls that are already on' {
        $script:Summary = [pscustomobject]@{ PersonalBlockedWindows = $true; MdmEnrollmentDuringRegistrationDisabled = $true }
        Get-CIPPAlertPersonalDevices -TenantFilter 'contoso.com'
        $script:Traced[0].Message | Should -Not -BeLike '*To stop new ones*'
    }

    It 'limits to Windows and macOS when PersonalDevicesComputersOnly is on, and reads a string false as off' {
        Get-CIPPAlertPersonalDevices -TenantFilter 'contoso.com' -InputValue @{ PersonalDevicesComputersOnly = $true }
        $script:Traced.Id | Should -Be @('PersonalDevice|w1')
        Get-CIPPAlertPersonalDevices -TenantFilter 'contoso.com' -InputValue @{ PersonalDevicesComputersOnly = 'false' }
        @($script:Traced).Count | Should -Be 2
    }

    It 'traces an empty set when there are no personal devices, so open alerts clear' {
        Mock Get-CIPPPersonalDevices { [pscustomobject]@{ Tenants = @($script:Summary); Devices = @() } }
        Get-CIPPAlertPersonalDevices -TenantFilter 'contoso.com'
        $script:TraceCalls | Should -Be 1
        @($script:Traced).Count | Should -Be 0
    }

    It 'does not reconcile when the device list cannot be read' {
        Mock Get-CIPPPersonalDevices { throw 'Forbidden' }
        Get-CIPPAlertPersonalDevices -TenantFilter 'contoso.com'
        $script:TraceCalls | Should -Be 0
    }
}
