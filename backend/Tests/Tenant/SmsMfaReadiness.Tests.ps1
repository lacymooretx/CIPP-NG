# Aspendora fork (Vikunja CIPP-6): who would break if SMS/voice MFA were disabled - rules, collector and alert.
# Registration shapes copied from a live userRegistrationDetails read (3endt.com, 2026-10-31).

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Tests/Alerts/AlertLifecycleHarness.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/SmsMfa/Test-CIPPSmsMfaReadiness.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/SmsMfa/Get-CIPPSmsMfaReadiness.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/SmsMfa/Save-CIPPSmsMfaReadinessSummary.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertSmsMfaReliance.ps1')

    function Reg {
        param($Id, [string[]]$Methods = @(), $Default = 'none', [switch]$Admin, $UserType = 'member', $Pref = 'none', [string[]]$SysPref = @(), $SysPrefOn = $true)
        [pscustomobject]@{ id = $Id; userPrincipalName = "$Id@contoso.com"; userDisplayName = $Id; userType = $UserType; isAdmin = [bool]$Admin
            methodsRegistered = $Methods; defaultMfaMethod = $Default; userPreferredMethodForSecondaryAuthentication = $Pref
            systemPreferredAuthenticationMethods = $SysPref; isSystemPreferredAuthenticationMethodEnabled = $SysPrefOn }
    }
    function User { param($Id, $Enabled = $true, $Licensed = $true, $Type = 'Member') [pscustomobject]@{ id = $Id; accountEnabled = $Enabled; userType = $Type; assignedLicenses = $(if ($Licensed) { @(@{ skuId = 'x' }) } else { @() }) } }
    function Policy { param($Sms = 'enabled', $Voice = 'disabled') [pscustomobject]@{ authenticationMethodConfigurations = @([pscustomobject]@{ id = 'Sms'; state = $Sms }, [pscustomobject]@{ id = 'Voice'; state = $Voice }) } }
}

Describe 'Test-CIPPSmsMfaReadiness' {
    It 'is ready when everyone has Authenticator or a passkey, and says SMS can go' {
        $Regs = @((Reg 'a' @('microsoftAuthenticatorPush', 'mobilePhone') 'microsoftAuthenticatorPush'), (Reg 'b' @('passKeySynced')))
        $R = Test-CIPPSmsMfaReadiness -Registrations $Regs -Users @((User 'a'), (User 'b')) -Policy (Policy)
        $R.Summary.ReadyToDisableSms | Should -BeTrue
        $R.Summary.ReadyToDisableBoth | Should -BeTrue
        $R.Summary.CoveragePercent | Should -Be 100
        $R.Findings.Key | Should -Be @('ReadyToDisableSms')
    }

    It 'flags phone-only users in one consolidated finding and is not ready' {
        $Regs = @((Reg 'a' @('mobilePhone') 'mobilePhone'), (Reg 'b' @('mobilePhone', 'officePhone', 'email') 'mobilePhone'), (Reg 'c' @('microsoftAuthenticatorPush')))
        $R = Test-CIPPSmsMfaReadiness -Registrations $Regs -Users @((User 'a'), (User 'b'), (User 'c')) -Policy (Policy)
        $R.Summary.PhoneOnly | Should -Be 2
        $R.Summary.ReadyToDisableSms | Should -BeFalse
        ($R.Findings | Where-Object Key -EQ 'PhoneOnlyUsers').Message | Should -Match '2 enabled user'
        @($R.Findings | Where-Object Key -EQ 'ReadyToDisableSms') | Should -BeNullOrEmpty
    }

    It 'treats office-phone-only users as voice-dependent but not SMS-dependent' {
        $R = Test-CIPPSmsMfaReadiness -Registrations @((Reg 'a' @('officePhone') 'officePhone')) -Users @((User 'a')) -Policy (Policy -Voice 'enabled')
        $R.Summary.SmsDependent | Should -Be 0
        $R.Summary.VoiceDependent | Should -Be 1
        $R.Summary.ReadyToDisableSms | Should -BeTrue
        $R.Summary.ReadyToDisableVoice | Should -BeFalse
    }

    It 'raises one Error per admin on SMS only or without MFA, and a Warning for an admin defaulting to SMS' {
        $Regs = @(
            (Reg 'adm1' @('mobilePhone') 'mobilePhone' -Admin)
            (Reg 'adm2' @() -Admin)
            (Reg 'adm3' @('mobilePhone', 'microsoftAuthenticatorPush') 'mobilePhone' -Admin -SysPrefOn $false -Pref 'sms')
        )
        $R = Test-CIPPSmsMfaReadiness -Registrations $Regs -Users @((User 'adm1'), (User 'adm2'), (User 'adm3')) -Policy (Policy)
        ($R.Findings | Where-Object Key -EQ 'AdminPhoneOnly|adm1').Severity | Should -Be 'Error'
        ($R.Findings | Where-Object Key -EQ 'AdminNoMfa|adm2').Severity | Should -Be 'Error'
        ($R.Findings | Where-Object Key -EQ 'AdminPhoneDefault|adm3').Severity | Should -Be 'Warning'
        @($R.Findings | Where-Object Key -EQ 'PhoneOnlyUsers') | Should -BeNullOrEmpty # admins are not double-counted
        $R.Users[0].IsAdmin | Should -BeTrue
    }

    It 'uses the system-preferred method as the effective default when Microsoft manages it' {
        $R = Test-CIPPSmsMfaReadiness -Registrations @((Reg 'a' @('mobilePhone', 'microsoftAuthenticatorPush') 'mobilePhone' -SysPref @('PhoneAppNotification'))) -Users @((User 'a')) -Policy (Policy)
        $R.Users[0].Category | Should -Be 'Ready'
        $R.Users[0].DefaultMethod | Should -Be 'PhoneAppNotification'
    }

    It 'ignores guests, disabled accounts and ids that are not users' {
        $Regs = @((Reg 'g' @('mobilePhone') -UserType 'guest'), (Reg 'off' @('mobilePhone')), (Reg 'gone' @('mobilePhone')), (Reg 'ok' @('fido2')))
        $R = Test-CIPPSmsMfaReadiness -Registrations $Regs -Users @((User 'off' -Enabled $false), (User 'ok')) -Policy (Policy)
        $R.Summary.UsersEnabled | Should -Be 1
        $R.Summary.PhoneOnly | Should -Be 0
    }

    It 'does not count email or security questions as MFA' {
        $R = Test-CIPPSmsMfaReadiness -Registrations @((Reg 'a' @('email', 'mobilePhone'))) -Users @((User 'a')) -Policy (Policy)
        $R.Users[0].Category | Should -Be 'PhoneOnly'
        $R.Users[0].Methods | Should -Be 'mobilePhone'
    }

    It 'splits users without MFA into licensed (Warning) and unlicensed (mentioned only)' {
        $R = Test-CIPPSmsMfaReadiness -Registrations @((Reg 'a'), (Reg 'shared')) -Users @((User 'a'), (User 'shared' -Licensed $false)) -Policy (Policy)
        $F = $R.Findings | Where-Object Key -EQ 'NoMfaUsers'
        $F.Message | Should -Match '^1 enabled licensed user'
        $F.Message | Should -Match '1 enabled unlicensed'
    }

    It 'warns when SMS is already off but users still depend on it' {
        $R = Test-CIPPSmsMfaReadiness -Registrations @((Reg 'a' @('mobilePhone'))) -Users @((User 'a')) -Policy (Policy -Sms 'disabled' -Voice 'disabled')
        ($R.Findings | Where-Object Key -EQ 'SmsOffUsersDependent').Message | Should -Match 'cannot complete MFA'
        $R.Summary.VoiceDependent | Should -Be 1
    }

    It 'keeps the aggregate Key stable while the count changes' {
        $A = Test-CIPPSmsMfaReadiness -Registrations @((Reg 'a' @('mobilePhone'))) -Users @((User 'a')) -Policy (Policy)
        $B = Test-CIPPSmsMfaReadiness -Registrations @((Reg 'a' @('mobilePhone')), (Reg 'b' @('mobilePhone'))) -Users @((User 'a'), (User 'b')) -Policy (Policy)
        ($A.Findings | Where-Object Check -Like 'Users relying*').Key | Should -Be ($B.Findings | Where-Object Check -Like 'Users relying*').Key
    }

    It 'reports an unknown policy as Info' {
        $R = Test-CIPPSmsMfaReadiness -Registrations @((Reg 'a' @('fido2'))) -Users @((User 'a')) -Policy $null
        $R.Summary.SmsState | Should -Be 'unknown'
        $R.Findings.Key | Should -Contain 'PolicyUnknown'
    }
}

Describe 'Get-CIPPSmsMfaReadiness' {
    BeforeAll {
        function New-GraphGetRequest { [CmdletBinding()] param($uri, $tenantid) }
    }
    It 'collects registrations, users and policy' {
        Mock New-GraphGetRequest {
            if ($uri -match 'userRegistrationDetails') { @((Reg 'a' @('mobilePhone'))) }
            elseif ($uri -match '/users\?') { @((User 'a')) }
            elseif ($uri -match 'usersRegisteredByMethod') { [pscustomobject]@{ userRegistrationMethodCounts = @(@{ authenticationMethod = 'mobilePhone'; userCount = 1 }, @{ authenticationMethod = 'fido2'; userCount = 0 }) } }
            else { Policy }
        }
        $R = Get-CIPPSmsMfaReadiness -TenantFilter 'contoso.com'
        $R.Errors | Should -BeNullOrEmpty
        $R.Summary.PhoneOnly | Should -Be 1
        $R.RegisteredByMethod.Method | Should -Be @('mobilePhone')
    }
    It 'returns an error and no summary when the registration report needs P1' {
        Mock New-GraphGetRequest { if ($uri -match 'userRegistrationDetails') { throw 'Tenant is not a B2C tenant and does not have premium license' } elseif ($uri -match '/users\?') { @() } else { Policy } }
        $R = Get-CIPPSmsMfaReadiness -TenantFilter 'contoso.com'
        $R.Summary | Should -BeNullOrEmpty
        $R.Errors[0] | Should -Match 'Entra ID P1'
    }
}

Describe 'Get-CIPPAlertSmsMfaReliance' {
    BeforeAll {
        function Get-CIPPSmsMfaReadiness { param($TenantFilter) $script:Report }
        function Set-Report {
            param([double]$Coverage, [object[]]$Findings = @(), [string[]]$Errors = @())
            $script:Report = [pscustomobject]@{ Errors = $Errors; Findings = $Findings
                Summary = [pscustomobject]@{ CoveragePercent = $Coverage; UsersEnabled = 100; PhoneOnly = 0 } }
        }
        function Run { param($InputValue) @(Get-CIPPAlertSmsMfaReliance -TenantFilter 'contoso.com' -InputValue $InputValue | Where-Object { $_ }) }
        $script:PhoneOnly = [pscustomobject]@{ Key = 'PhoneOnlyUsers'; Severity = 'Warning'; Check = 'Users relying only on SMS/voice'; Account = ''; Message = '3 enabled user(s)'; Fix = 'x' }
    }
    BeforeEach { Reset-AlertStore }

    It 'records the coverage baseline silently on the first run' {
        Set-Report -Coverage 80
        Run | Should -BeNullOrEmpty
        ($script:Store['SmsMfaReadiness'].Values | Where-Object PartitionKey -EQ 'Coverage').BestPercent | Should -Be '80'
    }

    It 'notifies once for a coverage drop beyond the threshold, then resolves when it recovers' {
        Set-Report -Coverage 80; $null = Run
        Set-Report -Coverage 70
        (Run).Id | Should -Be @('CoverageRegressed')
        Run | Should -BeNullOrEmpty # still regressed: no repeat
        Set-Report -Coverage 79; $null = Run
        (Get-LifecycleState 'Get-CIPPAlertSmsMfaReliance')['CoverageRegressed'] | Should -Be 'Resolved'
    }

    It 'honours SmsCoverageDropPercent' {
        Set-Report -Coverage 80; $null = Run
        Set-Report -Coverage 70
        Run -InputValue @{ SmsCoverageDropPercent = 15 } | Should -BeNullOrEmpty
    }

    It 'takes a drop that persisted 28 days as the new baseline' {
        Set-Report -Coverage 80; $null = Run
        Set-Report -Coverage 60; $null = Run
        $Row = $script:Store['SmsMfaReadiness'].Values | Where-Object PartitionKey -EQ 'Coverage'
        $Row.RegressedSinceUtc = [datetime]::UtcNow.AddDays(-29).ToString('o')
        $null = Run
        ($script:Store['SmsMfaReadiness'].Values | Where-Object PartitionKey -EQ 'Coverage').BestPercent | Should -Be '60'
    }

    It 'notifies a consolidated finding once while only its count changes' {
        Set-Report -Coverage 80 -Findings @($script:PhoneOnly)
        (Run).Id | Should -Be @('PhoneOnlyUsers')
        $Changed = $script:PhoneOnly.PSObject.Copy(); $Changed.Message = '5 enabled user(s)'
        Set-Report -Coverage 80 -Findings @($Changed)
        Run | Should -BeNullOrEmpty
    }

    It 'does not report (or resolve) when collection failed' {
        Set-Report -Coverage 80 -Findings @($script:PhoneOnly); $null = Run
        Set-Report -Coverage 80 -Errors @('Users: Forbidden')
        Run | Should -BeNullOrEmpty
        (Get-LifecycleState 'Get-CIPPAlertSmsMfaReliance')['PhoneOnlyUsers'] | Should -Be 'Open'
    }
}
