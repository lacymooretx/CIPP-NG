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

# Aspendora fork (Vikunja CIPP-46): Microsoft-provided SMS/voice retirement - date bucketing, policy parsing, alert.
# Policy shapes copied from live beta authenticationMethodsPolicy reads (3endt.com, aspendora.com, 2026-11-01);
# guest identity shapes from a live v1.0 users read (3endt.com, 2026-11-01). No real names.
Describe 'Test-CIPPSmsMfaReadiness retirement dates' {
    BeforeAll {
        # 2026-11-01 12:00 UTC = 06:00 CST (DST ended 02:00 CDT that morning).
        $script:Now = [datetime]::SpecifyKind([datetime]'2026-11-01T12:00:00', 'Utc')
        function Ext {
            param($Id, $Type = 'Guest', $Issuer = 'ExternalAzureAD', $State = 'Accepted', $Creation = 'Invitation')
            [pscustomobject]@{ id = $Id; accountEnabled = $true; userType = $Type; assignedLicenses = @(); userPrincipalName = "$($Id)_fabrikam.com#EXT#@contoso.onmicrosoft.com"
                creationType = $Creation; externalUserState = $State
                identities = @([pscustomobject]@{ signInType = 'federated'; issuer = $Issuer }, [pscustomobject]@{ signInType = 'userPrincipalName'; issuer = 'contoso.onmicrosoft.com' })
            }
        }
        function IntGuest {
            param($Id)
            [pscustomobject]@{ id = $Id; accountEnabled = $true; userType = 'Guest'; assignedLicenses = @(); userPrincipalName = "$Id@contoso.com"
                creationType = $null; externalUserState = $null; identities = @([pscustomobject]@{ signInType = 'userPrincipalName'; issuer = 'contoso.onmicrosoft.com' })
            }
        }
        function Eval {
            param($Regs, $Users, $Ga = @(), $GaEligible, $Policy = (Policy), $NowUtc = $script:Now)
            $P = @{ Registrations = $Regs; Users = $Users; Policy = $Policy; NowUtc = $NowUtc }
            if ($null -ne $Ga) { $P.GlobalAdminIds = $Ga }
            if ($null -ne $GaEligible) { $P.GlobalAdminEligibleIds = $GaEligible }
            Test-CIPPSmsMfaReadiness @P
        }
    }

    It 'dates a member February, an active Global Admin July, and leaves CIPP-6 counts alone' {
        $R = Eval -Regs @((Reg 'mem' @('mobilePhone')), (Reg 'ga' @('mobilePhone') -Admin)) -Users @((User 'mem'), (User 'ga')) -Ga @('GA')
        ($R.Users | Where-Object Id -EQ 'mem').RetirementDate | Should -Be '2027-02-01'
        ($R.Users | Where-Object Id -EQ 'mem').RetirementBasis | Should -Be 'Member'
        ($R.Users | Where-Object Id -EQ 'ga').RetirementDate | Should -Be '2027-07-01' # id match is case-insensitive
        ($R.Users | Where-Object Id -EQ 'ga').IsGlobalAdmin | Should -BeTrue
        $R.Summary.RetirementFebruary2027 | Should -Be 1
        $R.Summary.RetirementJuly2027 | Should -Be 1
        $R.Summary.PhoneOnly | Should -Be 2
        $R.Summary.UsersEnabled | Should -Be 2
        $R.Summary.ReadyByFeb2027 | Should -BeFalse
    }

    It 'treats a non-Global admin role holder as February' {
        $R = Eval -Regs @((Reg 'helpdesk' @('mobilePhone') -Admin)) -Users @((User 'helpdesk')) -Ga @('someoneelse')
        $R.Users[0].RetirementDate | Should -Be '2027-02-01'
        $R.Users[0].IsGlobalAdmin | Should -BeFalse
    }

    It 'treats a PIM-eligible-only Global Admin as July and says so' {
        $R = Eval -Regs @((Reg 'elig' @('mobilePhone') -Admin)) -Users @((User 'elig')) -Ga @() -GaEligible @('elig')
        $R.Users[0].RetirementBasis | Should -Be 'GlobalAdministratorEligible'
        $R.Users[0].RetirementDate | Should -Be '2027-07-01'
        ($R.Findings | Where-Object Key -EQ 'SmsRetirementJuly').Message | Should -Match 'PIM-eligible'
    }

    It 'dates an external guest July and an internal guest February, without adding guests to Users or PhoneOnly' {
        $Regs = @((Reg 'ext' @('mobilePhone') -UserType 'guest'), (Reg 'intg' @('mobilePhone') -UserType 'guest'), (Reg 'mem' @('fido2')))
        $R = Eval -Regs $Regs -Users @((Ext 'ext'), (IntGuest 'intg'), (User 'mem'))
        @($R.Users).Count | Should -Be 1
        $R.Summary.PhoneOnly | Should -Be 0
        $R.Summary.GuestsPhoneOnly | Should -Be 2
        ($R.Guests | Where-Object Id -EQ 'ext').RetirementBasis | Should -Be 'ExternalUser'
        ($R.Guests | Where-Object Id -EQ 'ext').RetirementDate | Should -Be '2027-07-01'
        ($R.Guests | Where-Object Id -EQ 'intg').RetirementBasis | Should -Be 'InternalGuest'
        ($R.Guests | Where-Object Id -EQ 'intg').RetirementDate | Should -Be '2027-02-01'
        $R.Summary.ReadyByFeb2027 | Should -BeFalse # the internal guest
        $R.Summary.RetirementJuly2027 | Should -Be 1
    }

    It 'recognises a MicrosoftAccount guest with no invitation state, and an external member, as external' {
        $Msa = Ext 'msa' -Issuer 'MicrosoftAccount' -State $null -Creation $null
        $ExtMember = Ext 'xm' -Type 'Member'
        $R = Eval -Regs @((Reg 'msa' @('mobilePhone') -UserType 'guest'), (Reg 'xm' @('mobilePhone'))) -Users @($Msa, $ExtMember)
        $R.Guests[0].RetirementBasis | Should -Be 'ExternalUser'
        ($R.Users | Where-Object Id -EQ 'xm').RetirementBasis | Should -Be 'ExternalUser'
        ($R.Users | Where-Object Id -EQ 'xm').RetirementDate | Should -Be '2027-07-01'
    }

    It 'gives no retirement date to users without a phone method' {
        $R = Eval -Regs @((Reg 'a' @('fido2'))) -Users @((User 'a'))
        $R.Users[0].RetirementDate | Should -BeNullOrEmpty
        $R.Users[0].DaysRemaining | Should -BeNullOrEmpty
        $R.Summary.NearestDeadline | Should -BeNullOrEmpty
        $R.Summary.ReadyByFeb2027 | Should -BeTrue
        @($R.Guests).Count | Should -Be 0
    }

    It 'falls back to February for everyone when Global Admins could not be read, with an Info row' {
        $R = Eval -Regs @((Reg 'ga' @('mobilePhone') -Admin)) -Users @((User 'ga')) -Ga $null
        $R.Users[0].RetirementDate | Should -Be '2027-02-01'
        $R.Summary.GlobalAdminsKnown | Should -BeFalse
        $R.Findings.Key | Should -Contain 'SmsRetirementGlobalAdminsUnknown'
    }

    It 'counts days from the US Central date, not the UTC date' {
        # 2027-01-31 05:30 UTC is 2027-01-30 23:30 CST: two days to Feb 1 in Central (one by the UTC date).
        $R = Eval -Regs @((Reg 'a' @('mobilePhone'))) -Users @((User 'a')) -NowUtc ([datetime]::SpecifyKind([datetime]'2027-01-31T05:30:00', 'Utc'))
        $R.Users[0].DaysRemaining | Should -Be 2
        $R.Summary.TodayCentral | Should -Be '2027-01-30'
        # 06:30 UTC is 00:30 CST on the 31st: one day.
        $R2 = Eval -Regs @((Reg 'a' @('mobilePhone'))) -Users @((User 'a')) -NowUtc ([datetime]::SpecifyKind([datetime]'2027-01-31T06:30:00', 'Utc'))
        $R2.Users[0].DaysRemaining | Should -Be 1
    }

    It 'counts from a CDT date (UTC-5) correctly too' {
        # 2026-10-31 04:30 UTC is 2026-10-30 23:30 CDT: 94 days to Feb 1.
        $R = Eval -Regs @((Reg 'a' @('mobilePhone'))) -Users @((User 'a')) -NowUtc ([datetime]::SpecifyKind([datetime]'2026-10-31T04:30:00', 'Utc'))
        $R.Summary.TodayCentral | Should -Be '2026-10-30'
        $R.Users[0].DaysRemaining | Should -Be 94
    }

    It 'counts 92 days from 2026-11-01 and goes negative once passed' {
        $R = Eval -Regs @((Reg 'a' @('mobilePhone'))) -Users @((User 'a'))
        $R.Users[0].DaysRemaining | Should -Be 92
        $R.Summary.NearestDeadline | Should -Be '2027-02-01'
        $R.Summary.NearestDeadlineDaysRemaining | Should -Be 92
        $Past = Eval -Regs @((Reg 'a' @('mobilePhone'))) -Users @((User 'a')) -NowUtc ([datetime]::SpecifyKind([datetime]'2027-02-03T18:00:00', 'Utc'))
        $Past.Users[0].DaysRemaining | Should -Be -2
        ($Past.Findings | Where-Object Key -EQ 'SmsRetirementFebruary').Message | Should -Match 'have been blocked at sign-in since 2027-02-01'
    }

    It 'raises an Error for the February group and a Warning for the July group, with stable Keys' {
        $R = Eval -Regs @((Reg 'm1' @('mobilePhone')), (Reg 'm2' @('officePhone')), (Reg 'ga' @('mobilePhone') -Admin)) -Users @((User 'm1'), (User 'm2'), (User 'ga')) -Ga @('ga')
        $Feb = $R.Findings | Where-Object Key -EQ 'SmsRetirementFebruary'
        $Feb.Severity | Should -Be 'Error'
        $Feb.Message | Should -Match '^2 account\(s\) .*blocked at sign-in from 2027-02-01 \(92 day'
        ($R.Findings | Where-Object Key -EQ 'SmsRetirementJuly').Severity | Should -Be 'Warning'
        $R.Summary.NearestDeadline | Should -Be '2027-02-01'
        $R.Summary.NearestDeadlineUsers | Should -Be 2
    }

    It 'makes July the nearest deadline when only the July group is left' {
        $R = Eval -Regs @((Reg 'ga' @('mobilePhone') -Admin), (Reg 'm' @('fido2'))) -Users @((User 'ga'), (User 'm')) -Ga @('ga')
        $R.Summary.NearestDeadline | Should -Be '2027-07-01'
        $R.Summary.ReadyByFeb2027 | Should -BeTrue
        $R.Summary.ReadyByJul2027 | Should -BeFalse
    }
}

Describe 'Test-CIPPSmsMfaReadiness policy parsing' {
    BeforeAll {
        # Trimmed from the live 3endt.com policy (2026-11-01), round-tripped through JSON so the shapes are what
        # New-GraphGetRequest hands back.
        function LivePolicy {
            param($OptOut = 'absent', $CampaignState = 'enabled', $CampaignMethod = 'microsoftAuthenticator', $FidoState = 'enabled', $FidoTarget = 'all_users', $Tel = 'null')
            $SmsTel = if ($Tel -eq 'null') { $null } else { @{ providerName = $Tel } }
            $Json = @{
                registrationEnforcement            = @{ authenticationMethodsRegistrationCampaign = @{ snoozeDurationInDays = 1; state = $CampaignState; excludeTargets = @()
                        includeTargets = @(@{ id = 'all_users'; targetType = 'group'; targetedAuthenticationMethod = $CampaignMethod }) }
                }
                authenticationMethodConfigurations = @(
                    @{ '@odata.type' = '#microsoft.graph.fido2AuthenticationMethodConfiguration'; id = 'Fido2'; state = $FidoState; includeTargets = @(@{ targetType = 'group'; id = $FidoTarget }) }
                    @{ '@odata.type' = '#microsoft.graph.smsAuthenticationMethodConfiguration'; id = 'Sms'; state = 'enabled'; telecomProviderSettings = $SmsTel }
                    @{ '@odata.type' = '#microsoft.graph.voiceAuthenticationMethodConfiguration'; id = 'Voice'; state = 'enabled'; telecomProviderSettings = $null }
                )
            }
            # String on the left: with $OptOut = $true on the left, 'null' would convert to $true and match.
            if ('null' -eq $OptOut) { $Json.optOutSettings = $null }
            elseif ('absent' -ne $OptOut) { $Json.optOutSettings = @{ passkeyDynamicMigration = $OptOut } }
            $Json | ConvertTo-Json -Depth 10 | ConvertFrom-Json
        }
        function EvalPolicy { param($P) Test-CIPPSmsMfaReadiness -Registrations @((Reg 'a' @('mobilePhone'))) -Users @((User 'a')) -Policy $P -GlobalAdminIds @() -NowUtc ([datetime]::SpecifyKind([datetime]'2026-11-01T12:00:00', 'Utc')) }
    }

    It 'reads opt-out true, false, null (never set, as seen live) and absent' {
        (EvalPolicy (LivePolicy -OptOut $true)).Summary.PasskeyDynamicMigrationOptOut | Should -Be 'true'
        (EvalPolicy (LivePolicy -OptOut $false)).Summary.PasskeyDynamicMigrationOptOut | Should -Be 'false'
        (EvalPolicy (LivePolicy -OptOut 'null')).Summary.PasskeyDynamicMigrationOptOut | Should -Be 'false'
        (EvalPolicy (LivePolicy -OptOut 'absent')).Summary.PasskeyDynamicMigrationOptOut | Should -Be 'unknown'
        (EvalPolicy $null).Summary.PasskeyDynamicMigrationOptOut | Should -Be 'unknown'
    }

    It 'adds an Info row only when opted out' {
        (EvalPolicy (LivePolicy -OptOut $true)).Findings.Key | Should -Contain 'SmsRetirementOptOut'
        (EvalPolicy (LivePolicy -OptOut 'null')).Findings.Key | Should -Not -Contain 'SmsRetirementOptOut'
    }

    It 'flags a campaign targeting Authenticator (live 3endt.com shape) but not one targeting FIDO2 (live aspendora.com shape)' {
        $A = EvalPolicy (LivePolicy -CampaignState 'enabled' -CampaignMethod 'microsoftAuthenticator')
        $A.Summary.RegistrationCampaignTargetsPasskey | Should -BeFalse
        $A.Summary.RegistrationCampaignMethods | Should -Be 'microsoftAuthenticator'
        ($A.Findings | Where-Object Key -EQ 'SmsRetirementCampaign').Message | Should -Match 'targets microsoftAuthenticator, not passkeys'
        $B = EvalPolicy (LivePolicy -CampaignState 'enabled' -CampaignMethod 'FIDO2')
        $B.Summary.RegistrationCampaignOk | Should -BeTrue
        $B.Summary.RegistrationCampaignAllUsers | Should -BeTrue
        $B.Findings.Key | Should -Not -Contain 'SmsRetirementCampaign'
    }

    It 'accepts Microsoft managed (default) targeting passkeys and flags a disabled campaign' {
        (EvalPolicy (LivePolicy -CampaignState 'default' -CampaignMethod 'passkey')).Summary.RegistrationCampaignOk | Should -BeTrue
        $D = EvalPolicy (LivePolicy -CampaignState 'disabled' -CampaignMethod 'FIDO2')
        $D.Summary.RegistrationCampaignOk | Should -BeFalse
        ($D.Findings | Where-Object Key -EQ 'SmsRetirementCampaign').Message | Should -Match 'is disabled'
    }

    It 'reports FIDO2 disabled, and FIDO2 scoped to groups' {
        $Off = EvalPolicy (LivePolicy -FidoState 'disabled')
        $Off.Summary.PasskeyState | Should -Be 'disabled'
        $Off.Summary.PasskeyScope | Should -Be 'None'
        $Off.Findings.Key | Should -Contain 'SmsRetirementPasskeyDisabled'
        $Grp = EvalPolicy (LivePolicy -FidoTarget '11111111-2222-3333-4444-555555555555')
        $Grp.Summary.PasskeyScope | Should -Be 'Groups'
        $Grp.Summary.PasskeyGroups | Should -Be 1
        $Grp.Findings.Key | Should -Contain 'SmsRetirementPasskeyScoped'
        (EvalPolicy (LivePolicy)).Summary.PasskeyScope | Should -Be 'AllUsers'
    }

    It 'reads the telephony provider from telecomProviderSettings' {
        (EvalPolicy (LivePolicy)).Summary.TelephonyProvider | Should -Be 'MicrosoftProvided'
        $T = EvalPolicy (LivePolicy -Tel 'Contoso Telecom')
        $T.Summary.TelephonyProvider | Should -Be 'Configured'
        ($T.Findings | Where-Object Key -EQ 'SmsRetirementFebruary').Severity | Should -Be 'Warning'
        (EvalPolicy (Policy)).Summary.TelephonyProvider | Should -Be 'NotDetectable' # property absent
        (EvalPolicy $null).Summary.TelephonyProvider | Should -Be 'unknown'
    }
}

Describe 'Get-CIPPAlertSmsMfaReliance retirement' {
    BeforeAll {
        function Get-CIPPSmsMfaReadiness { param($TenantFilter) $script:Report }
        function Set-RetReport {
            param($Nearest = '2027-02-01', $Days = 80, $Count = 4, [object[]]$Findings = @(), [object[]]$Users = @())
            $script:Report = [pscustomobject]@{ Errors = @(); Findings = $Findings; Users = $Users
                Summary = [pscustomobject]@{ CoveragePercent = $null; UsersEnabled = 10; PhoneOnly = $Count; NearestDeadline = $Nearest; NearestDeadlineDaysRemaining = $Days; NearestDeadlineUsers = $Count
                    PasskeyDynamicMigrationOptOut = 'false'; RegistrationCampaignState = 'enabled'; RegistrationCampaignMethods = 'microsoftAuthenticator'; PasskeyState = 'enabled'
                }
            }
        }
        function RunR { param($InputValue) @(Get-CIPPAlertSmsMfaReliance -TenantFilter 'contoso.com' -InputValue $InputValue | Where-Object { $_ }) }
        $script:AdminRow = [pscustomobject]@{ Key = 'AdminPhoneOnly|ga'; Severity = 'Error'; Check = 'Admin on SMS/voice'; Account = 'ga@contoso.com'; Message = 'm'; Fix = 'f' }
        $script:FebFinding = [pscustomobject]@{ Key = 'SmsRetirementFebruary'; Severity = 'Error'; Check = 'x'; Account = ''; Message = '4 account(s)'; Fix = 'f' }
        $script:GaUser = [pscustomobject]@{ Id = 'ga'; Category = 'PhoneOnly'; IsAdmin = $true; RetirementDate = '2027-07-01'; DaysRemaining = 242 }
    }
    BeforeEach { Reset-AlertStore }

    It 'raises the deadline row inside the default 90-day window, once, while the days count down' {
        Set-RetReport -Days 80
        $First = RunR
        $First.Id | Should -Be @('SmsRetirementDeadline|2027-02-01')
        $First[0].Severity | Should -Be 'Error'
        $First[0].DaysRemaining | Should -Be 80
        Set-RetReport -Days 73 -Count 3
        RunR | Should -BeNullOrEmpty # same Id: a new count or day does not re-notify
    }

    It 'stays quiet outside the window and honours SmsRetirementWarnDays' {
        Set-RetReport -Days 120
        RunR | Should -BeNullOrEmpty
        (RunR -InputValue @{ SmsRetirementWarnDays = 150 }).Id | Should -Be @('SmsRetirementDeadline|2027-02-01')
    }

    It 'resolves the February row and notifies the July date as a new row' {
        Set-RetReport -Days 30; $null = RunR
        Set-RetReport -Nearest '2027-07-01' -Days 60 -Count 1
        $R = RunR
        $R.Id | Should -Be @('SmsRetirementDeadline|2027-07-01')
        $R[0].Severity | Should -Be 'Warning'
        (Get-LifecycleState 'Get-CIPPAlertSmsMfaReliance')['SmsRetirementDeadline|2027-02-01'] | Should -Be 'Resolved'
    }

    It 'does not raise SmsRetirement findings directly, only the deadline row' {
        Set-RetReport -Days 200 -Findings @($script:FebFinding)
        RunR | Should -BeNullOrEmpty
    }

    It 'keeps existing Ids and adds the user retirement date to admin rows without re-notifying' {
        Set-RetReport -Nearest $null -Days $null -Findings @($script:AdminRow) -Users @($script:GaUser)
        $R = RunR
        $R.Id | Should -Be @('AdminPhoneOnly|ga')
        $R[0].RetirementDate | Should -Be '2027-07-01'
        $R[0].DaysRemaining | Should -Be 242
        $Later = $script:GaUser.PSObject.Copy(); $Later.DaysRemaining = 235
        Set-RetReport -Nearest $null -Days $null -Findings @($script:AdminRow) -Users @($Later)
        RunR | Should -BeNullOrEmpty
    }
}
