# Aspendora fork (Vikunja CIPP-7): phishing-resistant MFA for admins - rules, collector and alert.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PhishResistant/Test-CIPPPhishResistantPosture.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PhishResistant/Get-CIPPPhishResistantPosture.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertPhishResistantAdmins.ps1')
    $script:GA = '62e90394-69f5-4237-9190-012177145e10'
    $script:Exchange = '29232cdf-9323-42fd-ade2-1d097af3e4de'
    $script:Helpdesk = '729827e3-9c14-49f7-bb1b-9608f156bbb8'
    function Holder {
        param($Id, $Role = $script:GA, $Kind = 'Active', $Methods = @('passKeyDeviceBound'), $Lic = 0, $Mail = $null, $Enabled = $true)
        [pscustomobject]@{ Id = $Id; UserPrincipalName = "$Id@contoso.com"; DisplayName = $Id; AccountEnabled = $Enabled; Mail = $Mail; LicenseCount = $Lic
            Roles = @([pscustomobject]@{ RoleTemplateId = $Role; Kind = $Kind; Via = 'Direct' }); Methods = $Methods }
    }
    function GoodPolicy {
        [pscustomobject]@{
            registrationEnforcement            = @{ authenticationMethodsRegistrationCampaign = @{ state = 'enabled'; includeTargets = @(@{ id = 'all_users'; targetedAuthenticationMethod = 'microsoftAuthenticator' }); excludeTargets = @() } }
            authenticationMethodConfigurations = @([pscustomobject]@{ id = 'Fido2'; state = 'enabled'; isSelfServiceRegistrationAllowed = $true
                    keyRestrictions = @{ isEnforced = $false; enforcementType = 'block'; aaGuids = @() }; includeTargets = @(@{ id = 'all_users' })
                    passkeyProfiles = @(@{ name = 'Default passkey profile'; keyRestrictions = @{ isEnforced = $false; enforcementType = 'block'; aaGuids = @() } }) })
        }
    }
    # Registration report readable (empty) unless a test passes its own.
    function Check { param($Params) if (-not $Params.ContainsKey('Registrations')) { $Params.Registrations = @() }; Test-CIPPPhishResistantPosture @Params }
}

Describe 'Test-CIPPPhishResistantPosture' {
    It 'is clean for two GAs and a helpdesk admin with phishing-resistant methods and a good policy' {
        $R = Check @{ Holders = @((Holder 'ga1'), (Holder 'ga2' -Methods @('windowsHelloForBusiness')), (Holder 'hd' $script:Helpdesk -Methods @('passKeySynced'))); Policy = (GoodPolicy) }
        $R.Findings | Should -BeNullOrEmpty
        $R.Summary.AdminsTotal | Should -Be 3
        $R.Summary.AdminsPhishingResistant | Should -Be 3
        $R.Summary.GlobalAdmins | Should -Be 2
        @($R.Admins.PhishingResistant | Select-Object -Unique) | Should -Be @('Yes')
    }

    It 'errors for a GA without phishing-resistant MFA and warns for other roles' {
        $R = Check @{ Holders = @((Holder 'ga1'), (Holder 'ga2' -Methods @('microsoftAuthenticatorPush', 'mobilePhone')), (Holder 'ex' $script:Exchange -Methods @('softwareOneTimePasscode'))); Policy = (GoodPolicy) }
        ($R.Findings | Where-Object Key -EQ 'NoPhishRes|ga2').Severity | Should -Be 'Error'
        ($R.Findings | Where-Object Key -EQ 'NoPhishRes|ex').Severity | Should -Be 'Warning'
        ($R.Admins | Where-Object Id -EQ 'ga2').PhishingResistant | Should -Be 'No'
        $R.Admins[0].PhishingResistant | Should -Be 'No' # sorted: worst first
        $R.Summary.AdminsWithoutPhishingResistant | Should -Be 2
    }

    It 'reads methods from the registration report by id and counts tenant users' {
        $Regs = @(
            [pscustomobject]@{ id = 'ga1'; userType = 'member'; methodsRegistered = @('passKeyDeviceBoundAuthenticator') }
            [pscustomobject]@{ id = 'ga2'; userType = 'member'; methodsRegistered = @('mobilePhone') }
            [pscustomobject]@{ id = 'u1'; userType = 'member'; methodsRegistered = @() }
            [pscustomobject]@{ id = 'g1'; userType = 'guest'; methodsRegistered = @('fido2') }
        )
        $H1 = Holder 'ga1'; $H1.PSObject.Properties.Remove('Methods')
        $H2 = Holder 'ga2'; $H2.Methods = $null
        $R = Check @{ Holders = @($H1, $H2); Registrations = $Regs; Policy = (GoodPolicy) }
        $R.Findings.Key | Should -Be @('NoPhishRes|ga2')
        $R.Summary.UsersTotal | Should -Be 3
        $R.Summary.UsersPhishingResistant | Should -Be 1
    }

    It 'reports unknown methods as Info, not as a missing method' {
        $H = Holder 'ga2'; $H.Methods = $null
        $R = Test-CIPPPhishResistantPosture -Holders @((Holder 'ga1'), $H) -Policy (GoodPolicy) # no registration report
        $R.Findings.Key | Should -Be @('RegistrationUnknown', 'MethodsUnknown|ga2')
        ($R.Admins | Where-Object Id -EQ 'ga2').PhishingResistant | Should -Be 'Unknown'
        $R.Summary.UsersTotal | Should -BeNullOrEmpty
        @($R.Findings | Where-Object Severity -NE 'Info') | Should -BeNullOrEmpty
    }

    It 'treats an empty method list as no methods, not unknown' {
        $R = Check @{ Holders = @((Holder 'ga1'), (Holder 'ga2' -Methods @())); Policy = (GoodPolicy) }
        $R.Findings.Key | Should -Be @('NoPhishRes|ga2')
        $R.Findings[0].Message | Should -Match 'no MFA methods registered'
    }

    It 'accepts the authentication/methods @odata.type fallback names' {
        $R = Check @{ Holders = @((Holder 'ga1' -Methods @('#microsoft.graph.fido2AuthenticationMethod')), (Holder 'ga2' -Methods @('#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'))); Policy = (GoodPolicy) }
        @($R.Findings | Where-Object Severity -NE 'Info') | Should -BeNullOrEmpty
    }

    It 'requires a passkey (not Windows Hello) for a break-glass account' {
        $R = Check @{ Holders = @((Holder 'ga1'), (Holder 'bg' -Methods @('windowsHelloForBusiness'))); BreakGlassIds = @('bg'); Policy = (GoodPolicy) }
        $F = $R.Findings | Where-Object Key -EQ 'NoPhishRes|bg'
        $F.Severity | Should -Be 'Error'
        $F.Message | Should -Match 'Break-glass'
        $R2 = Check @{ Holders = @((Holder 'ga1'), (Holder 'bg' -Methods @('passKeyDeviceBound'))); BreakGlassIds = @('bg'); Policy = (GoodPolicy) }
        $R2.Findings | Should -BeNullOrEmpty
        ($R2.Admins | Where-Object Id -EQ 'bg').BreakGlass | Should -BeTrue
    }

    It 'warns when an admin account is licensed or mail-enabled, not for guests' {
        $G = Holder 'guest' $script:Exchange -Mail 'x@partner.com'; $G.UserPrincipalName = 'x_partner.com#EXT#@contoso.onmicrosoft.com'
        $R = Check @{ Holders = @((Holder 'ga1' -Lic 2), (Holder 'ga2' -Mail 'ga2@contoso.com'), $G); Policy = (GoodPolicy) }
        $R.Findings.Key | Should -Be @('DailyUse|ga1', 'DailyUse|ga2')
        @($R.Findings.Severity) | Should -Be @('Warning', 'Info') # mail address without a mailbox licence is only Info
        $R.Summary.AdminsAlsoDailyUse | Should -Be 1
    }

    It 'does not count identity-only licences (Entra ID P2 for PIM) as daily use' {
        $P2 = Holder 'ga1'; $P2 | Add-Member SkuIds @('84A661C4-E949-4BD2-A560-ED7766FCAF2B')
        $E3 = Holder 'ga2'; $E3 | Add-Member SkuIds @('84a661c4-e949-4bd2-a560-ed7766fcaf2b', '05e9a617-0261-4cee-bb44-138d3ef5d965')
        $R = Check @{ Holders = @($P2, $E3); Policy = (GoodPolicy) }
        $R.Findings.Key | Should -Be @('DailyUse|ga2')
        $R.Findings[0].Message | Should -Match '1 mailbox/productivity licence'
        ($R.Admins | Where-Object Id -EQ 'ga1').Licensed | Should -BeFalse
    }

    It 'flags a GA count below 2 or above 4, counting eligible and break-glass, ignoring disabled accounts' {
        (Check @{ Holders = @(Holder 'ga1'); Policy = (GoodPolicy) }).Findings.Key | Should -Be @('GaCount|Low')
        $Five = @(1..4 | ForEach-Object { Holder "ga$_" }) + @(Holder 'ga5' -Kind 'Eligible')
        (Check @{ Holders = $Five; Policy = (GoodPolicy) }).Findings.Key | Should -Be @('GaCount|High')
        $FourPlusDisabled = @(1..4 | ForEach-Object { Holder "ga$_" }) + @(Holder 'old' -Enabled $false -Methods @())
        (Check @{ Holders = $FourPlusDisabled; Policy = (GoodPolicy) }).Findings | Should -BeNullOrEmpty
    }

    It 'notes when PIM eligibility could not be read' {
        $R = Check @{ Holders = @((Holder 'ga1'), (Holder 'ga2')); Policy = (GoodPolicy); EligibleKnown = $false }
        $R.Findings.Key | Should -Be @('EligibleUnknown')
        $R.Summary.EligibleKnown | Should -BeFalse
    }

    It 'warns when passkeys are disabled or not self-service, and notes group scoping' {
        $P = GoodPolicy; $P.authenticationMethodConfigurations[0].state = 'disabled'
        (Check @{ Holders = @((Holder 'ga1'), (Holder 'ga2')); Policy = $P }).Findings.Key | Should -Be @('PasskeysDisabled')
        $P = GoodPolicy; $P.authenticationMethodConfigurations[0].isSelfServiceRegistrationAllowed = $false; $P.authenticationMethodConfigurations[0].includeTargets = @(@{ id = 'grp1' })
        $Keys = (Check @{ Holders = @((Holder 'ga1'), (Holder 'ga2')); Policy = $P }).Findings.Key
        $Keys | Should -Contain 'PasskeySelfServiceOff'
        $Keys | Should -Contain 'PasskeysScoped'
    }

    It 'warns when an enforced AAGUID allow list leaves out Microsoft Authenticator, on the method or a passkey profile' {
        $P = GoodPolicy
        $P.authenticationMethodConfigurations[0].keyRestrictions = @{ isEnforced = $true; enforcementType = 'allow'; aaGuids = @('cb69481e-8ff7-4039-93ec-0a2729a154a8', 'DE1E552D-DB1D-4423-A619-566B625CDC84') }
        $F = @((Check @{ Holders = @((Holder 'ga1'), (Holder 'ga2')); Policy = $P }).Findings)
        $F.Key | Should -Be @('AaguidBlocksAuthenticator|Passkey (FIDO2) policy')
        $F[0].Message | Should -Match 'iOS 90a3ccdf'
        $F[0].Message | Should -Not -Match 'Android'

        $P = GoodPolicy
        $P.authenticationMethodConfigurations[0].passkeyProfiles[0].keyRestrictions = @{ isEnforced = $true; enforcementType = 'block'; aaGuids = @('90a3ccdf-635c-4729-a248-9b709135078f') }
        (Check @{ Holders = @((Holder 'ga1'), (Holder 'ga2')); Policy = $P }).Findings.Key | Should -Be @("AaguidBlocksAuthenticator|passkey profile 'Default passkey profile'")

        $P = GoodPolicy
        $P.authenticationMethodConfigurations[0].keyRestrictions = @{ isEnforced = $true; enforcementType = 'allow'; aaGuids = @('de1e552d-db1d-4423-a619-566b625cdc84', '90a3ccdf-635c-4729-a248-9b709135078f') }
        (Check @{ Holders = @((Holder 'ga1'), (Holder 'ga2')); Policy = $P }).Findings | Should -BeNullOrEmpty
    }

    It 'notes a disabled registration campaign and summarises its targets' {
        $P = GoodPolicy; $P.registrationEnforcement.authenticationMethodsRegistrationCampaign.state = 'disabled'
        $R = Check @{ Holders = @((Holder 'ga1'), (Holder 'ga2')); Policy = $P }
        $R.Findings.Key | Should -Be @('CampaignDisabled')
        $R.Findings[0].Severity | Should -Be 'Info'
        $R.Summary.RegistrationCampaign.Targets | Should -Be 'all_users -> microsoftAuthenticator'
    }
}

Describe 'Get-CIPPPhishResistantPosture' {
    BeforeAll {
        function New-GraphGetRequest { param($uri, $tenantid) }
        function Get-CippException { param($Exception) [pscustomobject]@{ NormalizedError = $Exception.Exception.Message } }
        function Get-CIPPBreakGlassAccounts { param($TenantFilter) }
    }
    BeforeEach {
        Mock Get-CIPPBreakGlassAccounts { @([pscustomobject]@{ RowKey = 'bg' }) }
        Mock New-GraphGetRequest {
            switch -Regex ($uri) {
                'userRegistrationDetails' { return @(
                        [pscustomobject]@{ id = 'ga1'; userType = 'member'; methodsRegistered = @('passKeyDeviceBound') }
                        [pscustomobject]@{ id = 'bg'; userType = 'member'; methodsRegistered = @('passKeySynced') }
                        [pscustomobject]@{ id = 'm1'; userType = 'member'; methodsRegistered = @('mobilePhone') }
                    ) }
                'roleAssignments' { return @(
                        [pscustomobject]@{ roleDefinitionId = $script:GA; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'ga1'; userPrincipalName = 'ga1@contoso.com'; accountEnabled = $true; assignedLicenses = @() } }
                        [pscustomobject]@{ roleDefinitionId = $script:GA; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'bg'; userPrincipalName = 'bg@contoso.onmicrosoft.com'; accountEnabled = $true; assignedLicenses = @() } }
                        [pscustomobject]@{ roleDefinitionId = $script:Exchange; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.group'; id = 'grp'; displayName = 'Role-Exchange' } }
                        [pscustomobject]@{ roleDefinitionId = $script:GA; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = 'sp1' } }
                        [pscustomobject]@{ roleDefinitionId = '88d8e3e3-8f55-4a1e-953a-9b9898b8876b'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'reader'; assignedLicenses = @() } }
                    ) }
                'groups/grp/transitiveMembers' { return @([pscustomobject]@{ id = 'm1'; userPrincipalName = 'm1@contoso.com'; mail = 'm1@contoso.com'; accountEnabled = $true; assignedLicenses = @(@{ skuId = 'x' }) }) }
                'roleEligibilitySchedules' { throw 'The tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID Governance license.' }
                'authenticationMethodsPolicy' { return (GoodPolicy) }
                default { throw "unexpected $uri" }
            }
        }
    }

    It 'collects active holders, expands groups, skips service principals and non-privileged roles, degrades without P2' {
        $R = Get-CIPPPhishResistantPosture -TenantFilter 'contoso.com'
        $R.Errors | Should -BeNullOrEmpty
        @($R.Admins.Id | Sort-Object) | Should -Be @('bg', 'ga1', 'm1')
        ($R.Admins | Where-Object Id -EQ 'm1').Via | Should -Be 'Group: Role-Exchange'
        $R.Summary.EligibleKnown | Should -BeFalse
        $Keys = $R.Findings.Key
        $Keys | Should -Contain 'NoPhishRes|m1'
        $Keys | Should -Contain 'DailyUse|m1'
        $Keys | Should -Contain 'EligibleUnknown'
        $Keys | Should -Not -Contain 'NoPhishRes|bg'
        $R.Summary.GlobalAdmins | Should -Be 2
    }

    It 'records an error when role assignments cannot be read' {
        Mock New-GraphGetRequest { if ($uri -match 'roleAssignments') { throw 'Forbidden' } elseif ($uri -match 'authenticationMethodsPolicy') { GoodPolicy } else { @() } }
        $R = Get-CIPPPhishResistantPosture -TenantFilter 'contoso.com'
        $R.Errors | Should -Match 'Active role assignments'
    }

    It 'falls back to per-user methods when the registration report is unavailable' {
        Mock New-GraphGetRequest {
            switch -Regex ($uri) {
                'userRegistrationDetails' { throw 'Tenant does not have premium license' }
                'roleAssignments' { return @([pscustomobject]@{ roleDefinitionId = $script:GA; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'ga1'; userPrincipalName = 'ga1@contoso.com'; accountEnabled = $true; assignedLicenses = @() } }) }
                'roleEligibilitySchedules' { return @([pscustomobject]@{ roleDefinitionId = $script:GA; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'ga2'; userPrincipalName = 'ga2@contoso.com' } }) }
                'users/ga2\?' { return [pscustomobject]@{ id = 'ga2'; userPrincipalName = 'ga2@contoso.com'; accountEnabled = $true; mail = $null; assignedLicenses = @() } }
                'users/ga1/authentication/methods' { return @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod' }, [pscustomobject]@{ '@odata.type' = '#microsoft.graph.fido2AuthenticationMethod' }) }
                'users/ga2/authentication/methods' { return @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod' }, [pscustomobject]@{ '@odata.type' = '#microsoft.graph.phoneAuthenticationMethod' }) }
                'authenticationMethodsPolicy' { return (GoodPolicy) }
                default { throw "unexpected $uri" }
            }
        }
        $R = Get-CIPPPhishResistantPosture -TenantFilter 'contoso.com'
        $R.Errors | Should -BeNullOrEmpty
        $R.Summary.UsersTotal | Should -BeNullOrEmpty
        ($R.Admins | Where-Object Id -EQ 'ga2').Assignment | Should -Be 'Eligible'
        ($R.Admins | Where-Object Id -EQ 'ga2').Methods | Should -Be 'phone'
        $R.Findings.Key | Should -Contain 'NoPhishRes|ga2'
        $R.Findings.Key | Should -Contain 'RegistrationUnknown'
        $R.Findings.Key | Should -Not -Contain 'NoPhishRes|ga1'
    }
}

Describe 'Get-CIPPAlertPhishResistantAdmins' {
    BeforeAll {
        function Write-AlertTrace { param($cmdletName, $tenantFilter, $data) }
        function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData) }
        function Get-CippException { param($Exception) [pscustomobject]@{ NormalizedError = "$Exception" } }
    }
    It 'sends Error and Warning findings only' {
        Mock Get-CIPPPhishResistantPosture { [pscustomobject]@{ Errors = @(); Findings = @(
                    [pscustomobject]@{ Key = 'NoPhishRes|a'; Severity = 'Error'; Check = 'c'; Account = 'a'; Message = 'm'; Fix = 'f' }
                    [pscustomobject]@{ Key = 'CampaignDisabled'; Severity = 'Info'; Check = 'c'; Account = ''; Message = 'm'; Fix = 'f' }) } }
        Mock Write-AlertTrace {}
        Get-CIPPAlertPhishResistantAdmins -TenantFilter 'contoso.com'
        Should -Invoke Write-AlertTrace -Times 1 -ParameterFilter { @($data).Count -eq 1 -and $data[0].Key -eq 'NoPhishRes|a' -and $cmdletName -eq 'Get-CIPPAlertPhishResistantAdmins' }
    }
    It 'does not report when anything could not be read' {
        Mock Get-CIPPPhishResistantPosture { [pscustomobject]@{ Errors = @('Active role assignments: Forbidden'); Findings = @() } }
        Mock Write-AlertTrace {}
        Mock Write-LogMessage {}
        Get-CIPPAlertPhishResistantAdmins -TenantFilter 'contoso.com'
        Should -Invoke Write-AlertTrace -Times 0
        Should -Invoke Write-LogMessage -Times 1
    }
}
