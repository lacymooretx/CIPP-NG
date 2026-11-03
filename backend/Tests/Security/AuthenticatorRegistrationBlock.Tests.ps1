# Pester tests for Get-CIPPCARegistrationBlock, Test-CIPPCAGapAuthenticatorRegistration (Vikunja CIPP-53) and the
# 'CA would block registration' field on the SMS/voice readiness report (CIPP-46).
# The grant and strength shapes are from a live v1.0 conditionalAccess/policies read in aspendora.com, 2026-11-03.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $CaFolder = Join-Path $RepoRoot 'Modules/CIPPCore/Public/SecuritySimulations/CAAnalysis'
    . (Join-Path $CaFolder 'ConvertTo-CIPPCANormalizedPolicy.ps1')
    . (Join-Path $CaFolder 'New-CIPPCAGapFinding.ps1')
    . (Join-Path $CaFolder 'Get-CIPPCARegistrationBlock.ps1')
    . (Join-Path $CaFolder 'Test-CIPPCAGapAuthenticatorRegistration.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/SmsMfa/Test-CIPPSmsMfaReadiness.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/SmsMfa/Get-CIPPSmsMfaReadiness.ps1')

    $script:App = '6aa00308-ea33-4caa-90d6-ae905d8cb51b'
    $script:RoleGa = '62e90394-69f5-4237-9190-012177145e10'
    $script:PhishResistant = [pscustomobject]@{ id = '00000000-0000-0000-0000-000000000004'; displayName = 'Phishing-resistant MFA'; allowedCombinations = @('windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor') }
    $script:Multifactor = [pscustomobject]@{ id = '00000000-0000-0000-0000-000000000002'; displayName = 'Multifactor authentication'; allowedCombinations = @('windowsHelloForBusiness', 'fido2', 'temporaryAccessPassOneTime', 'password,sms') }

    function New-CaPolicy {
        param(
            [string]$Name = 'Policy', [string]$State = 'enabled', [string[]]$Controls = @(), [string]$Operator = 'OR', $Strength,
            [string[]]$Include = @('All'), [string[]]$Exclude = @(), [string[]]$UserActions = @(),
            [string[]]$IncludeUsers = @('All'), [string[]]$Roles = @(), [string[]]$Groups = @(), [string[]]$ExcludeUsers = @(),
            $Platforms = $null, [string[]]$ClientAppTypes = @('all'), [switch]$NoGrant
        )
        [pscustomobject]@{
            id            = "id-$Name"
            displayName   = $Name
            state         = $State
            conditions    = [pscustomobject]@{
                users          = [pscustomobject]@{ includeUsers = $IncludeUsers; excludeUsers = $ExcludeUsers; includeGroups = $Groups; excludeGroups = @(); includeRoles = $Roles; excludeRoles = @() }
                applications   = [pscustomobject]@{ includeApplications = $Include; excludeApplications = $Exclude; includeUserActions = $UserActions }
                clientAppTypes = $ClientAppTypes
                platforms      = $Platforms
            }
            grantControls = $(if ($NoGrant) { $null } else { [pscustomobject]@{ operator = $Operator; builtInControls = $Controls; customAuthenticationFactors = @(); termsOfUse = @(); authenticationStrength = $Strength } })
        }
    }
    function New-AdminPhishPolicy {
        param([string]$Name = 'Admins PR', [string]$State = 'enabled', [string[]]$Exclude = @())
        New-CaPolicy -Name $Name -State $State -Strength $script:PhishResistant -IncludeUsers @() -Roles @($script:RoleGa) -Exclude $Exclude
    }
    function New-GapContext {
        param([object[]]$RawPolicies = @())
        $Normalized = @($RawPolicies | ForEach-Object { ConvertTo-CIPPCANormalizedPolicy -Policy $_ })
        @{ Policies = $Normalized; AuthStrengths = @{} }
    }
    function New-RegRow { param($Id, [string[]]$Methods = @('mobilePhone'), [switch]$Admin) [pscustomobject]@{ id = $Id; userPrincipalName = "$Id@contoso.com"; userDisplayName = $Id; userType = 'member'; isAdmin = [bool]$Admin; methodsRegistered = $Methods; defaultMfaMethod = 'none'; userPreferredMethodForSecondaryAuthentication = 'none'; systemPreferredAuthenticationMethods = @(); isSystemPreferredAuthenticationMethodEnabled = $false } }
    function New-UserRow { param($Id) [pscustomobject]@{ id = $Id; accountEnabled = $true; userType = 'Member'; assignedLicenses = @(@{ skuId = 'x' }) } }
}

Describe 'Get-CIPPCARegistrationBlock' {
    It 'matches pattern 1 and separates enforced from report-only' {
        $B = Get-CIPPCARegistrationBlock -Policies @((New-AdminPhishPolicy -Name 'Enforced'), (New-AdminPhishPolicy -Name 'Report' -State 'enabledForReportingButNotEnforced'))
        $B.CaWouldBlock | Should -Be 'Yes'
        @($B.Enforced.DisplayName) | Should -Be @('Enforced')
        @($B.ReportOnly.DisplayName) | Should -Be @('Report')
        $B.Enforced[0].UserScope | Should -Be 'AdminRoles'
        $B.Enforced[0].Pattern | Should -Match 'Phishing-resistant'
    }

    It 'says ReportOnly when only report-only policies match' {
        (Get-CIPPCARegistrationBlock -Policies @((New-AdminPhishPolicy -State 'enabledForReportingButNotEnforced'))).CaWouldBlock | Should -Be 'ReportOnly'
    }

    It 'matches pattern 2 for both approved client app and app protection' {
        $B = Get-CIPPCARegistrationBlock -Policies @((New-CaPolicy -Name 'Approved' -Controls @('approvedApplication')), (New-CaPolicy -Name 'Protect' -Controls @('compliantApplication')), (New-CaPolicy -Name 'Either' -Controls @('approvedApplication', 'compliantApplication')))
        @($B.Enforced.DisplayName) | Should -Be @('Approved', 'Protect', 'Either')
        $B.Enforced[0].UserScope | Should -Be 'AllUsers'
    }

    It 'does not match ordinary policies, or an empty grant' {
        $Policies = @(
            (New-CaPolicy -Name 'MFA' -Controls @('mfa'))
            (New-CaPolicy -Name 'Block' -Controls @('block'))
            (New-CaPolicy -Name 'Compliant' -Controls @('compliantDevice'))
            (New-CaPolicy -Name 'Session' -NoGrant)
            (New-CaPolicy -Name 'MFA strength' -Strength $script:Multifactor)
        )
        $B = Get-CIPPCARegistrationBlock -Policies $Policies
        $B.CaWouldBlock | Should -Be 'No'
        $B.Enforced.Count | Should -Be 0
    }

    It 'does not match a specific-app policy, like the approved apps policy on Office365' {
        (Get-CIPPCARegistrationBlock -Policies @((New-CaPolicy -Include @('Office365') -Controls @('approvedApplication')))).CaWouldBlock | Should -Be 'No'
    }

    It 'ignores disabled policies' {
        (Get-CIPPCARegistrationBlock -Policies @((New-AdminPhishPolicy -State 'disabled'))).CaWouldBlock | Should -Be 'No'
    }

    It 'moves a policy that already excludes the app to AlreadyExcluded' {
        $B = Get-CIPPCARegistrationBlock -Policies @((New-AdminPhishPolicy -Exclude @($script:App)))
        $B.CaWouldBlock | Should -Be 'No'
        $B.AlreadyExcluded.Count | Should -Be 1
    }

    It 'does not treat the old undocumented exclusion as a fix' {
        (Get-CIPPCARegistrationBlock -Policies @((New-AdminPhishPolicy -Exclude @('ea890292-c8c8-4433-b5ea-b09d0668e1a6')))).CaWouldBlock | Should -Be 'Yes'
    }

    It 'sees an OR with something the user can meet as Mitigated, and an AND as blocking' {
        $B = Get-CIPPCARegistrationBlock -Policies @(
            (New-CaPolicy -Name 'Or MFA' -Controls @('approvedApplication', 'mfa'))
            (New-CaPolicy -Name 'Or compliant' -Controls @('compliantApplication', 'compliantDevice'))
            (New-CaPolicy -Name 'Strength or compliant' -Controls @('compliantDevice') -Strength $script:PhishResistant)
            (New-CaPolicy -Name 'And MFA' -Controls @('approvedApplication', 'mfa') -Operator 'AND')
            (New-CaPolicy -Name 'Or hybrid' -Controls @('approvedApplication', 'domainJoinedDevice'))
        )
        @($B.Mitigated.DisplayName) | Should -Be @('Or MFA', 'Or compliant', 'Strength or compliant')
        @($B.Enforced.DisplayName) | Should -Be @('And MFA', 'Or hybrid')
    }

    It 'judges a custom strength by its combinations: all phishing-resistant blocks, a TAP does not' {
        $Strict = [pscustomobject]@{ id = 'custom-1'; displayName = 'Keys only'; allowedCombinations = @('fido2') }
        $WithTap = [pscustomobject]@{ id = 'custom-2'; displayName = 'Phishing-resistant plus TAP'; allowedCombinations = @('fido2', 'temporaryAccessPassOneTime') }
        $B = Get-CIPPCARegistrationBlock -Policies @((New-CaPolicy -Name 'Strict' -Strength $Strict), (New-CaPolicy -Name 'Tap' -Strength $WithTap))
        @($B.Enforced.DisplayName) | Should -Be @('Strict')
    }

    It 'looks up combinations when the grant only carries an id, and reports what it cannot judge' {
        $IdOnly = [pscustomobject]@{ id = 'custom-1' }
        $Known = Get-CIPPCARegistrationBlock -Policies @((New-CaPolicy -Strength $IdOnly)) -AuthStrengths @{ 'custom-1' = [pscustomobject]@{ allowedCombinations = @('fido2') } }
        $Known.CaWouldBlock | Should -Be 'Yes'
        $Unknown = Get-CIPPCARegistrationBlock -Policies @((New-CaPolicy -Strength $IdOnly))
        $Unknown.CaWouldBlock | Should -Be 'Unknown'
        $Unknown.Unverified.Count | Should -Be 1
    }

    It 'knows the built-in strength by id alone, as the template stores it' {
        (Get-CIPPCARegistrationBlock -Policies @((New-CaPolicy -Strength ([pscustomobject]@{ id = '00000000-0000-0000-0000-000000000004' })))).CaWouldBlock | Should -Be 'Yes'
    }

    It 'skips policies that cannot apply to Authenticator on a phone' {
        $Windows = [pscustomobject]@{ includePlatforms = @('windows'); excludePlatforms = @() }
        $NotPhones = [pscustomobject]@{ includePlatforms = @('all'); excludePlatforms = @('android', 'iOS') }
        $B = Get-CIPPCARegistrationBlock -Policies @(
            (New-CaPolicy -Name 'Windows' -Controls @('approvedApplication') -Platforms $Windows)
            (New-CaPolicy -Name 'NotPhones' -Controls @('approvedApplication') -Platforms $NotPhones)
            (New-CaPolicy -Name 'Legacy' -Controls @('approvedApplication') -ClientAppTypes @('exchangeActiveSync', 'other'))
            (New-CaPolicy -Name 'Nobody' -Controls @('approvedApplication') -IncludeUsers @('None'))
        )
        $B.CaWouldBlock | Should -Be 'No'
    }

    It 'still matches when one phone platform is reachable' {
        $Ios = [pscustomobject]@{ includePlatforms = @('all'); excludePlatforms = @('android') }
        (Get-CIPPCARegistrationBlock -Policies @((New-CaPolicy -Controls @('approvedApplication') -Platforms $Ios))).CaWouldBlock | Should -Be 'Yes'
    }

    It 'calls a group-targeted policy Targeted' {
        (Get-CIPPCARegistrationBlock -Policies @((New-CaPolicy -Controls @('approvedApplication') -IncludeUsers @() -Groups @('g')))).Enforced[0].UserScope | Should -Be 'Targeted'
    }

    It 'reports the Register security info policy state, and does not count a disabled one' {
        $Rsi = { param($State) New-CaPolicy -Name "RSI $State" -State $State -Include @() -UserActions @('urn:user:registersecurityinfo') -Controls @('mfa') }
        (Get-CIPPCARegistrationBlock -Policies @()).RegisterSecurityInfoPolicy | Should -Be 'Missing'
        (Get-CIPPCARegistrationBlock -Policies @((& $Rsi 'disabled'))).RegisterSecurityInfoPolicy | Should -Be 'Missing'
        (Get-CIPPCARegistrationBlock -Policies @((& $Rsi 'enabledForReportingButNotEnforced'))).RegisterSecurityInfoPolicy | Should -Be 'ReportOnly'
        $Both = Get-CIPPCARegistrationBlock -Policies @((& $Rsi 'enabledForReportingButNotEnforced'), (& $Rsi 'enabled'))
        $Both.RegisterSecurityInfoPolicy | Should -Be 'Enforced'
        @($Both.RegisterSecurityInfoPolicies).Count | Should -Be 2
    }

    It 'reads the CIPP-7 template in the repo as matching until the exclusion, and as excluded with it' {
        $Template = Get-Content (Join-Path (Split-Path -Parent $RepoRoot) 'docs/ca-templates/cipp7-phishres-admins.json') -Raw | ConvertFrom-Json -Depth 20
        @($Template.conditions.applications.excludeApplications) | Should -Be @($script:App)
        $B = Get-CIPPCARegistrationBlock -Policies @($Template)
        $B.AlreadyExcluded.Count | Should -Be 1
        $B.ReportOnly.Count | Should -Be 0
        $Template.conditions.applications.excludeApplications = @()
        (Get-CIPPCARegistrationBlock -Policies @($Template)).ReportOnly.Count | Should -Be 1
    }
}

Describe 'Test-CIPPCAGapAuthenticatorRegistration' {
    It 'is in the gap analysis check list' {
        Get-Content (Join-Path $CaFolder 'Get-CIPPCAGapAnalysis.ps1') -Raw | Should -Match "'Test-CIPPCAGapAuthenticatorRegistration'"
    }

    It 'rates an all-users enforced match High, and one scoped to admin roles Medium' {
        $All = @(Test-CIPPCAGapAuthenticatorRegistration -Context (New-GapContext @((New-CaPolicy -Controls @('approvedApplication'))))) | Where-Object title -Match 'enforced policy'
        $All.severity | Should -Be 'High'
        $Admin = @(Test-CIPPCAGapAuthenticatorRegistration -Context (New-GapContext @((New-AdminPhishPolicy)))) | Where-Object title -Match 'enforced policy'
        $Admin.severity | Should -Be 'Medium'
        @($Admin.affectedPolicies) | Should -Be @('Admins PR')
        $Admin.description | Should -Match 'admin roles only'
    }

    It 'keeps report-only separate from enforced' {
        $Findings = @(Test-CIPPCAGapAuthenticatorRegistration -Context (New-GapContext @((New-AdminPhishPolicy -Name 'On'), (New-AdminPhishPolicy -Name 'Off' -State 'enabledForReportingButNotEnforced'))))
        @(($Findings | Where-Object title -Match '^1 enforced').affectedPolicies) | Should -Be @('On')
        @(($Findings | Where-Object title -Match 'report-only policy').affectedPolicies) | Should -Be @('Off')
        ($Findings | Where-Object title -Match 'report-only policy').severity | Should -Be 'Medium'
    }

    It 'flags a missing Register security info policy as Medium where it matters' {
        foreach ($Policy in @((New-AdminPhishPolicy), (New-AdminPhishPolicy -State 'enabledForReportingButNotEnforced'), (New-AdminPhishPolicy -Exclude @($script:App)))) {
            $Finding = @(Test-CIPPCAGapAuthenticatorRegistration -Context (New-GapContext @($Policy))) | Where-Object title -Match 'registering security info'
            $Finding.severity | Should -Be 'Medium'
        }
    }

    It 'keeps a missing Register security info policy at Low when nothing matches, so the analysis hides it' {
        $Findings = @(Test-CIPPCAGapAuthenticatorRegistration -Context (New-GapContext @((New-CaPolicy -Controls @('mfa')))))
        $Findings.Count | Should -Be 1
        $Findings[0].severity | Should -Be 'Low'
    }

    It 'says nothing when the app is excluded and Register security info is enforced' {
        $Rsi = New-CaPolicy -Name 'RSI' -Include @() -UserActions @('urn:user:registersecurityinfo') -Controls @('mfa')
        @(Test-CIPPCAGapAuthenticatorRegistration -Context (New-GapContext @((New-AdminPhishPolicy -Exclude @($script:App)), $Rsi))).Count | Should -Be 0
    }

    It 'flags a report-only Register security info policy as not enforcing' {
        $Rsi = New-CaPolicy -Name 'RSI' -State 'enabledForReportingButNotEnforced' -Include @() -UserActions @('urn:user:registersecurityinfo') -Controls @('mfa')
        $Finding = @(Test-CIPPCAGapAuthenticatorRegistration -Context (New-GapContext @((New-AdminPhishPolicy -Exclude @($script:App)), $Rsi)))
        $Finding.Count | Should -Be 1
        $Finding[0].description | Should -Match 'report-only'
    }

    It 'surfaces a strength it could not judge' {
        $Finding = @(Test-CIPPCAGapAuthenticatorRegistration -Context (New-GapContext @((New-CaPolicy -Name 'Custom' -Strength ([pscustomobject]@{ id = 'custom-9' }))))) | Where-Object title -Match 'Could not tell'
        @($Finding.affectedPolicies) | Should -Be @('Custom')
    }
}

Describe 'SMS/voice readiness: CA would block registration' {
    BeforeAll {
        $script:Regs = @((New-RegRow 'admin1' -Admin), (New-RegRow 'user1'), (New-RegRow 'ok1' -Methods @('microsoftAuthenticatorPush')))
        $script:Users = @((New-UserRow 'admin1'), (New-UserRow 'user1'), (New-UserRow 'ok1'))
    }

    It 'is Unknown, with no finding, when Conditional Access was not read' {
        $R = Test-CIPPSmsMfaReadiness -Registrations $script:Regs -Users $script:Users
        $R.Summary.CaWouldBlockRegistration | Should -Be 'Unknown'
        $R.Summary.RegisterSecurityInfoPolicy | Should -Be 'Unknown'
        $R.Summary.CaBlockPhoneOnlyUsers | Should -Be 0
        @($R.Findings | Where-Object Key -Match 'SmsRetirementCa').Count | Should -Be 0
    }

    It 'is No, with no finding, when nothing matches' {
        $R = Test-CIPPSmsMfaReadiness -Registrations $script:Regs -Users $script:Users -RegistrationBlock (Get-CIPPCARegistrationBlock -Policies @((New-CaPolicy -Controls @('mfa'))))
        $R.Summary.CaWouldBlockRegistration | Should -Be 'No'
        $R.Summary.RegisterSecurityInfoPolicy | Should -Be 'Missing'
        @($R.Findings | Where-Object Key -Match 'SmsRetirementCa').Count | Should -Be 0
    }

    It 'counts only phone-only admins for an admin-role policy, and warns' {
        $R = Test-CIPPSmsMfaReadiness -Registrations $script:Regs -Users $script:Users -RegistrationBlock (Get-CIPPCARegistrationBlock -Policies @((New-AdminPhishPolicy)))
        $R.Summary.CaWouldBlockRegistration | Should -Be 'Yes'
        $R.Summary.CaBlockEnforcedPolicies | Should -Be 'Admins PR'
        $R.Summary.CaBlockPhoneOnlyUsers | Should -Be 1
        ($R.Findings | Where-Object Key -EQ 'SmsRetirementCaBlocksRegistration').Severity | Should -Be 'Warning'
    }

    It 'stays Info when an enforced admin policy has no phone-only admin in scope, as in aspendora.com' {
        $Regs = @((New-RegRow 'user1'), (New-RegRow 'admin1' -Admin -Methods @('fido2')))
        $R = Test-CIPPSmsMfaReadiness -Registrations $Regs -Users @((New-UserRow 'user1'), (New-UserRow 'admin1')) -RegistrationBlock (Get-CIPPCARegistrationBlock -Policies @((New-AdminPhishPolicy)))
        $R.Summary.CaWouldBlockRegistration | Should -Be 'Yes'
        $R.Summary.CaBlockPhoneOnlyUsers | Should -Be 0
        $Finding = $R.Findings | Where-Object Key -EQ 'SmsRetirementCaBlocksRegistration'
        $Finding.Severity | Should -Be 'Info'
        $Finding.Message | Should -Match 'No account'
    }

    It 'counts everyone in an all-users policy except its excluded users, once across policies' {
        $Block = Get-CIPPCARegistrationBlock -Policies @((New-CaPolicy -Name 'A' -Controls @('approvedApplication') -ExcludeUsers @('user1')), (New-CaPolicy -Name 'B' -Controls @('compliantApplication') -ExcludeUsers @('user1')))
        (Test-CIPPSmsMfaReadiness -Registrations $script:Regs -Users $script:Users -RegistrationBlock $Block).Summary.CaBlockPhoneOnlyUsers | Should -Be 1
    }

    It 'reports report-only separately, and does not count those users as blocked' {
        $R = Test-CIPPSmsMfaReadiness -Registrations $script:Regs -Users $script:Users -RegistrationBlock (Get-CIPPCARegistrationBlock -Policies @((New-AdminPhishPolicy -State 'enabledForReportingButNotEnforced')))
        $R.Summary.CaWouldBlockRegistration | Should -Be 'ReportOnly'
        $R.Summary.CaBlockReportOnlyPolicies | Should -Be 'Admins PR'
        $R.Summary.CaBlockPhoneOnlyUsers | Should -Be 0
        ($R.Findings | Where-Object Key -EQ 'SmsRetirementCaMayBlockRegistration').Severity | Should -Be 'Info'
    }

    It 'does not change ReadyByFeb2027, and uses a key the weekly alert skips' {
        $Without = Test-CIPPSmsMfaReadiness -Registrations $script:Regs -Users $script:Users
        $With = Test-CIPPSmsMfaReadiness -Registrations $script:Regs -Users $script:Users -RegistrationBlock (Get-CIPPCARegistrationBlock -Policies @((New-AdminPhishPolicy)))
        $With.Summary.ReadyByFeb2027 | Should -Be $Without.Summary.ReadyByFeb2027
        @($With.Findings | Where-Object { $_.Key -match 'Ca(May)?Block' }).Key | Should -BeLike 'SmsRetirement*'
    }

    Context 'Get-CIPPSmsMfaReadiness' {
        BeforeAll {
            function Get-CippException { [CmdletBinding()] param($Exception) [pscustomobject]@{ NormalizedError = "$Exception" } }
            function New-GraphGetRequest { [CmdletBinding()] param($uri, $tenantid, $AsApp) }
        }

        It 'reads Conditional Access as the app and passes it to the rules' {
            Mock New-GraphGetRequest {
                if ($uri -match 'conditionalAccess/policies') { $script:CaAsApp = $AsApp; return (New-AdminPhishPolicy) }
                if ($uri -match 'userRegistrationDetails') { return (New-RegRow 'admin1' -Admin) }
                if ($uri -match '/users\?') { return (New-UserRow 'admin1') }
            }
            $R = Get-CIPPSmsMfaReadiness -TenantFilter 'contoso.com'
            $script:CaAsApp | Should -BeTrue
            $R.Summary.CaWouldBlockRegistration | Should -Be 'Yes'
            $R.Errors | Should -BeNullOrEmpty
        }

        It 'stays Unknown and does not add an error when Conditional Access cannot be read' {
            Mock New-GraphGetRequest {
                if ($uri -match 'conditionalAccess/policies') { throw 'Forbidden' }
                if ($uri -match 'userRegistrationDetails') { return (New-RegRow 'admin1' -Admin) }
                if ($uri -match '/users\?') { return (New-UserRow 'admin1') }
            }
            $R = Get-CIPPSmsMfaReadiness -TenantFilter 'contoso.com'
            $R.Summary.CaWouldBlockRegistration | Should -Be 'Unknown'
            $R.Errors | Should -BeNullOrEmpty
        }

        It 'is No, not Unknown, for a tenant with no policies' {
            Mock New-GraphGetRequest {
                if ($uri -match 'userRegistrationDetails') { return (New-RegRow 'admin1' -Admin) }
                if ($uri -match '/users\?') { return (New-UserRow 'admin1') }
            }
            (Get-CIPPSmsMfaReadiness -TenantFilter 'contoso.com').Summary.CaWouldBlockRegistration | Should -Be 'No'
        }
    }
}
