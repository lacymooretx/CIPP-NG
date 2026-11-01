# Aspendora fork (Vikunja CIPP-4): break-glass posture rules.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/BreakGlass/Test-CIPPBreakGlassPosture.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/CAPreflight/Test-CIPPCAPolicyUserScope.ps1')
    $script:Now = [datetime]::new(2026, 10, 31, 12, 0, 0, [DateTimeKind]::Utc)
    $script:GA = '62e90394-69f5-4237-9190-012177145e10'
    function Good {
        param($Id = 'bg1', $Upn = 'bg1@contoso.onmicrosoft.com')
        [pscustomobject]@{ Id = $Id; UserPrincipalName = $Upn; Exists = $true; AccountEnabled = $true; OnPremisesSyncEnabled = $null
            PasswordPolicies = 'DisablePasswordExpiration'; PasswordNeverExpiresByDomain = $false; ActiveGlobalAdmin = $true; EligibleGlobalAdmin = $false
            GroupIds = @('bg-group'); RoleTemplateIds = @($script:GA); Methods = @('#microsoft.graph.fido2AuthenticationMethod', '#microsoft.graph.passwordAuthenticationMethod')
            SignInActivityKnown = $true; LastSuccessfulSignIn = $script:Now.AddDays(-10).ToString('o') }
    }
    function Pol { param($Id, $State = 'enabled', $IncUsers = @('All'), $ExUsers = @(), $ExGroups = @(), $IncRoles = @(), $ExRoles = @())
        [pscustomobject]@{ id = $Id; displayName = "Policy $Id"; state = $State; grantControls = @{ builtInControls = @('mfa') }
            conditions = @{ users = @{ includeUsers = $IncUsers; excludeUsers = $ExUsers; includeGroups = @(); excludeGroups = $ExGroups; includeRoles = $IncRoles; excludeRoles = $ExRoles } } } }
    function Check { param($Params) Test-CIPPBreakGlassPosture -Now $script:Now @Params }
}

Describe 'Test-CIPPBreakGlassPosture' {
    It 'is clean for two well-configured accounts excluded through a group' {
        $F = Check @{ Accounts = @((Good), (Good 'bg2' 'bg2@contoso.onmicrosoft.com')); Policies = @(Pol 'p1' -ExGroups @('bg-group')) }
        $F | Should -BeNullOrEmpty
    }

    It 'errors with no accounts and warns with one' {
        (Check @{ Accounts = @() }).Key | Should -Be @('Count|0')
        (Check @{ Accounts = @(Good) }).Key | Should -Be @('Count|1')
    }

    It 'catches a policy that applies through a role and is not excluded' {
        $F = Check @{ Accounts = @((Good), (Good 'bg2' 'bg2@contoso.onmicrosoft.com')); Policies = @(Pol 'p2' -IncUsers @() -IncRoles @($script:GA)) }
        $F.Key | Should -Be @('CA|bg1|p2', 'CA|bg2|p2')
        $F[0].Severity | Should -Be 'Error'
    }

    It 'treats a report-only policy as a warning and ignores disabled ones' {
        $F = Check @{ Accounts = @((Good), (Good 'bg2' 'bg2@contoso.onmicrosoft.com')); Policies = @((Pol 'p3' -State 'enabledForReportingButNotEnforced' -ExUsers @('bg2')), (Pol 'p4' -State 'disabled')) }
        $F.Key | Should -Be @('CA|bg1|p3')
        $F[0].Severity | Should -Be 'Warning'
    }

    It 'flags PIM-eligible-only GA, synced, custom domain, expiring password, no FIDO2 and personal MFA' {
        $A = Good; $A.ActiveGlobalAdmin = $false; $A.EligibleGlobalAdmin = $true; $A.OnPremisesSyncEnabled = $true
        $A.UserPrincipalName = 'bg@contoso.com'; $A.PasswordPolicies = $null; $A.Methods = @('#microsoft.graph.phoneAuthenticationMethod')
        $Keys = (Check @{ Accounts = @($A, (Good 'bg2' 'bg2@contoso.onmicrosoft.com')) }).Key
        foreach ($K in 'GaEligible|bg1', 'Synced|bg1', 'Domain|bg1', 'PwdExpiry|bg1', 'NoFido2|bg1', 'PersonalMfa|bg1') { $Keys | Should -Contain $K }
    }

    It 'accepts a domain-wide never-expire password policy' {
        $A = Good; $A.PasswordPolicies = 'None'; $A.PasswordNeverExpiresByDomain = $true
        (Check @{ Accounts = @($A, (Good 'bg2' 'bg2@contoso.onmicrosoft.com')) }) | Should -BeNullOrEmpty
    }

    It 'flags an untested account only when sign-in activity is known' {
        $A = Good; $A.LastSuccessfulSignIn = $null
        (Check @{ Accounts = @($A, (Good 'bg2' 'bg2@contoso.onmicrosoft.com')) }).Key | Should -Be @('Untested|bg1')
        $A.SignInActivityKnown = $false
        (Check @{ Accounts = @($A, (Good 'bg2' 'bg2@contoso.onmicrosoft.com')) }) | Should -BeNullOrEmpty
    }

    It 'flags other accounts with broad CA exclusions, not registered ones' {
        $P = @(1..3 | ForEach-Object { Pol "p$_" -ExUsers @('bg1', 'bg2', 'admin1') -ExGroups @('bg-group') })
        $F = Check @{ Accounts = @((Good), (Good 'bg2' 'bg2@contoso.onmicrosoft.com')); Policies = $P; UserNames = @{ admin1 = 'asp_admin@contoso.com' } }
        $F.Key | Should -Be @('BroadExclusion|admin1')
        $F[0].Account | Should -Be 'asp_admin@contoso.com'
    }

    It 'reports a missing account and stops checking it' {
        $A = [pscustomobject]@{ Id = 'gone'; UserPrincipalName = 'x@contoso.onmicrosoft.com'; Exists = $false }
        $Keys = (Check @{ Accounts = @($A, (Good)) }).Key
        $Keys | Should -Contain 'Missing|gone'
        $Keys | Should -Contain 'Count|1'
        @($Keys | Where-Object { $_ -match '\|gone' }).Count | Should -Be 1
    }
}
