# Aspendora fork (Vikunja CIPP-5): CA pre-flight lockout rules. Pure functions, no Graph.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    foreach ($F in 'Test-CIPPCAPolicyUserScope', 'Test-CIPPCAGrantSatisfiable', 'Test-CIPPCAPreflight', 'Resolve-CIPPCAPreflightGate') {
        . (Join-Path $RepoRoot "Modules/CIPPCore/Public/CAPreflight/$F.ps1")
    }
    $script:Now = [datetime]::new(2026, 10, 31, 12, 0, 0, [DateTimeKind]::Utc)
    $script:GA = '62e90394-69f5-4237-9190-012177145e10'

    function Pol {
        param($State = 'enabled', $IncUsers = @('All'), $ExUsers = @(), $ExGroups = @(), $IncRoles = @(), $Controls = @('mfa'), $Strength, $IncExternal, $ExExternal, $Modified)
        $G = [ordered]@{ operator = 'OR'; builtInControls = $Controls }
        if ($Strength) { $G.authenticationStrength = $Strength }
        [pscustomobject]@{
            id = 'p1'; displayName = 'Require MFA'; state = $State; modifiedDateTime = $Modified
            conditions    = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = $IncUsers; excludeUsers = $ExUsers; includeGroups = @(); excludeGroups = $ExGroups; includeRoles = $IncRoles; excludeRoles = @(); includeGuestsOrExternalUsers = $IncExternal; excludeGuestsOrExternalUsers = $ExExternal } }
            grantControls = [pscustomobject]$G
        }
    }
    function User {
        param($Id, $Groups = @(), $Methods = @('microsoftAuthenticatorPush'), [switch]$BreakGlass, [switch]$Ga)
        [pscustomobject]@{ Id = $Id; UserPrincipalName = "$Id@contoso.onmicrosoft.com"; Exists = $true; MembershipKnown = $true; GroupIds = $Groups
            RoleTemplateIds = @(if ($Ga) { $script:GA }); Methods = $Methods; IsExternal = $false; IsBreakGlass = [bool]$BreakGlass }
    }
    function Gdap { [pscustomobject]@{ Id = $null; UserPrincipalName = 'tech@partner.com'; MembershipKnown = $true; GroupIds = @(); RoleTemplateIds = @(); Methods = $null; IsExternal = $true; ExternalUserType = 'serviceProvider'; HomeTenantId = 'partner-tid' } }
    function Run {
        param([hashtable]$P)
        $Defaults = @{ Now = $script:Now; BreakGlassAccounts = @(User 'bg1' -Groups @('bg-group') -Methods @('fido2') -BreakGlass -Ga); GlobalAdmins = @((User 'admin1' -Ga), (User 'bg1' -Groups @('bg-group') -Methods @('fido2') -BreakGlass -Ga)) }
        foreach ($K in $P.Keys) { $Defaults[$K] = $P[$K] }
        Test-CIPPCAPreflight @Defaults
    }
    function StatusOf { param($R, $Key) ($R.Checks | Where-Object Key -EQ $Key).Status }
}

Describe 'Test-CIPPCAPolicyUserScope' {
    It 'includes everyone for All and lets an exclusion through a group win' {
        (Test-CIPPCAPolicyUserScope -Policy (Pol) -Principal (User 'u1')).InScope | Should -BeTrue
        $S = Test-CIPPCAPolicyUserScope -Policy (Pol -ExGroups @('bg-group')) -Principal (User 'u1' -Groups @('bg-group'))
        $S.InScope | Should -BeFalse
        $S.Reason | Should -Match 'bg-group'
    }

    It 'matches included roles' {
        (Test-CIPPCAPolicyUserScope -Policy (Pol -IncUsers @() -IncRoles @($script:GA)) -Principal (User 'a' -Ga)).InScope | Should -BeTrue
        (Test-CIPPCAPolicyUserScope -Policy (Pol -IncUsers @() -IncRoles @($script:GA)) -Principal (User 'b')).InScope | Should -BeFalse
    }

    It 'treats a GDAP service-provider user as included by All and excluded by a matching external-user exclusion' {
        (Test-CIPPCAPolicyUserScope -Policy (Pol) -Principal (Gdap)).InScope | Should -BeTrue
        $Ex = [pscustomobject]@{ guestOrExternalUserTypes = 'b2bCollaborationGuest,serviceProvider'; externalTenants = [pscustomobject]@{ membershipKind = 'all' } }
        (Test-CIPPCAPolicyUserScope -Policy (Pol -ExExternal $Ex) -Principal (Gdap)).InScope | Should -BeFalse
    }

    It 'never reads an enumerated tenant list as excluding a principal whose home tenant is unknown' {
        $P = Gdap; $P.HomeTenantId = $null
        $Ex = [pscustomobject]@{ guestOrExternalUserTypes = 'serviceProvider'; externalTenants = [pscustomobject]@{ membershipKind = 'enumerated'; members = @('other-tid') } }
        (Test-CIPPCAPolicyUserScope -Policy (Pol -ExExternal $Ex) -Principal $P).InScope | Should -BeTrue
    }

    It 'ignores external-user conditions for members' {
        $Ex = [pscustomobject]@{ guestOrExternalUserTypes = 'serviceProvider'; externalTenants = [pscustomobject]@{ membershipKind = 'all' } }
        (Test-CIPPCAPolicyUserScope -Policy (Pol -ExExternal $Ex) -Principal (User 'u1')).InScope | Should -BeTrue
    }
}

Describe 'Test-CIPPCAGrantSatisfiable' {
    It 'is <Outcome> for <Name>' -ForEach @(
        @{ Name = 'block'; Controls = @('block'); Methods = @('fido2'); Outcome = 'Blocked' }
        @{ Name = 'MFA with Authenticator'; Controls = @('mfa'); Methods = @('microsoftAuthenticatorPush'); Outcome = 'Satisfiable' }
        @{ Name = 'MFA with nothing registered'; Controls = @('mfa'); Methods = @(); Outcome = 'Blocked' }
        @{ Name = 'MFA with email only'; Controls = @('mfa'); Methods = @('email'); Outcome = 'Blocked' }
        @{ Name = 'MFA, methods unknown'; Controls = @('mfa'); Methods = $null; Outcome = 'Unknown' }
        @{ Name = 'MFA via @odata.type'; Controls = @('mfa'); Methods = @('#microsoft.graph.fido2AuthenticationMethod'); Outcome = 'Satisfiable' }
        @{ Name = 'compliant device'; Controls = @('compliantDevice'); Methods = @('fido2'); Outcome = 'Unknown' }
        @{ Name = 'session controls only'; Controls = @(); Methods = @(); Outcome = 'Satisfiable' }
    ) {
        $P = Pol -Controls $Controls
        (Test-CIPPCAGrantSatisfiable -Policy $P -Methods $Methods).Outcome | Should -Be $Outcome
    }

    It 'checks built-in phishing-resistant strength by id' {
        $P = Pol -Controls @() -Strength ([pscustomobject]@{ id = '00000000-0000-0000-0000-000000000004' })
        (Test-CIPPCAGrantSatisfiable -Policy $P -Methods @('microsoftAuthenticatorPush')).Outcome | Should -Be 'Blocked'
        (Test-CIPPCAGrantSatisfiable -Policy $P -Methods @('passKeyDeviceBound')).Outcome | Should -Be 'Satisfiable'
    }

    It 'uses allowedCombinations of a custom strength, and is Unknown without them' {
        $P = Pol -Controls @() -Strength ([pscustomobject]@{ id = 'custom'; allowedCombinations = @('password,softwareOath') })
        (Test-CIPPCAGrantSatisfiable -Policy $P -Methods @('softwareOneTimePasscode')).Outcome | Should -Be 'Satisfiable'
        $P2 = Pol -Controls @() -Strength ([pscustomobject]@{ id = 'custom' })
        (Test-CIPPCAGrantSatisfiable -Policy $P2 -Methods @('fido2')).Outcome | Should -Be 'Unknown'
    }

    It 'applies AND and OR operators' {
        $P = Pol -Controls @('mfa', 'compliantDevice')
        (Test-CIPPCAGrantSatisfiable -Policy $P -Methods @('fido2')).Outcome | Should -Be 'Satisfiable'
        $P.grantControls.operator = 'AND'
        (Test-CIPPCAGrantSatisfiable -Policy $P -Methods @('fido2')).Outcome | Should -Be 'Unknown'
        (Test-CIPPCAGrantSatisfiable -Policy $P -Methods @()).Outcome | Should -Be 'Blocked'
    }
}

Describe 'Test-CIPPCAPreflight' {
    Context 'break-glass exclusion' {
        It 'fails when a break-glass account is in scope (the 2026-10-07 regression)' {
            $R = Run @{ Policy = (Pol); ExistingPolicy = (Pol -State 'enabled') }
            StatusOf $R 'BreakGlassExcluded' | Should -Be 'Fail'
            $R.Passed | Should -BeFalse
        }

        It 'passes when the break-glass group is excluded' {
            $R = Run @{ Policy = (Pol -ExGroups @('bg-group')); ExistingPolicy = (Pol -State 'enabled' -ExGroups @('bg-group')) }
            StatusOf $R 'BreakGlassExcluded' | Should -Be 'Pass'
        }

        It 'fails when no break-glass account is registered' {
            StatusOf (Run @{ Policy = (Pol); BreakGlassAccounts = @() }) 'BreakGlassExcluded' | Should -Be 'Fail'
        }

        It 'warns, not passes, when membership could not be read' {
            $Bg = User 'bg1' -BreakGlass; $Bg.MembershipKnown = $false
            StatusOf (Run @{ Policy = (Pol -IncUsers @() -IncRoles @($script:GA)); BreakGlassAccounts = @($Bg) }) 'BreakGlassExcluded' | Should -Be 'Warn'
        }
    }

    Context 'Global Admin access' {
        It 'passes when a non-break-glass GA has MFA registered' {
            StatusOf (Run @{ Policy = (Pol -ExGroups @('bg-group')) }) 'GlobalAdminAccess' | Should -Be 'Pass'
        }

        It 'fails when no GA can meet the controls' {
            $R = Run @{ Policy = (Pol -Controls @('block')); GlobalAdmins = @((User 'admin1' -Ga), (User 'admin2' -Ga)) }
            StatusOf $R 'GlobalAdminAccess' | Should -Be 'Fail'
        }

        It 'warns when the only GAs are break-glass accounts' {
            $R = Run @{ Policy = (Pol -ExGroups @('bg-group')); GlobalAdmins = @(User 'bg1' -Groups @('bg-group') -BreakGlass -Ga) }
            StatusOf $R 'GlobalAdminAccess' | Should -Be 'Warn'
        }

        It 'warns when the GA list could not be read' {
            StatusOf (Run @{ Policy = (Pol -ExGroups @('bg-group')); GlobalAdmins = @(); GlobalAdminsKnown = $false }) 'GlobalAdminAccess' | Should -Be 'Warn'
        }
    }

    Context 'What-If' {
        It 'fails when the executing GDAP admin would be blocked' {
            $R = Run @{ Policy = (Pol -Controls @('block') -ExGroups @('bg-group')); Executor = (Gdap) }
            StatusOf $R 'WhatIf' | Should -Be 'Fail'
            ($R.WhatIf | Where-Object Role -EQ 'Executing admin').Outcome | Should -Be 'Blocked'
        }

        It 'warns for MFA on a GDAP admin, whose methods live in the partner tenant' {
            StatusOf (Run @{ Policy = (Pol -ExGroups @('bg-group')); Executor = (Gdap) }) 'WhatIf' | Should -Be 'Warn'
        }

        It 'is Info for a scheduled run with no executor' {
            StatusOf (Run @{ Policy = (Pol -ExGroups @('bg-group')) }) 'WhatIf' | Should -Be 'Info'
        }
    }

    Context 'report-only soak' {
        It 'fails a new policy created straight into On' {
            StatusOf (Run @{ Policy = (Pol -ExGroups @('bg-group')) }) 'ReportOnlySoak' | Should -Be 'Fail'
        }

        It 'fails a disabled policy' {
            StatusOf (Run @{ Policy = (Pol -ExGroups @('bg-group')); ExistingPolicy = (Pol -State 'disabled' -ExGroups @('bg-group')) }) 'ReportOnlySoak' | Should -Be 'Fail'
        }

        It 'passes when report-only and unchanged for N days (modifiedDateTime lower bound)' {
            $E = Pol -State 'enabledForReportingButNotEnforced' -ExGroups @('bg-group') -Modified $script:Now.AddDays(-10).ToString('o')
            $R = Run @{ Policy = (Pol -ExGroups @('bg-group')); ExistingPolicy = $E }
            StatusOf $R 'ReportOnlySoak' | Should -Be 'Pass'
            $R.ReportOnly.SinceIsLowerBound | Should -BeTrue
        }

        It 'fails when the audit log shows it entered report-only 2 days ago' {
            $E = Pol -State 'enabledForReportingButNotEnforced' -ExGroups @('bg-group') -Modified $script:Now.AddDays(-2).ToString('o')
            $Ev = @([pscustomobject]@{ ActivityDateTime = $script:Now.AddDays(-2).ToString('o'); Activity = 'Update conditional access policy'; OldState = 'disabled'; NewState = 'enabledForReportingButNotEnforced' })
            $R = Run @{ Policy = (Pol -ExGroups @('bg-group')); ExistingPolicy = $E; AuditEvents = $Ev; AuditKnown = $true }
            StatusOf $R 'ReportOnlySoak' | Should -Be 'Fail'
            $R.ReportOnly.Source | Should -Be 'directoryAudit'
        }

        It 'warns when it entered report-only 20 days ago but was edited yesterday' {
            $E = Pol -State 'enabledForReportingButNotEnforced' -ExGroups @('bg-group') -Modified $script:Now.AddDays(-1).ToString('o')
            $Ev = @(
                [pscustomobject]@{ ActivityDateTime = $script:Now.AddDays(-1).ToString('o'); Activity = 'Update conditional access policy'; OldState = 'enabledForReportingButNotEnforced'; NewState = 'enabledForReportingButNotEnforced' }
                [pscustomobject]@{ ActivityDateTime = $script:Now.AddDays(-20).ToString('o'); Activity = 'Add conditional access policy'; OldState = $null; NewState = 'enabledForReportingButNotEnforced' }
            )
            StatusOf (Run @{ Policy = (Pol -ExGroups @('bg-group')); ExistingPolicy = $E; AuditEvents = $Ev; AuditKnown = $true }) 'ReportOnlySoak' | Should -Be 'Warn'
        }

        It 'warns when the definition being enabled differs from the one that soaked' {
            $E = Pol -State 'enabledForReportingButNotEnforced' -ExGroups @('bg-group') -Modified $script:Now.AddDays(-10).ToString('o')
            $R = Run @{ Policy = (Pol -ExGroups @('bg-group') -Controls @('block')); ExistingPolicy = $E }
            StatusOf $R 'ReportOnlySoak' | Should -Be 'Warn'
            $R.ReportOnly.DefinitionChanged | Should -BeTrue
        }

        It 'is Info for an edit of an already-enforced policy' {
            StatusOf (Run @{ Policy = (Pol -ExGroups @('bg-group')); ExistingPolicy = (Pol -State 'enabled' -ExGroups @('bg-group')) }) 'ReportOnlySoak' | Should -Be 'Info'
        }
    }

    Context 'would-be-blocked sign-ins' {
        BeforeAll {
            $script:Soaked = Pol -State 'enabledForReportingButNotEnforced' -ExGroups @('bg-group') -Modified $script:Now.AddDays(-10).ToString('o')
            function SignIns { param($Samples) [pscustomobject]@{ Collected = $true; Known = $true; WindowDays = 7; Totals = [pscustomobject]@{ total = 100; reportOnlyFailure = @($Samples | Where-Object policyResult -EQ 'reportOnlyFailure').Count; reportOnlyInterrupted = 0 }; Samples = $Samples } }
        }

        It 'passes with no would-be failures' {
            StatusOf (Run @{ Policy = (Pol -ExGroups @('bg-group')); ExistingPolicy = $script:Soaked; SignIns = (SignIns @()) }) 'WouldBeBlocked' | Should -Be 'Pass'
        }

        It 'warns on user failures and fails when an admin would have been blocked' {
            $User = [pscustomobject]@{ userId = 'u9'; userPrincipalName = 'u9@contoso.com'; policyResult = 'reportOnlyFailure' }
            $Admin = [pscustomobject]@{ userId = 'admin1'; userPrincipalName = 'admin1@contoso.onmicrosoft.com'; policyResult = 'reportOnlyFailure' }
            StatusOf (Run @{ Policy = (Pol -ExGroups @('bg-group')); ExistingPolicy = $script:Soaked; SignIns = (SignIns @($User)) }) 'WouldBeBlocked' | Should -Be 'Warn'
            $R = Run @{ Policy = (Pol -ExGroups @('bg-group')); ExistingPolicy = $script:Soaked; SignIns = (SignIns @($User, $Admin)) }
            StatusOf $R 'WouldBeBlocked' | Should -Be 'Fail'
            $R.WouldBeBlocked.AdminSignIns.userId | Should -Be @('admin1')
        }

        It 'warns when sign-ins could not be read (no P1)' {
            $S = [pscustomobject]@{ Collected = $true; Known = $false; Error = 'Tenant does not have a premium license'; WindowDays = 7 }
            StatusOf (Run @{ Policy = (Pol -ExGroups @('bg-group')); ExistingPolicy = $script:Soaked; SignIns = $S }) 'WouldBeBlocked' | Should -Be 'Warn'
        }
    }

    It 'passes overall for a well-prepared policy' {
        $E = Pol -State 'enabledForReportingButNotEnforced' -ExGroups @('bg-group') -Modified $script:Now.AddDays(-10).ToString('o')
        $R = Run @{ Policy = (Pol -ExGroups @('bg-group')); ExistingPolicy = $E }
        $R.Passed | Should -BeTrue
        @($R.Checks | Where-Object Status -EQ 'Fail') | Should -BeNullOrEmpty
    }
}

Describe 'Resolve-CIPPCAPreflightGate' {
    BeforeAll {
        function Write-LogMessage { param($headers, $API, $tenant, $message, $Sev, $LogData) $script:Logged.Add([pscustomobject]@{ Message = $message; Sev = $Sev }) }
        $script:Failed = [pscustomobject]@{ Passed = $false; PolicyName = 'P'; Checks = @([pscustomobject]@{ Check = 'Break-glass accounts excluded'; Status = 'Fail'; Message = 'bg in scope' }) }
        $Principal = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('{"userDetails":"tech@aspendora.com"}'))
        $script:Headers = @{ 'x-ms-client-principal' = $Principal }
    }
    BeforeEach { $script:Logged = [System.Collections.Generic.List[object]]::new() }

    It 'blocks in Enforce mode without an override and logs nothing' {
        $G = Resolve-CIPPCAPreflightGate -Result $script:Failed -Mode Enforce -Headers $script:Headers -TenantFilter 't'
        $G.Allowed | Should -BeFalse
        $G.Message | Should -Match 'override'
        $script:Logged.Count | Should -Be 0
    }

    It 'allows an override and logs a Warning naming the actor' {
        $G = Resolve-CIPPCAPreflightGate -Result $script:Failed -Mode Enforce -Override $true -Headers $script:Headers -TenantFilter 't'
        $G.Allowed | Should -BeTrue
        $G.Overridden | Should -BeTrue
        $script:Logged[0].Sev | Should -Be 'Warning'
        $script:Logged[0].Message | Should -Match 'OVERRIDDEN by tech@aspendora.com'
    }

    It 'never blocks in Warn mode (standards) but logs a Warning' {
        $G = Resolve-CIPPCAPreflightGate -Result $script:Failed -Mode Warn -TenantFilter 't'
        $G.Allowed | Should -BeTrue
        $script:Logged[0].Sev | Should -Be 'Warning'
    }

    It 'passes through a passed result' {
        (Resolve-CIPPCAPreflightGate -Result ([pscustomobject]@{ Passed = $true; PolicyName = 'P'; Checks = @() })).Allowed | Should -BeTrue
    }
}

Describe 'Get-CIPPCAPreflightContext' {
    BeforeAll {
        . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/CAPreflight/Get-CIPPCAPreflightContext.ps1')
        function Get-CippException { param($Exception) [pscustomobject]@{ NormalizedError = "$($Exception.Exception.Message)" } }
        function Get-CIPPBreakGlassAccounts { param($TenantFilter) @([pscustomobject]@{ RowKey = 'bg1'; UserPrincipalName = 'bg1@contoso.onmicrosoft.com' }) }
        function Get-CIPPCAPolicyImpact { param($TenantFilter, $PolicyId, $Days) $script:ImpactDays = $Days; [pscustomobject]@{ totals = [pscustomobject]@{ total = 3; reportOnlyFailure = 1 }; samples = @([pscustomobject]@{ userId = 'u1'; policyResult = 'reportOnlyFailure' }); partial = $false } }
        # Shape of a real "Update conditional access policy" directory audit (3endt.com, 2026-10-31).
        $script:Old = '{"state":"disabled"}'
        $script:New = '{"state":"enabledForReportingButNotEnforced"}'
        function New-GraphGetRequest {
            [CmdletBinding()] param($uri, $tenantid)
            $script:Uris.Add($uri)
            switch -Regex ($uri) {
                'userRegistrationDetails' { throw 'Tenant does not have a premium license' }
                '/authentication/methods' { @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.fido2AuthenticationMethod' }) }
                'roleAssignments' { @([pscustomobject]@{ directoryScopeId = '/'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'admin1'; userPrincipalName = 'admin1@contoso.com' } }) }
                'transitiveMemberOf' { @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.group'; id = 'bg-group' }) }
                'directoryAudits' {
                    @([pscustomobject]@{ activityDisplayName = 'Update conditional access policy'; activityDateTime = '2026-10-29T10:00:00Z'
                            targetResources = @([pscustomobject]@{ id = 'p1'; modifiedProperties = @([pscustomobject]@{ displayName = 'ConditionalAccessPolicy'; oldValue = $script:Old; newValue = $script:New }) }) })
                }
                default { throw "unexpected $uri" }
            }
        }
    }
    BeforeEach { $script:Uris = [System.Collections.Generic.List[string]]::new() }

    It 'collects break-glass, GAs (per-user methods without P1), audit state changes and sign-ins' {
        $Existing = Pol -State 'enabledForReportingButNotEnforced' -Modified ([datetime]::UtcNow.AddDays(-2).ToString('o'))
        $C = Get-CIPPCAPreflightContext -TenantFilter 'contoso.com' -Policy (Pol) -ExistingPolicy $Existing
        $C.BreakGlassAccounts[0].GroupIds | Should -Be @('bg-group')
        $C.GlobalAdmins[0].RoleTemplateIds | Should -Contain $script:GA
        $C.GlobalAdmins[0].Methods | Should -Be @('#microsoft.graph.fido2AuthenticationMethod')
        $C.AuditKnown | Should -BeTrue
        $C.AuditEvents[0].OldState | Should -Be 'disabled'
        $C.AuditEvents[0].NewState | Should -Be 'enabledForReportingButNotEnforced'
        $C.SignIns.Known | Should -BeTrue
        $script:ImpactDays | Should -Be 7
        ($C.Errors -join ' ') | Should -Match 'P1'
        $C.Executor | Should -BeNullOrEmpty
    }

    It 'skips the audit read when modifiedDateTime already proves the soak, and sign-ins when asked' {
        $Existing = Pol -State 'enabledForReportingButNotEnforced' -Modified ([datetime]::UtcNow.AddDays(-20).ToString('o'))
        $C = Get-CIPPCAPreflightContext -TenantFilter 'contoso.com' -Policy (Pol) -ExistingPolicy $Existing -SkipSignIns
        @($script:Uris | Where-Object { $_ -match 'directoryAudits' }) | Should -BeNullOrEmpty
        $C.SignIns.Collected | Should -BeFalse
    }
}
