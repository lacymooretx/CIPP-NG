# Pester tests for the sign-in failure explainer (Vikunja CIPP-10): ConvertTo-CIPPSignInExplanation (one sign-in),
# Get-CIPPSignInExplanation (fetch + pick + resolve), the error catalog and the ConnectWise note text.
# Fixtures are synthetic but shaped like real beta auditLogs/signIns records (checked live 2026-11-01). They go
# through JSON so dates arrive the way Graph's do; assertions on times only use ConvertTo-CIPPCentralTime output,
# which is the same whether ConvertFrom-Json produced a Utc or a Local DateTime.

BeforeAll {
    $BackendRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $BackendRoot 'Modules/CIPPCore/Public/MailTriage/ConvertTo-CIPPCentralTime.ps1')
    foreach ($F in 'Get-CIPPSignInErrorCatalog', 'ConvertTo-CIPPSignInExplanation', 'Get-CIPPSignInExplanation', 'ConvertTo-CIPPSignInExplanationNote') {
        . (Join-Path $BackendRoot "Modules/CIPPCore/Public/SignInExplainer/$F.ps1")
    }

    function New-GraphGetRequest { [CmdletBinding()] param($uri, $tenantid, $noPagination, $AsApp, [switch]$ComplexFilter) }
    function New-GraphBulkRequest { [CmdletBinding()] param($Requests, $tenantid, $Version, $asapp) }
    function Get-CippException { [CmdletBinding()] param($Exception) [pscustomobject]@{ NormalizedError = "$($Exception.Exception.Message)" } }

    function script:ConvertTo-Fixture($Object) { $Object | ConvertTo-Json -Depth 12 | ConvertFrom-Json }

    function script:New-CAPolicy {
        param([string]$Id, [string]$Name, [string]$Result, [string[]]$Grant = @(), [string]$Matched = 'application,users', [string]$NotMatched = 'none', [string[]]$Session = @())
        [ordered]@{
            id = $Id; displayName = $Name; result = $Result; enforcedGrantControls = @($Grant); enforcedSessionControls = @($Session)
            sessionControlsNotSatisfied = @(); conditionsSatisfied = $Matched; conditionsNotSatisfied = $NotMatched; authenticationStrength = $null
            includeRulesSatisfied = @(); excludeRulesSatisfied = @()
        }
    }

    function script:New-SignIn {
        param(
            [string]$Id = ([guid]::NewGuid().ToString()), [string]$Correlation = ([guid]::NewGuid().ToString()),
            [string]$When = '2026-10-15T17:11:50Z', [int]$Code = 0, [string]$Reason = '', [string]$Client = 'Browser',
            [string]$City = 'Dallas', [string]$Country = 'US', [string]$Ip = '203.0.113.10', $Policies = @(),
            [string]$CAStatus = 'notApplied', [string]$Risk = 'none', [string]$RiskState = 'none', [string[]]$Providers = @(),
            $Device = @{ deviceId = 'dev-1'; displayName = 'LAPTOP-01'; operatingSystem = 'Windows10'; browser = 'Edge 155.0.0'; isCompliant = $true; isManaged = $true; trustType = 'Azure AD joined' },
            $AuthDetails = @(), [string]$Upn = 'alex@contoso.com'
        )
        ConvertTo-Fixture ([ordered]@{
                id = $Id; correlationId = $Correlation; createdDateTime = $When
                userPrincipalName = $Upn; userId = '11111111-1111-1111-1111-111111111111'; userDisplayName = 'Alex Example'
                appDisplayName = 'Office 365 Exchange Online'; resourceDisplayName = 'Office 365 Exchange Online'
                ipAddress = $Ip; clientAppUsed = $Client; isInteractive = $true; conditionalAccessStatus = $CAStatus
                riskLevelDuringSignIn = $Risk; riskState = $RiskState; riskDetail = 'none'; riskEventTypes_v2 = @()
                authenticationRequirement = 'singleFactorAuthentication'
                authenticationRequirementPolicies = @($Providers | ForEach-Object { @{ requirementProvider = $_; detail = $_ } })
                status = @{ errorCode = $Code; failureReason = $Reason; additionalDetails = '' }
                deviceDetail = $Device
                location = @{ city = $City; state = ''; countryOrRegion = $Country }
                appliedConditionalAccessPolicies = @($Policies)
                authenticationDetails = @($AuthDetails)
                networkLocationDetails = @()
            })
    }

    $script:NoDevice = @{ deviceId = ''; displayName = ''; operatingSystem = 'Android'; browser = 'Chrome Mobile 155'; isCompliant = $false; isManaged = $false; trustType = $null }
}

Describe 'Get-CIPPSignInErrorCatalog' {
    It 'has a title, explanation and fix for every code, keyed by the numeric code as a string' {
        $Catalog = Get-CIPPSignInErrorCatalog
        $Catalog.Count | Should -BeGreaterThan 40
        foreach ($Key in $Catalog.Keys) {
            [string]$Key | Should -Match '^\d+$'
            $Catalog[$Key].Title | Should -Not -BeNullOrEmpty
            $Catalog[$Key].Explanation | Should -Not -BeNullOrEmpty
            $Catalog[$Key].Fix | Should -Not -BeNullOrEmpty
        }
    }
    It 'covers the codes helpdesk asks about, with the meanings Microsoft documents' {
        $Catalog = Get-CIPPSignInErrorCatalog
        foreach ($Code in '50126', '50053', '50057', '50055', '50056', '50076', '50079', '50074', '500121', '53000', '53001', '53003', '53004', '530032', '50158', '50105', '65001', '700016', '90072', '50097', '50020', '7000218') {
            $Catalog.Contains($Code) | Should -BeTrue -Because "AADSTS$Code is in the scope list"
        }
        $Catalog['530032'].Name | Should -Be 'BlockedByConditionalAccessOnSecurityPolicy'
        $Catalog['7000218'].Category | Should -Be 'App'
        $Catalog['50097'].Interrupt | Should -BeTrue
        $Catalog['50126'].Interrupt | Should -BeFalse
    }
    It 'never tells helpdesk to reset a password just because it is being guessed' {
        $Catalog = Get-CIPPSignInErrorCatalog
        $Catalog['50126'].Fix | Should -BeLike '*Do not reset the password only because*'
    }
}

Describe 'ConvertTo-CIPPSignInExplanation' {
    It 'names the CA policy that blocked the sign-in, the conditions it matched, and the report-only policy that would have' {
        $SignIn = New-SignIn -Code 53003 -Reason 'Access has been blocked by Conditional Access policies.' -CAStatus 'failure' -City 'Toronto' -Country 'CA' -Device $script:NoDevice -Client 'Mobile Apps and Desktop clients' -Policies @(
            (New-CAPolicy -Id 'p-mfa' -Name 'Require MFA' -Result 'success' -Grant 'Mfa' -Matched 'application,users,location')
            (New-CAPolicy -Id 'p-usa' -Name 'Allow USA Login Only' -Result 'failure' -Grant 'Block' -Matched 'application,users,devicePlatform,location,clientType,ipAddressSeenByAzureAD')
            (New-CAPolicy -Id 'p-ro' -Name 'Restrict Non-Compliant Devices to US' -Result 'reportOnlyFailure' -Grant 'Block' -Matched 'application,users,location,deviceState')
            (New-CAPolicy -Id 'p-legacy' -Name 'Block legacy authentication' -Result 'notApplied' -Grant 'Block' -NotMatched 'clientType')
        )
        $Policies = @{ 'p-usa' = (ConvertTo-Fixture @{ id = 'p-usa'; state = 'enabled'; grantControls = @{ operator = 'OR'; builtInControls = @('block') }; conditions = @{ locations = @{ includeLocations = @('All'); excludeLocations = @('loc-us') } } }) }
        $R = ConvertTo-CIPPSignInExplanation -SignIn $SignIn -Policies $Policies -NamedLocations @{ 'loc-us' = 'United States' } -TenantFilter 'contoso.com'

        $R.Outcome | Should -Be 'Failure'
        $R.ErrorCode | Should -Be 53003
        $R.Title | Should -Be "Blocked by Conditional Access: 'Allow USA Login Only'"
        ($R.BlockingPolicies -join '|') | Should -Be 'Allow USA Login Only'
        $R.Policies[0].Name | Should -Be 'Allow USA Login Only'
        $R.Policies[0].Effect | Should -Be 'Blocked this sign-in'
        $R.Policies[0].Locations | Should -Be 'include any location; exclude United States'
        $R.Policies[-1].Result | Should -Be 'notApplied'
        $R.Policies[-1].Effect | Should -Be 'Did not apply: client app type did not match'
        ($R.Details -join ' ') | Should -BeLike "*'Allow USA Login Only': Blocked this sign-in. It applied because the sign-in matched: app, user or group, device platform, location, client app type, IP address (signed in from Toronto, CA, IP 203.0.113.10, not a named location; platform Android; client Mobile Apps and Desktop clients). Policy locations: include any location; exclude United States.*"
        ($R.ReportOnlyFailures -join '|') | Should -Be 'Restrict Non-Compliant Devices to US'
        ($R.Policies | Where-Object Name -EQ 'Restrict Non-Compliant Devices to US').Enforced | Should -BeFalse
        ($R.Details -join ' ') | Should -BeLike "*Report-only policy 'Restrict Non-Compliant Devices to US' would have blocked this sign-in*"
        @($R.Flags.Key) | Should -Contain 'CABlock'
        @($R.Flags.Key) | Should -Contain 'ReportOnly'
        $R.LegacyAuth | Should -BeFalse
        $R.Fix | Should -BeLike '*exclusion group*'
        $R.Time | Should -Be '2026-10-15 12:11 CDT (17:11 UTC)'
        $R.Links.ErrorLookup | Should -Be 'https://login.microsoftonline.com/error?code=53003'
        $R.Links.EntraUserSignIns | Should -BeLike 'https://entra.microsoft.com/contoso.com/*/userId/11111111-1111-1111-1111-111111111111'
        $R.DiagnosticHint | Should -BeLike "*$($SignIn.correlationId)*"
    }

    It 'explains a failed grant (compliant device) with the operator from the policy and the missing device identity' {
        $SignIn = New-SignIn -Code 53000 -Reason 'Device is not in required device state: compliant.' -CAStatus 'failure' -Device $script:NoDevice -Policies @(
            (New-CAPolicy -Id 'p-dev' -Name 'Require compliant device or MFA' -Result 'failure' -Grant 'Mfa', 'RequireCompliantDevice' -Matched 'application,users,devicePlatform')
        )
        $Policies = @{ 'p-dev' = (ConvertTo-Fixture @{ id = 'p-dev'; state = 'enabled'; grantControls = @{ operator = 'AND'; builtInControls = @('mfa', 'compliantDevice') } }) }
        $R = ConvertTo-CIPPSignInExplanation -SignIn $SignIn -Policies $Policies

        $R.Title | Should -Be "Device is not compliant: 'Require compliant device or MFA'"
        $R.Category | Should -Be 'Device'
        $R.Policies[0].Requires | Should -Be 'Require all of: MFA, a compliant device'
        $R.Policies[0].Effect | Should -Be 'Enforced: required MFA / a compliant device and it was not met in this attempt'
        ($R.Details -join ' ') | Should -BeLike '*No device ID was sent*'
        ($R.Details -join ' ') | Should -BeLike '*compliant: no, managed: no*'
        @($R.Flags.Key) | Should -Contain 'NoDeviceId'
        @($R.Flags.Key) | Should -Contain 'CARequirement'
        @($R.Flags.Key) | Should -Not -Contain 'CABlock'
    }

    It 'treats an MFA prompt as an interrupt and names both MFA sources when per-user MFA is also on' {
        $SignIn = New-SignIn -Code 50074 -Reason 'Strong Authentication is required.' -CAStatus 'failure' -Providers 'multiConditionalAccess', 'user' -Policies @(
            (New-CAPolicy -Id 'p-mfa' -Name 'Require MFA' -Result 'failure' -Grant 'Mfa' -Matched 'application,users,location,ipAddressSeenByAzureAD')
        )
        $R = ConvertTo-CIPPSignInExplanation -SignIn $SignIn -PerUserMfaState 'enforced'

        $R.Outcome | Should -Be 'Interrupted'
        $R.Title | Should -Be 'MFA required, not completed'
        $R.MfaSource | Should -Be "Conditional Access ('Require MFA') and per-user MFA"
        ($R.Details -join ' ') | Should -BeLike "*MFA was required by Conditional Access ('Require MFA') and per-user MFA.*"
        ($R.Details -join ' ') | Should -BeLike '*Per-user MFA is enforced for this user as well as Conditional Access MFA*'
        @($R.Flags.Key) | Should -Contain 'PerUserMfa'
        ($R.Flags | Where-Object Key -EQ 'CARequirement').Severity | Should -Be 'info'
    }

    It 'falls back to per-user MFA from the account when the sign-in records no requirement provider' {
        $R = ConvertTo-CIPPSignInExplanation -SignIn (New-SignIn -Code 50076 -Reason 'MFA required') -PerUserMfaState 'enabled'
        $R.MfaSource | Should -Be 'per-user MFA (enabled on the account)'
    }

    It 'reports a lockout and the failed authentication step' {
        $SignIn = New-SignIn -Code 50053 -Reason 'The account is locked.' -City 'London' -Country 'GB' -AuthDetails @(
            @{ authenticationMethod = 'Password'; succeeded = $false; authenticationStepResultDetail = 'Incorrect password' }
        )
        $R = ConvertTo-CIPPSignInExplanation -SignIn $SignIn
        $R.Category | Should -Be 'Lockout'
        $R.Title | Should -BeLike 'Account locked*'
        @($R.Flags.Key) | Should -Contain 'Lockout'
        ($R.Details -join ' ') | Should -BeLike '*Failed step: Password - Incorrect password.*'
        $R.AuthSteps[0].Method | Should -Be 'Password'
    }

    It 'flags legacy authentication and security defaults' {
        $SignIn = New-SignIn -Code 530035 -Reason 'Blocked by security defaults' -Client 'IMAP4'
        $R = ConvertTo-CIPPSignInExplanation -SignIn $SignIn -SecurityDefaultsEnabled $true
        $R.LegacyAuth | Should -BeTrue
        @($R.Flags.Key) | Should -Contain 'LegacyAuth'
        @($R.Flags.Key) | Should -Contain 'SecurityDefaults'
        ($R.Details -join ' ') | Should -BeLike '*legacy authentication client (IMAP4)*'
    }

    It 'flags legacy authentication blocked by a CA legacy-auth policy' {
        $SignIn = New-SignIn -Code 53003 -Reason 'Blocked by CA' -Client 'Authenticated SMTP' -CAStatus 'failure' -Policies @(
            (New-CAPolicy -Id 'p-legacy' -Name 'Block legacy authentication' -Result 'failure' -Grant 'Block' -Matched 'application,users,clientType')
        )
        $R = ConvertTo-CIPPSignInExplanation -SignIn $SignIn
        $R.LegacyAuth | Should -BeTrue
        ($R.Details -join ' ') | Should -BeLike "*'Block legacy authentication': Blocked this sign-in.*(client Authenticated SMTP)*"
        (New-SignIn -Client 'Mobile Apps and Desktop clients' | ForEach-Object { ConvertTo-CIPPSignInExplanation -SignIn $_ }).LegacyAuth | Should -BeFalse
    }

    It 'shows a report-only failure on a successful sign-in without calling it a failure' {
        $SignIn = New-SignIn -Code 0 -CAStatus 'success' -Policies @(
            (New-CAPolicy -Id 'p-ro' -Name 'Block outside US (report-only)' -Result 'reportOnlyFailure' -Grant 'Block' -Matched 'application,users,location')
            (New-CAPolicy -Id 'p-ne' -Name 'Sign-in frequency on unmanaged' -Result 'notEnoughInformationReporting' -Session 'SignInFrequency' -Matched 'none')
        )
        $R = ConvertTo-CIPPSignInExplanation -SignIn $SignIn
        $R.Outcome | Should -Be 'Success'
        $R.Title | Should -Be 'Signed in successfully'
        $R.Fix | Should -BeNullOrEmpty
        $R.BlockingPolicies.Count | Should -Be 0
        ($R.ReportOnlyFailures -join '|') | Should -Be 'Block outside US (report-only)'
        $R.Policies[0].Effect | Should -Be 'Report-only: would have blocked this sign-in. Not enforced'
        ($R.Policies | Where-Object Result -EQ 'notEnoughInformationReporting').Enforced | Should -BeFalse
    }

    It 'calls out a risk-based block' {
        $SignIn = New-SignIn -Code 53003 -Reason 'Blocked by CA' -CAStatus 'failure' -Risk 'high' -RiskState 'atRisk' -Policies @(
            (New-CAPolicy -Id 'p-risk' -Name 'Sign-in risk high - block' -Result 'failure' -Grant 'Block' -Matched 'application,users,signInRisk')
        )
        $R = ConvertTo-CIPPSignInExplanation -SignIn $SignIn
        $R.RiskBlock | Should -BeTrue
        @($R.Flags.Key) | Should -Contain 'RiskBlock'
        ($R.Details -join ' ') | Should -BeLike '*rated this sign-in risk high (state atRisk)*The risk is why it was blocked.*'
    }

    It 'falls back to Microsoft''s reason for a code it does not know' {
        $R = ConvertTo-CIPPSignInExplanation -SignIn (New-SignIn -Code 123456 -Reason 'Something unusual happened.')
        $R.Title | Should -Be 'Error 123456'
        $R.Explanation | Should -Be "Microsoft's reason: Something unusual happened."
        $R.Fix | Should -BeLike '*not in CIPP*'
        $R.Category | Should -Be 'Other'
    }
}

Describe 'Get-CIPPSignInExplanation' {
    BeforeEach {
        $script:F = @{ Light = @(); Full = @{}; NoP1 = $false; Policies = @(); PerUser = 'disabled' }
        $script:Uris = [System.Collections.Generic.List[string]]::new()
        Mock New-GraphGetRequest {
            $script:Uris.Add([string]$uri)
            if ($uri -like '*auditLogs/signIns?*') {
                if ($script:F.NoP1) { throw "Neither tenant is B2C or tenant doesn't have premium license" }
                return $script:F.Light
            }
            if ($uri -like '*/users/*') { return [pscustomobject]@{ id = '11111111-1111-1111-1111-111111111111'; displayName = 'Alex Example'; userPrincipalName = 'alex@contoso.com'; accountEnabled = $true; perUserMfaState = $script:F.PerUser; userType = 'Member'; onPremisesSyncEnabled = $null } }
            if ($uri -like '*identitySecurityDefaultsEnforcementPolicy*') { return [pscustomobject]@{ isEnabled = $false } }
            if ($uri -like '*conditionalAccess/policies*') { return $script:F.Policies }
            if ($uri -like '*namedLocations*') { return @() }
            throw "unexpected GET $uri"
        }
        Mock New-GraphBulkRequest {
            foreach ($R in $Requests) {
                [pscustomobject]@{ id = $R.id; status = 200; body = $script:F.Full[$R.id] }
            }
        }
        $script:SetFixture = {
            param($SignIns)
            $script:F.Light = @($SignIns)
            foreach ($S in $SignIns) { $script:F.Full[[string]$S.id] = $S }
        }
    }

    It 'marks an MFA prompt followed by a success with the same correlation ID as resolved' {
        $Corr = '22222222-2222-2222-2222-222222222222'
        & $script:SetFixture @(
            (New-SignIn -Id 'ok' -Correlation $Corr -When '2026-10-15T17:12:30Z' -Code 0 -CAStatus 'success')
            (New-SignIn -Id 'prompt' -Correlation $Corr -When '2026-10-15T17:12:00Z' -Code 50074 -Reason 'Strong Authentication is required.' -CAStatus 'failure' -Policies @(
                    (New-CAPolicy -Id 'p-mfa' -Name 'Require MFA' -Result 'failure' -Grant 'Mfa')
                ))
        )
        $R = Get-CIPPSignInExplanation -TenantFilter 'contoso.com' -UserPrincipalName 'alex@contoso.com'

        $R.SignIns.Count | Should -Be 2
        $Prompt = $R.SignIns | Where-Object RequestId -EQ 'prompt'
        $Prompt.ResolvedLater | Should -BeTrue
        $Prompt.Fix | Should -BeLike 'Nothing to do*'
        $R.Counts.Interrupts | Should -Be 1
        $R.Counts.Failures | Should -Be 0
        $R.Counts.Successes | Should -Be 1
        $R.Headline | Should -BeLike 'No unresolved failures*'
        $R.LatestSuccess | Should -Be '2026-10-15 12:12 CDT (17:12 UTC)'
        # The list is filtered on the user's object ID once the user is known; policies are fetched because one failed.
        ($script:Uris | Where-Object { $_ -like '*auditLogs/signIns?*' } | Select-Object -First 1) | Should -BeLike '*userId%20eq%20%2711111111-1111-1111-1111-111111111111%27*'
        @($script:Uris | Where-Object { $_ -like '*conditionalAccess/policies*' }).Count | Should -Be 1
        $R.SummaryText | Should -BeLike '*Sign-in failure explanation (CIPP)*'
    }

    It 'summarises a lockout and wrong passwords from several countries as a likely attack' {
        & $script:SetFixture @(
            (New-SignIn -Id 'ok' -When '2026-10-15T14:00:00Z' -Code 0 -Country 'US' -Ip '203.0.113.10')
            (New-SignIn -Id 'b1' -When '2026-10-15T16:00:00Z' -Code 50126 -Reason 'Invalid password' -Country 'GB' -City 'London' -Ip '198.51.100.1')
            (New-SignIn -Id 'b2' -When '2026-10-15T16:01:00Z' -Code 50126 -Reason 'Invalid password' -Country 'NL' -City 'Amsterdam' -Ip '198.51.100.2')
            (New-SignIn -Id 'b3' -When '2026-10-15T16:02:00Z' -Code 50053 -Reason 'The account is locked.' -Country 'GB' -City 'London' -Ip '198.51.100.3')
        )
        $R = Get-CIPPSignInExplanation -TenantFilter 'contoso.com' -UserPrincipalName 'alex@contoso.com' -Hours 48

        $R.PasswordAttempts.Count | Should -Be 3
        $R.PasswordAttempts.Lockouts | Should -Be 1
        $R.PasswordAttempts.DistinctIPs | Should -Be 3
        $R.PasswordAttempts.LikelyAttack | Should -BeTrue
        $R.PasswordAttempts.Summary | Should -BeLike '*do not reset the password only because of this*'
        $R.SignIns[0].RequestId | Should -Be 'b3'
        $R.Headline | Should -BeLike 'Account locked*'
        $R.ByError[0].ErrorCode | Should -Be 50126
        $R.ByError[0].Count | Should -Be 2
        $R.Hours | Should -Be 48
    }

    It 'returns a clear message instead of failing when the tenant has no Entra ID P1' {
        $script:F.NoP1 = $true
        $R = Get-CIPPSignInExplanation -TenantFilter 'contoso.com' -UserPrincipalName 'alex@contoso.com'
        $R.LicenseRequired | Should -BeTrue
        @($R.SignIns).Count | Should -Be 0
        $R.Headline | Should -BeLike '*no Entra ID P1*'
        $R.User.PerUserMfaState | Should -Be 'disabled'
        $R.SummaryText | Should -BeLike '*no Entra ID P1*'
        Should -Invoke New-GraphBulkRequest -Times 0 -Exactly
    }

    It 'rethrows other Graph errors' {
        Mock New-GraphGetRequest { if ($uri -like '*auditLogs/signIns?*') { throw 'Forbidden: Insufficient privileges' } }
        { Get-CIPPSignInExplanation -TenantFilter 'contoso.com' -UserPrincipalName 'alex@contoso.com' } | Should -Throw '*Insufficient privileges*'
    }

    It 'searches by correlation or request ID and rejects a value that is not a GUID' {
        $Corr = '33333333-3333-3333-3333-333333333333'
        & $script:SetFixture @(New-SignIn -Id 'c1' -Correlation $Corr -Code 53003 -Reason 'Blocked' -CAStatus 'failure')
        $R = Get-CIPPSignInExplanation -TenantFilter 'contoso.com' -CorrelationId $Corr
        ($script:Uris | Where-Object { $_ -like '*auditLogs/signIns?*' } | Select-Object -First 1) | Should -BeLike "*correlationId%20eq%20%27$Corr%27%20or%20id%20eq%20%27$Corr%27*"
        $R.UserPrincipalName | Should -Be 'alex@contoso.com'
        $R.SignIns[0].ErrorCode | Should -Be 53003
        { Get-CIPPSignInExplanation -TenantFilter 'contoso.com' -CorrelationId 'not-a-guid' } | Should -Throw '*not a correlation ID*'
        { Get-CIPPSignInExplanation -TenantFilter 'contoso.com' } | Should -Throw '*user principal name*'
    }

    It 'adds the non-interactive filter only when asked, and says when nothing was found' {
        & $script:SetFixture @()
        $R = Get-CIPPSignInExplanation -TenantFilter 'contoso.com' -UserPrincipalName 'alex@contoso.com' -IncludeNonInteractive
        ($script:Uris | Where-Object { $_ -like '*auditLogs/signIns?*' } | Select-Object -First 1) | Should -BeLike '*nonInteractiveUser*'
        $R.Headline | Should -BeLike 'No sign-ins for alex@contoso.com in the last 24 hours*'
        $R.Counts.Total | Should -Be 0
    }

    It 'keeps going without CA details when the detail batch fails' {
        & $script:SetFixture @(New-SignIn -Id 'x1' -Code 50126 -Reason 'Invalid password')
        Mock New-GraphBulkRequest { throw 'batch failed' }
        $R = Get-CIPPSignInExplanation -TenantFilter 'contoso.com' -UserPrincipalName 'alex@contoso.com'
        $R.SignIns[0].ErrorCode | Should -Be 50126
        ($R.Errors -join ' ') | Should -BeLike '*Full sign-in details could not be read*'
    }
}

Describe 'ConvertTo-CIPPSignInExplanationNote' {
    BeforeAll {
        $script:Bundle = [pscustomobject]@{
            Tenant = 'contoso.com'; UserPrincipalName = 'alex@contoso.com'; CorrelationId = ''; Hours = 24; IncludeNonInteractive = $false
            WindowStart = ConvertTo-CIPPCentralTime -Value '2026-10-14T17:00:00Z'; WindowEnd = ConvertTo-CIPPCentralTime -Value '2026-10-15T17:00:00Z'
            GeneratedAt = ConvertTo-CIPPCentralTime -Value '2026-10-15T17:00:00Z'; LicenseRequired = $false; SecurityDefaultsEnabled = $false
            User = [pscustomobject]@{ AccountEnabled = $true; PerUserMfaState = 'disabled'; Synced = $false }
            Headline = 'Blocked by Conditional Access <b>now</b>'
            Counts = [ordered]@{ Total = 3; Failures = 1; Interrupts = 1; Successes = 1; Shown = 3 }
            LatestSuccess = '2026-10-15 09:00 CDT (14:00 UTC)'; Truncated = $false; PasswordAttempts = $null
            SignIns = @(ConvertTo-CIPPSignInExplanation -SignIn (New-SignIn -Code 53003 -Reason 'Blocked' -CAStatus 'failure' -Policies @(
                        (New-CAPolicy -Id 'p1' -Name 'Allow USA Login Only' -Result 'failure' -Grant 'Block' -Matched 'application,users,location')
                    )) -TenantFilter 'contoso.com')
        }
    }
    It 'renders ConnectWise-safe Markdown with the code, the policy, the fix and the correlation ID' {
        $Text = ConvertTo-CIPPSignInExplanationNote -Bundle $script:Bundle
        $Text | Should -BeLike '*AADSTS53003*'
        $Text | Should -BeLike "*'Allow USA Login Only'*"
        $Text | Should -BeLike '**Fix:**'
        $Text | Should -BeLike "*Correlation ID: $($script:Bundle.SignIns[0].CorrelationId)*"
        $Text | Should -BeLike '*Times are US Central*'
        $Text | Should -Not -BeLike '*<b>*'
        ($Text -split "`n" | Where-Object { $_ -like '#*' -or $_ -like '- *' }).Count | Should -Be 0
    }
    It 'stays under the length cap' {
        $Text = ConvertTo-CIPPSignInExplanationNote -Bundle $script:Bundle -MaxLength 600
        $Text.Length | Should -BeLessOrEqual 600
    }
}
