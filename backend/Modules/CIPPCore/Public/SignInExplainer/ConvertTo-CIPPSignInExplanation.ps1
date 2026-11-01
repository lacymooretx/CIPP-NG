function ConvertTo-CIPPSignInExplanation {
    <#
    .SYNOPSIS
        Turns one Entra sign-in log entry into a plain-language diagnosis: what happened, why, and what to do.
    .DESCRIPTION
        Pure function (no Graph calls), so it can be tested from fixtures. Input is one beta auditLogs/signIns
        object. Optional context: Policies (CA policy id -> policy object from identity/conditionalAccess/policies,
        used for the grant operator, state and location lists), NamedLocations (id -> display name), the user's
        per-user MFA state, and whether security defaults are on.

        Shape facts verified live 2026-11-01 (aspendora.com, 3endt.com): appliedConditionalAccessPolicies entries
        carry displayName, result, enforcedGrantControls (Mfa, Block, RequireCompliantDevice, MfaAndChangePassword),
        enforcedSessionControls, conditionsSatisfied / conditionsNotSatisfied as comma-separated strings ('none' when
        empty, and 'ipAddressSeenByAzureAD' next to 'location'), and authenticationStrength. Results seen:
        success, failure, notApplied, reportOnlySuccess, reportOnlyFailure, reportOnlyInterrupted,
        reportOnlyNotApplied, and the undocumented notEnoughInformationReporting. An MFA prompt (50074) marks the
        MFA policy 'failure' and conditionalAccessStatus 'failure' even when the user then completes MFA, so the
        caller checks for a later success with the same correlation ID (ResolvedLater).
        Aspendora fork addition (Vikunja CIPP-10).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$SignIn,
        [hashtable]$Policies = @{},
        [hashtable]$NamedLocations = @{},
        [string]$PerUserMfaState,
        $SecurityDefaultsEnabled,
        [string]$TenantFilter,
        $Catalog
    )

    if (-not $Catalog) { $Catalog = Get-CIPPSignInErrorCatalog }

    $Code = 0
    [void][int]::TryParse("$($SignIn.status.errorCode)", [ref]$Code)
    # String key on purpose: an int index into an ordered dictionary is positional.
    $Entry = if ($Code -ne 0) { $Catalog["$Code"] } else { $null }
    $Outcome = if ($Code -eq 0) { 'Success' } elseif ($Entry -and $Entry.Interrupt) { 'Interrupted' } else { 'Failure' }

    $ConditionText = @{
        application = 'app'; users = 'user or group'; location = 'location'; ipAddressSeenByAzureAD = 'IP address'
        devicePlatform = 'device platform'; clientType = 'client app type'; signInRisk = 'sign-in risk'; userRisk = 'user risk'
        servicePrincipalRisk = 'service principal risk'; insiderRisk = 'insider risk'; deviceState = 'device filter'; devices = 'device filter'
        authenticationFlow = 'authentication flow (device code / authentication transfer)'; time = 'time'; authenticationContext = 'authentication context'
    }
    $GrantText = @{
        mfa = 'MFA'; requirecompliantdevice = 'a compliant device'; requiredomainjoineddevice = 'a hybrid joined device'
        requireapprovedapp = 'an approved client app'; requirecompliantapp = 'an app protection policy'; passwordchange = 'a password change'
        mfaandchangepassword = 'MFA and a password change'; requireauthenticationstrength = 'an authentication strength'
    }
    $SessionText = @{
        signinfrequency = 'sign-in frequency'; persistentbrowsersessionmode = 'no persistent browser'; appenforcedrestrictions = 'app enforced restrictions'
        cloudappsecurity = 'Defender for Cloud Apps session'; signintokenprotection = 'token protection'; apptokenprotection = 'token protection (apps)'
        continuousaccessevaluation = 'continuous access evaluation'; disableresiliencedefaults = 'no resilience defaults'
    }
    $Split = { param($Value) @(([string]$Value -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne 'none' }) }
    $Friendly = { param($List, $Map) @($List | ForEach-Object { if ($Map.ContainsKey([string]$_)) { $Map[[string]$_] } else { [string]$_ } }) }
    $Quote = { param($Names) (@($Names) | ForEach-Object { "'$_'" }) -join ', ' }
    $YesNo = { param($Value) if ($Value -eq $true) { 'yes' } elseif ($Value -eq $false) { 'no' } else { 'unknown' } }

    $Where = (@($SignIn.location.city, $SignIn.location.state, $SignIn.location.countryOrRegion) | Where-Object { $_ }) -join ', '
    $Networks = @($SignIn.networkLocationDetails | ForEach-Object { @($_.networkNames) } | Where-Object { $_ })
    $ClientApp = [string]$SignIn.clientAppUsed
    # Conditional Access's "legacy authentication clients" = Exchange ActiveSync + "Other clients"; these are the
    # clientAppUsed values the sign-in log reports for them. Modern EWS/MAPI show as "Mobile Apps and Desktop clients".
    $LegacyClients = @('Exchange ActiveSync', 'IMAP4', 'POP3', 'Authenticated SMTP', 'Exchange Web Services', 'MAPI Over HTTP',
        'Offline Address Book', 'Outlook Anywhere (RPC over HTTP)', 'AutoDiscover', 'Exchange Online PowerShell',
        'Reporting Web Services', 'Universal Outlook', 'Other clients')
    $Legacy = [bool]($ClientApp -and $LegacyClients -contains $ClientApp)

    # --- Conditional Access policies ---
    $Rank = @{ failure = 0; success = 1; reportOnlyFailure = 2; reportOnlyInterrupted = 3; notEnoughInformationReporting = 4; reportOnlySuccess = 5; notApplied = 6; reportOnlyNotApplied = 7; notEnabled = 8 }
    $PolicyRows = foreach ($P in @($SignIn.appliedConditionalAccessPolicies | Where-Object { $_ })) {
        $Result = [string]$P.result
        $Def = if ($P.id) { $Policies[[string]$P.id] } else { $null }
        $Grants = @($P.enforcedGrantControls | Where-Object { $_ })
        $Sessions = @($P.enforcedSessionControls | Where-Object { $_ })
        $IsBlock = $Grants -contains 'Block'
        $Parts = @(& $Friendly @($Grants | Where-Object { $_ -ne 'Block' } | ForEach-Object { ([string]$_).ToLower() }) $GrantText)
        if ($P.authenticationStrength.authenticationStrengthId) {
            $StrengthName = $P.authenticationStrength.displayName ?? $Def.grantControls.authenticationStrength.displayName
            $Parts += $(if ($StrengthName) { "authentication strength '$StrengthName'" } else { 'an authentication strength' })
        }
        $Joiner = switch ([string]$Def.grantControls.operator) { 'AND' { 'all of: ' } 'OR' { 'one of: ' } default { '' } }
        $Requires = if ($IsBlock) { 'Block access' }
        elseif ($Parts.Count -gt 1) { "Require $Joiner$($Parts -join ', ')" }
        elseif ($Parts.Count -eq 1) { "Require $($Parts[0])" }
        else { $null }
        $SessionList = @(& $Friendly @($Sessions | ForEach-Object { ([string]$_).ToLower() }) $SessionText)
        if (-not $Requires -and $SessionList.Count) { $Requires = "Session: $($SessionList -join ', ')" }
        $What = if ($IsBlock) { 'blocked' } elseif ($Parts.Count) { "required $($Parts -join ' / ')" } else { 'applied session controls' }

        $Matched = @(& $Split $P.conditionsSatisfied)
        $NotMatched = @(& $Split $P.conditionsNotSatisfied)
        $NotMatchedText = (& $Friendly $NotMatched $ConditionText) -join ', '
        $Effect = switch ($Result) {
            'failure' { if ($IsBlock) { 'Blocked this sign-in' } else { "Enforced: $What and it was not met in this attempt" } }
            'success' { if ($Parts.Count -or $IsBlock) { "Applied; requirement met ($($Parts -join ' / '))" } else { "Applied ($($SessionList -join ', '))" } }
            'notApplied' { if ($NotMatchedText) { "Did not apply: $NotMatchedText did not match" } else { 'Did not apply' } }
            'notEnabled' { 'Policy is turned off' }
            'reportOnlyFailure' { "Report-only: would have $(if ($IsBlock) { 'blocked this sign-in' } else { "failed ($What)" }). Not enforced" }
            'reportOnlyInterrupted' { "Report-only: would have prompted ($What). Not enforced" }
            'reportOnlySuccess' { 'Report-only: would have been satisfied' }
            'reportOnlyNotApplied' { 'Report-only: would not apply' }
            'notEnoughInformationReporting' { 'Report-only: not enough information in this sign-in to evaluate it' }
            default { "Result: $Result" }
        }
        # Wording for the narrative line about a report-only policy that would have failed.
        $Would = if ($IsBlock) { 'would have blocked this sign-in' } elseif ($Result -eq 'reportOnlyInterrupted') { "would have prompted ($What)" } else { "would have failed ($What)" }

        $LocationText = $null
        if ($Def.conditions.locations) {
            $Name = { param($Id) switch ([string]$Id) { 'All' { 'any location' } 'AllTrusted' { 'all trusted locations' } default { $NamedLocations[[string]$Id] ?? $Id } } }
            $Inc = @($Def.conditions.locations.includeLocations | ForEach-Object { & $Name $_ })
            $Exc = @($Def.conditions.locations.excludeLocations | ForEach-Object { & $Name $_ })
            $LocationText = (@($(if ($Inc.Count) { "include $($Inc -join ', ')" }), $(if ($Exc.Count) { "exclude $($Exc -join ', ')" })) | Where-Object { $_ }) -join '; '
        }

        [pscustomobject]@{
            Id                    = [string]$P.id
            Name                  = [string]$P.displayName
            Result                = $Result
            Enforced              = -not ($Result -like 'reportOnly*' -or $Result -eq 'notEnoughInformationReporting')
            Effect                = $Effect
            Requires              = $Requires
            ConditionsMatched     = (& $Friendly $Matched $ConditionText) -join ', '
            ConditionsNotMatched  = $NotMatchedText
            MatchedKeys           = $Matched
            GrantControls         = $Grants
            SessionControls       = $SessionList
            SessionNotSatisfied   = @($P.sessionControlsNotSatisfied | Where-Object { $_ })
            AuthStrengthResult    = [string]$P.authenticationStrength.authenticationStrengthResult
            State                 = [string]$Def.state
            Locations             = $LocationText
            Would                 = $Would
            SortRank              = $(if ($Rank.ContainsKey($Result)) { $Rank[$Result] } else { 9 })
        }
    }
    $PolicyRows = @($PolicyRows | Sort-Object -Property SortRank, Name)
    $Blocking = @($PolicyRows | Where-Object Result -EQ 'failure')
    $ReportOnlyHits = @($PolicyRows | Where-Object { $_.Result -in @('reportOnlyFailure', 'reportOnlyInterrupted') })

    # --- Device, risk, MFA ---
    $Device = [pscustomobject]@{
        Name      = [string]$SignIn.deviceDetail.displayName
        DeviceId  = [string]$SignIn.deviceDetail.deviceId
        OS        = [string]$SignIn.deviceDetail.operatingSystem
        Browser   = [string]$SignIn.deviceDetail.browser
        Compliant = $SignIn.deviceDetail.isCompliant
        Managed   = $SignIn.deviceDetail.isManaged
        TrustType = [string]$SignIn.deviceDetail.trustType
    }
    $RiskLevel = [string]$SignIn.riskLevelDuringSignIn
    $RiskState = [string]$SignIn.riskState
    $RiskTypes = @($SignIn.riskEventTypes_v2 | Where-Object { $_ })
    $Risky = ($RiskLevel -in @('low', 'medium', 'high')) -or ($RiskState -in @('atRisk', 'confirmedCompromised'))
    $RiskPolicyBlock = @($Blocking | Where-Object { $_.MatchedKeys -contains 'signInRisk' -or $_.MatchedKeys -contains 'userRisk' })
    $RiskBlock = $Outcome -ne 'Success' -and ($RiskPolicyBlock.Count -gt 0 -or ($Risky -and $Code -in @(53003, 530032, 50131, 53004, 50142, 50135, 53011, 530034)))

    $MfaCodes = @(50074, 50076, 50079, 50072, 500121, 50078, 53004, 53010, 50158)
    $MfaRelated = $Code -in $MfaCodes
    $MfaPolicies = @($PolicyRows | Where-Object { $_.Enforced -and $_.Result -in @('success', 'failure') -and ($_.GrantControls -contains 'Mfa' -or $_.GrantControls -contains 'MfaAndChangePassword' -or $_.Requires -like '*authentication strength*') })
    $ProviderText = @{
        user = 'per-user MFA'; request = 'the app asked for MFA'; securityDefaults = 'security defaults'
        mfaRegistrationRequiredBySecurityDefaults = 'security defaults (registration)'; baselineProtection = 'baseline protection'
        tenantSessionRiskPolicy = 'an Identity Protection risk policy'; riskBasedPolicy = 'an Identity Protection risk policy'; accountCompromisePolicies = 'an Identity Protection risk policy'
        mfaRegistrationRequiredByIdentityProtectionPolicy = 'the Identity Protection MFA registration policy'
        enforcedForCspAdmins = 'partner (CSP) admin MFA'; crossTenantOutboundRule = 'cross-tenant access settings'; authenticationStrengths = 'an authentication strength'
    }
    $Sources = [System.Collections.Generic.List[string]]::new()
    foreach ($Provider in @($SignIn.authenticationRequirementPolicies | ForEach-Object { [string]$_.requirementProvider } | Where-Object { $_ } | Select-Object -Unique)) {
        $Text = if ($Provider -like '*ConditionalAccess*') {
            if ($MfaPolicies.Count) { "Conditional Access ($(& $Quote $MfaPolicies.Name))" } else { 'Conditional Access' }
        } elseif ($ProviderText.ContainsKey($Provider)) { $ProviderText[$Provider] } else { $Provider }
        if (-not $Sources.Contains($Text)) { $Sources.Add($Text) }
    }
    if ($Sources.Count -eq 0 -and $MfaPolicies.Count) { $Sources.Add("Conditional Access ($(& $Quote $MfaPolicies.Name))") }
    $PerUserOn = $PerUserMfaState -in @('enabled', 'enforced')
    if ($PerUserOn -and -not $Sources.Contains('per-user MFA')) { $Sources.Add("per-user MFA ($PerUserMfaState on the account)") }
    $MfaSource = if ($Sources.Count) { $Sources -join ' and ' } else { $null }

    $FailedStep = @($SignIn.authenticationDetails | Where-Object { $_.succeeded -eq $false }) | Select-Object -Last 1
    $Steps = @($SignIn.authenticationDetails | Where-Object { $_ } | ForEach-Object {
            [pscustomobject]@{ Method = [string]$_.authenticationMethod; Succeeded = $_.succeeded; Detail = [string]$_.authenticationStepResultDetail }
        })

    # --- Narrative ---
    $Details = [System.Collections.Generic.List[string]]::new()
    foreach ($B in $Blocking) {
        $Context = [System.Collections.Generic.List[string]]::new()
        if ($B.MatchedKeys -contains 'location' -or $B.MatchedKeys -contains 'ipAddressSeenByAzureAD') {
            $Context.Add("signed in from $(if ($Where) { $Where } else { 'an unknown location' })$(if ($SignIn.ipAddress) { ", IP $($SignIn.ipAddress)" })$(if ($Networks.Count) { ", network $(& $Quote $Networks)" } else { ', not a named location' })")
        }
        if ($B.MatchedKeys -contains 'devicePlatform' -and $Device.OS) { $Context.Add("platform $($Device.OS)") }
        if ($B.MatchedKeys -contains 'clientType' -and $ClientApp) { $Context.Add("client $ClientApp") }
        if ($B.MatchedKeys -contains 'signInRisk' -and $RiskLevel) { $Context.Add("sign-in risk $RiskLevel") }
        if ($B.MatchedKeys -contains 'deviceState' -or $B.MatchedKeys -contains 'devices') { $Context.Add("device compliant: $(& $YesNo $Device.Compliant), managed: $(& $YesNo $Device.Managed)") }
        $Line = "'$($B.Name)': $($B.Effect). It applied because the sign-in matched: $($B.ConditionsMatched)"
        if ($Context.Count) { $Line += " ($($Context -join '; '))" }
        if ($B.Locations) { $Line += ". Policy locations: $($B.Locations)" }
        $Details.Add("$Line.")
    }
    $MfaBlock = @($Blocking | Where-Object { $_.GrantControls -contains 'Mfa' -or $_.GrantControls -contains 'MfaAndChangePassword' })
    if ($MfaRelated -or ($Outcome -ne 'Success' -and $MfaBlock.Count -gt 0)) {
        $Details.Add("MFA was required by $(if ($MfaSource) { $MfaSource } else { 'a source the sign-in log does not record' }).")
    }
    if ($PerUserOn -and $MfaPolicies.Count) {
        $Details.Add("Per-user MFA is $PerUserMfaState for this user as well as Conditional Access MFA. Per-user MFA ignores Conditional Access exclusions such as trusted locations, so it can prompt where Conditional Access would not; Microsoft recommends using Conditional Access only.")
    }
    if ($FailedStep -and $Outcome -ne 'Success') {
        $Details.Add("Failed step: $($FailedStep.authenticationMethod)$(if ($FailedStep.authenticationStepResultDetail) { " - $($FailedStep.authenticationStepResultDetail)" }).")
    }
    if ($Code -in @(53000, 53001, 50155) -or ($Entry -and $Entry.Category -eq 'Device' -and $Outcome -eq 'Failure')) {
        $DevLine = "Device: $(if ($Device.Name) { $Device.Name } else { '(no name sent)' }), $("$($Device.OS) $($Device.Browser)".Trim()), compliant: $(& $YesNo $Device.Compliant), managed: $(& $YesNo $Device.Managed), join type: $(if ($Device.TrustType) { $Device.TrustType } else { 'none' })."
        if (-not $Device.DeviceId) { $DevLine += ' No device ID was sent, so Entra could not check the device at all; this points to the browser or app, not the device''s compliance.' }
        $Details.Add($DevLine)
    }
    if ($Legacy) {
        $Details.Add("This came from a legacy authentication client ($ClientApp), which cannot do MFA. Conditional Access legacy-auth blocks and security defaults stop these. The fix is to move the app or device to modern authentication, not to exclude the user.")
    }
    if ($Risky) {
        $Details.Add("Identity Protection rated this sign-in risk $RiskLevel (state $RiskState)$(if ($RiskTypes.Count) { ": $($RiskTypes -join ', ')" }).$(if ($RiskBlock) { ' The risk is why it was blocked.' })")
    } elseif ($RiskLevel -eq 'hidden') {
        $Details.Add('Risk details are hidden: they need an Entra ID P2 licence.')
    }
    foreach ($R in $ReportOnlyHits) {
        $Details.Add("Report-only policy '$($R.Name)' $($R.Would). It did not affect this sign-in, but it will once the policy is turned on.")
    }

    $Flags = [System.Collections.Generic.List[object]]::new()
    $Flag = { param($Key, $Severity, $Text) $Flags.Add([pscustomobject]@{ Key = $Key; Severity = $Severity; Text = $Text }) }
    if ($Code -eq 50053) { & $Flag 'Lockout' 'error' 'Account locked or malicious IP' }
    if ($Legacy) { & $Flag 'LegacyAuth' 'warning' "Legacy authentication ($ClientApp)" }
    if ($RiskBlock) { & $Flag 'RiskBlock' 'error' "Blocked because of risk ($RiskLevel)" }
    elseif ($Risky) { & $Flag 'Risk' 'warning' "Risky sign-in ($RiskLevel)" }
    if ($Code -eq 530035 -or ($Legacy -and $SecurityDefaultsEnabled -eq $true -and $Outcome -ne 'Success')) { & $Flag 'SecurityDefaults' 'warning' 'Security defaults' }
    if ($PerUserOn) { & $Flag 'PerUserMfa' 'info' "Per-user MFA $PerUserMfaState" }
    # An MFA prompt also marks its policy 'failure', so only a Block grant is called a block.
    $HardBlocks = @($Blocking | Where-Object { $_.GrantControls -contains 'Block' })
    if ($HardBlocks.Count) { & $Flag 'CABlock' 'error' "Blocked by Conditional Access: $(& $Quote $HardBlocks.Name)" }
    elseif ($Blocking.Count) { & $Flag 'CARequirement' $(if ($Outcome -eq 'Interrupted') { 'info' } else { 'warning' }) "Conditional Access requirement not met: $(& $Quote $Blocking.Name)" }
    if ($ReportOnlyHits.Count) { & $Flag 'ReportOnly' 'info' "Report-only would fail: $(& $Quote $ReportOnlyHits.Name)" }
    if ($Code -in @(53000, 53001) -and -not $Device.DeviceId) { & $Flag 'NoDeviceId' 'warning' 'No device identity sent' }

    $Title = if ($Code -eq 0) { 'Signed in successfully' }
    elseif ($Entry -and $Blocking.Count -and $Entry.Category -in @('ConditionalAccess', 'Device')) { "$($Entry.Title): $(& $Quote $Blocking.Name)" }
    elseif ($Entry) { $Entry.Title }
    elseif ($Blocking.Count) { "Error $Code (Conditional Access: $(& $Quote $Blocking.Name))" }
    else { "Error $Code" }
    $Explanation = if ($Code -eq 0) { 'The sign-in succeeded.' } elseif ($Entry) { $Entry.Explanation } else { "Microsoft's reason: $([string]$SignIn.status.failureReason)" }
    $Fix = if ($Code -eq 0) { $null }
    elseif ($Entry) { $Entry.Fix }
    elseif ($Blocking.Count) { $Catalog['53003'].Fix }
    else { "This code is not in CIPP's table. Look it up with the link below and run the Sign-in Diagnostic with the correlation ID." }

    $Time = ConvertTo-CIPPCentralTime -Value $SignIn.createdDateTime
    $CorrelationId = [string]$SignIn.correlationId
    [pscustomobject]@{
        RequestId             = [string]$SignIn.id
        CorrelationId         = $CorrelationId
        Time                  = $Time.Display
        TimeUtc               = $Time.Utc
        Outcome               = $Outcome
        ResolvedLater         = $false
        ErrorCode             = $Code
        ErrorName             = if ($Entry) { $Entry.Name } else { $null }
        Category              = if ($Code -eq 0) { 'Success' } elseif ($Entry) { $Entry.Category } elseif ($Blocking.Count) { 'ConditionalAccess' } else { 'Other' }
        Title                 = $Title
        FailureReason         = [string]$SignIn.status.failureReason
        AdditionalDetails     = [string]$SignIn.status.additionalDetails
        Explanation           = $Explanation
        Details               = @($Details)
        Fix                   = $Fix
        UserPrincipalName     = [string]$SignIn.userPrincipalName
        UserId                = [string]$SignIn.userId
        App                   = [string]$SignIn.appDisplayName
        Resource              = [string]$SignIn.resourceDisplayName
        ClientApp             = $ClientApp
        LegacyAuth            = $Legacy
        Interactive           = $SignIn.isInteractive
        IPAddress             = [string]$SignIn.ipAddress
        Location              = $Where
        NamedNetworks         = $Networks
        Device                = $Device
        ConditionalAccess     = [string]$SignIn.conditionalAccessStatus
        AuthRequirement       = [string]$SignIn.authenticationRequirement
        MfaSource             = $MfaSource
        AuthSteps             = $Steps
        RiskLevel             = $RiskLevel
        RiskState             = $RiskState
        RiskEventTypes        = $RiskTypes
        RiskBlock             = [bool]$RiskBlock
        BlockingPolicies      = @($Blocking | ForEach-Object { $_.Name })
        ReportOnlyFailures    = @($ReportOnlyHits | ForEach-Object { $_.Name })
        Policies              = @($PolicyRows | Select-Object -Property * -ExcludeProperty SortRank, MatchedKeys, Would)
        Flags                 = @($Flags)
        Links                 = [pscustomobject]@{
            ErrorLookup      = if ($Code -ne 0) { "https://login.microsoftonline.com/error?code=$Code" } else { $null }
            EntraUserSignIns = if ($SignIn.userId -and $TenantFilter) { "https://entra.microsoft.com/$TenantFilter/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/SignIns/userId/$($SignIn.userId)" } else { $null }
            SignInDiagnostic = 'https://learn.microsoft.com/entra/identity/monitoring-health/howto-use-sign-in-diagnostics'
        }
        DiagnosticHint        = "Entra admin center > Diagnose and solve problems > Sign-in diagnostic > Troubleshoot, then search for correlation ID $CorrelationId (or request ID $([string]$SignIn.id))."
    }
}
