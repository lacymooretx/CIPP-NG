function Test-CIPPSmsMfaReadiness {
    <#
    .SYNOPSIS
        Evaluates whether a tenant can disable SMS and voice MFA without locking anyone out, from already-collected data.
    .DESCRIPTION
        Pure rules, no Graph or table calls; Get-CIPPSmsMfaReadiness collects the inputs. Returns
        @{ Summary; Users; Findings }. Each finding has a stable Key, so the weekly SmsMfaReliance alert notifies once
        per problem and resolves when it is fixed.

        Only enabled member accounts count. Email and security questions are not MFA methods and are ignored.
        Phone methods are mobilePhone (SMS or voice), alternateMobilePhone and officePhone (voice only).

          PhoneOnly    - every MFA method the user has is a phone method. Disabling SMS and voice locks them out
                         of MFA until they register something else.
          DefaultPhone - the user has a non-phone method, but SMS or voice is their default (or system-preferred)
                         method. They keep working after the change; their sign-in prompt changes.
          NoMfa        - no MFA method at all. Not affected by the change, but a separate risk.

        ReadyToDisableSms   = no enabled member is PhoneOnly with a mobile phone registered.
        ReadyToDisableVoice = no enabled member is PhoneOnly with only voice numbers (office / alternate mobile), and,
                              when SMS is already off, no PhoneOnly user at all.
        ReadyToDisableBoth  = no enabled member is PhoneOnly.
        Coverage = enabled members with Microsoft Authenticator (push or passwordless), a passkey or FIDO2 key,
        Windows Hello for Business or a Platform Credential, as a percentage of enabled members.

        Retirement of Microsoft-provided SMS/voice (Vikunja CIPP-46; Microsoft Learn concept-sms-voice-retirement,
        read 2026-11-01): from 2027-02-01 for everyone except Global Administrators and external users, who follow
        on 2027-07-01. After their date, a user whose ONLY MFA method is SMS/voice gets a blocking passkey
        registration at sign-in, with no opt-out. Every user row with a phone method gets RetirementDate
        (yyyy-MM-dd), DaysRemaining (whole days from today's US Central date; negative once passed) and
        RetirementBasis:
          GlobalAdministrator         active Global Administrator assignment (direct or via a role-assignable
                                      group) -> July
          GlobalAdministratorEligible PIM-eligible only (known when the tenant has P2) -> July, as asked for in
                                      CIPP-46; flagged separately because Microsoft has not said whether an
                                      eligible-only assignment counts
          ExternalUser                B2B account from another organisation -> July. External = UPN contains
                                      #EXT#, or externalUserState is set, or creationType is Invitation, or a
                                      federated identity issued by ExternalAzureAD / MicrosoftAccount / mail /
                                      google.com / facebook.com. userType does not matter: external members are
                                      external too.
          InternalGuest               userType Guest that is none of the above (an account that belongs to the
                                      tenant but is marked Guest) -> February, as Microsoft states
          Member                      everyone else -> February
        Guests stay out of Users and every pre-existing count (unchanged since CIPP-6); phone-only guests are
        returned in Guests and counted in the retirement figures only.

        Report only: nothing is changed. Aspendora fork addition (Vikunja CIPP-6, CIPP-46).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        # beta reports/authenticationMethods/userRegistrationDetails rows.
        [object[]]$Registrations = @(),
        # v1.0 users rows (id, accountEnabled, userType, assignedLicenses). $null = could not read; then every
        # registration row with userType member is assumed enabled.
        [object[]]$Users,
        # beta policies/authenticationMethodsPolicy, or $null if unreadable.
        $Policy,
        # Users listed per aggregate finding before "and N more".
        [int]$ListLimit = 25,
        # Object ids holding Global Administrator: active (direct or group-expanded), and PIM-eligible. $null for
        # GlobalAdminIds = could not read; then nobody is treated as Global Administrator, so everyone gets the
        # earlier (February) date - the safe side for planning.
        [string[]]$GlobalAdminIds,
        [string[]]$GlobalAdminEligibleIds,
        # Injected for tests; "today" is this instant's US Central date.
        [datetime]$NowUtc = [datetime]::UtcNow
    )

    # --- Retirement dates (Microsoft Learn, read 2026-11-01) ---
    $FebDate = [datetime]::new(2027, 2, 1)
    $JulDate = [datetime]::new(2027, 7, 1)
    $Central = $null
    foreach ($ZoneId in 'America/Chicago', 'Central Standard Time') {
        try { $Central = [System.TimeZoneInfo]::FindSystemTimeZoneById($ZoneId); break } catch { $Central = $null }
    }
    $UtcNow = if ($NowUtc.Kind -eq [System.DateTimeKind]::Local) { $NowUtc.ToUniversalTime() } else { [datetime]::SpecifyKind($NowUtc, [System.DateTimeKind]::Utc) }
    # No Central zone on the host (not expected): UTC-6 is right for the whole run-up to February.
    $TodayCentral = if ($Central) { [System.TimeZoneInfo]::ConvertTimeFromUtc($UtcNow, $Central).Date } else { $UtcNow.AddHours(-6).Date }
    $DaysTo = { param([datetime]$D) [int]($D.Date - $TodayCentral).TotalDays }

    $GaKnown = $null -ne $GlobalAdminIds
    $GaSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($G in @($GlobalAdminIds)) { if ($G) { [void]$GaSet.Add([string]$G) } }
    $GaEligibleSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($G in @($GlobalAdminEligibleIds)) { if ($G) { [void]$GaEligibleSet.Add([string]$G) } }

    # Issuers seen live on B2B guests (3endt.com, 2026-11-01): ExternalAzureAD, MicrosoftAccount; mail = email OTP.
    $ExternalIssuers = @('ExternalAzureAD', 'MicrosoftAccount', 'mail', 'google.com', 'facebook.com')
    $IsExternal = {
        param($Reg, $Usr)
        $Upn = if ($Usr -and $Usr.userPrincipalName) { [string]$Usr.userPrincipalName } else { [string]$Reg.userPrincipalName }
        if ($Upn -like '*#EXT#*') { return $true }
        if ($Usr) {
            if (-not [string]::IsNullOrWhiteSpace([string]$Usr.externalUserState)) { return $true }
            if ([string]$Usr.creationType -eq 'Invitation') { return $true }
            foreach ($I in @($Usr.identities)) {
                if ($I -and [string]$I.signInType -eq 'federated' -and [string]$I.issuer -in $ExternalIssuers) { return $true }
            }
        }
        return $false
    }

    $PhoneMethods = @('mobilePhone', 'alternateMobilePhone', 'officePhone')
    $NotMfa = @('email', 'securityQuestion', 'password', 'temporaryAccessPass')
    $StrongPattern = '^(microsoftAuthenticator(Push|Passwordless)|fido2\w*|passKey\w*|windowsHelloForBusiness|macOsSecureEnclaveKey|platformCredential)$'
    # defaultMfaMethod / userPreferredMethodForSecondaryAuthentication / systemPreferredAuthenticationMethods spellings
    # seen live on 2026-10-31: mobilePhone, officePhone, sms, voiceMobile, voiceOffice, Sms, Voice.
    $PhoneDefaultPattern = '^(mobilePhone|alternateMobilePhone|officePhone|sms|voice\w*)$'

    $Findings = [System.Collections.Generic.List[object]]::new()
    $Add = {
        param($Key, $Severity, $Check, $Account, $Message, $Fix)
        $Findings.Add([pscustomobject]@{ Key = $Key; Severity = $Severity; Check = $Check; Account = [string]$Account; Message = $Message; Fix = $Fix })
    }

    $UsersKnown = $null -ne $Users
    $UserById = @{}
    foreach ($U in @($Users)) { if ($U.id) { $UserById[[string]$U.id] = $U } }

    # Authentication methods policy state.
    $MethodState = {
        param($Id)
        if ($null -eq $Policy) { return 'unknown' }
        $C = @($Policy.authenticationMethodConfigurations | Where-Object { $_.id -eq $Id }) | Select-Object -First 1
        if ($C) { [string]$C.state } else { 'unknown' }
    }
    $SmsState = & $MethodState 'Sms'
    $VoiceState = & $MethodState 'Voice'

    # Members go to Rows (everything from CIPP-6 is computed from these only), enabled guests to GuestRows.
    $Rows = [System.Collections.Generic.List[object]]::new()
    $GuestRows = [System.Collections.Generic.List[object]]::new()
    foreach ($R in @($Registrations)) {
        if (-not $R.id) { continue }
        $U = $UserById[[string]$R.id]
        $IsGuest = [string]$R.userType -eq 'guest' -or ($U -and [string]$U.userType -eq 'Guest')
        if ($UsersKnown) {
            if (-not $U) { continue } # deleted or not a user object
            if ($U.accountEnabled -eq $false) { continue }
        }
        $Mfa = @($R.methodsRegistered | Where-Object { $_ -and [string]$_ -notin $NotMfa } | ForEach-Object { [string]$_ })
        $Phone = @($Mfa | Where-Object { $_ -in $PhoneMethods })
        $Other = @($Mfa | Where-Object { $_ -notin $PhoneMethods })
        $Strong = @($Mfa | Where-Object { $_ -match $StrongPattern })

        # Effective default: system-preferred when Microsoft manages it, otherwise the user's own choice.
        $SysPref = @($R.systemPreferredAuthenticationMethods | Where-Object { $_ })
        $Default = if ($R.isSystemPreferredAuthenticationMethodEnabled -eq $true -and $SysPref.Count -gt 0) { [string]$SysPref[0] }
        elseif ($R.userPreferredMethodForSecondaryAuthentication -and [string]$R.userPreferredMethodForSecondaryAuthentication -ne 'none') { [string]$R.userPreferredMethodForSecondaryAuthentication }
        else { [string]$R.defaultMfaMethod }
        if ($Default -eq 'none') { $Default = '' }

        $Category = if ($Mfa.Count -eq 0) { 'NoMfa' }
        elseif ($Other.Count -eq 0) { 'PhoneOnly' }
        elseif ($Default -match $PhoneDefaultPattern) { 'DefaultPhone' }
        else { 'Ready' }

        # Which retirement date applies to this account's SMS/voice. Only accounts with a phone method get one.
        $External = & $IsExternal $R $U
        $Basis = if ($GaSet.Contains([string]$R.id)) { 'GlobalAdministrator' }
        elseif ($GaEligibleSet.Contains([string]$R.id)) { 'GlobalAdministratorEligible' }
        elseif ($External) { 'ExternalUser' }
        elseif ($IsGuest) { 'InternalGuest' }
        else { 'Member' }
        $RetDate = $null
        $Days = $null
        if ($Phone.Count -gt 0) {
            $D = if ($Basis -in @('GlobalAdministrator', 'GlobalAdministratorEligible', 'ExternalUser')) { $JulDate } else { $FebDate }
            $RetDate = $D.ToString('yyyy-MM-dd')
            $Days = & $DaysTo $D
        }

        $Row = [pscustomobject]@{
            UserPrincipalName = $R.userPrincipalName
            DisplayName       = $R.userDisplayName
            Category          = $Category
            IsAdmin           = $R.isAdmin -eq $true
            Methods           = ($Mfa -join ', ')
            DefaultMethod     = $Default
            HasMobilePhone    = $Phone -contains 'mobilePhone'
            AuthenticatorOrPasskey = $Strong.Count -gt 0
            Licensed          = if ($U) { @($U.assignedLicenses | Where-Object { $_ }).Count -gt 0 } else { $null }
            Id                = [string]$R.id
            IsGlobalAdmin     = $Basis -in @('GlobalAdministrator', 'GlobalAdministratorEligible')
            IsExternal        = [bool]$External
            RetirementBasis   = $Basis
            RetirementDate    = $RetDate
            DaysRemaining     = $Days
        }
        if ($IsGuest) { $GuestRows.Add($Row) } else { $Rows.Add($Row) }
    }
    # Plain @() of the lists, never via if/else or a function return: an empty List would unroll to $null.
    $Rows = @($Rows)
    $GuestRows = @($GuestRows)

    $PhoneOnly = @($Rows | Where-Object Category -EQ 'PhoneOnly')
    $SmsDependent = @($PhoneOnly | Where-Object HasMobilePhone)
    $VoiceDependent = @($PhoneOnly | Where-Object { -not $_.HasMobilePhone -or $SmsState -eq 'disabled' })
    $DefaultPhone = @($Rows | Where-Object Category -EQ 'DefaultPhone')
    $NoMfa = @($Rows | Where-Object Category -EQ 'NoMfa')
    $Strong = @($Rows | Where-Object AuthenticatorOrPasskey)
    $Coverage = if ($Rows.Count -gt 0) { [math]::Round(100 * $Strong.Count / $Rows.Count, 1) } else { $null }

    $List = {
        param($Items)
        $Names = @($Items | Select-Object -First $ListLimit | ForEach-Object { $_.UserPrincipalName })
        $More = @($Items).Count - $Names.Count
        ($Names -join ', ') + $(if ($More -gt 0) { " and $More more" })
    }

    # --- Admins (one finding each; isAdmin is Microsoft's flag for any admin role) ---
    foreach ($A in @($Rows | Where-Object IsAdmin)) {
        switch ($A.Category) {
            'PhoneOnly' {
                & $Add "AdminPhoneOnly|$($A.Id)" 'Error' 'Admin on SMS/voice' $A.UserPrincipalName "Admin $($A.UserPrincipalName) has only SMS/voice MFA ($($A.Methods)). Phone codes can be taken with a SIM swap or relayed by a phishing kit, and disabling SMS/voice would lock this admin out of MFA." 'Register a passkey (FIDO2 key or Microsoft Authenticator passkey) or Windows Hello for Business for the admin, then remove the phone method.'
            }
            'DefaultPhone' {
                & $Add "AdminPhoneDefault|$($A.Id)" 'Warning' 'Admin on SMS/voice' $A.UserPrincipalName "Admin $($A.UserPrincipalName) signs in with $($A.DefaultMethod) by default although they have $($A.Methods)." 'Make a passkey or Authenticator the default method (or enable system-preferred MFA), then remove the phone method.'
            }
            'NoMfa' {
                & $Add "AdminNoMfa|$($A.Id)" 'Error' 'Admin without MFA' $A.UserPrincipalName "Admin $($A.UserPrincipalName) has no MFA method registered." 'Register a passkey for the admin now; issue a Temporary Access Pass if they cannot sign in to set one up.'
            }
        }
    }

    # --- Everyone (consolidated per tenant: the Key never changes, the count in the message may) ---
    $NonAdminPhoneOnly = @($PhoneOnly | Where-Object { -not $_.IsAdmin })
    if ($NonAdminPhoneOnly.Count -gt 0) {
        & $Add 'PhoneOnlyUsers' 'Warning' 'Users relying only on SMS/voice' '' "$($NonAdminPhoneOnly.Count) enabled user(s) have only SMS/voice MFA and would be locked out of MFA if SMS and voice were disabled: $(& $List $NonAdminPhoneOnly)." 'Run a registration campaign for Microsoft Authenticator (Entra > Authentication methods > Registration campaign) and follow up with these users before disabling SMS/voice.'
    }
    $NonAdminDefault = @($DefaultPhone | Where-Object { -not $_.IsAdmin })
    if ($NonAdminDefault.Count -gt 0) {
        & $Add 'DefaultPhoneUsers' 'Info' 'Users defaulting to SMS/voice' '' "$($NonAdminDefault.Count) enabled user(s) have a stronger method but SMS/voice is their default: $(& $List $NonAdminDefault). They will be prompted for their other method once SMS/voice is disabled." 'Enable system-preferred MFA so Entra prompts for the strongest registered method.'
    }
    $NoMfaLicensed = @($NoMfa | Where-Object { -not $_.IsAdmin -and $_.Licensed -ne $false })
    $NoMfaUnlicensed = @($NoMfa | Where-Object { -not $_.IsAdmin -and $_.Licensed -eq $false })
    if ($NoMfaLicensed.Count -gt 0) {
        $Extra = if ($NoMfaUnlicensed.Count -gt 0) { " A further $($NoMfaUnlicensed.Count) enabled unlicensed account(s) (often shared mailboxes or service accounts) also have none; block sign-in on them if nobody signs in as them." } else { '' }
        & $Add 'NoMfaUsers' 'Warning' 'Users without MFA' '' "$($NoMfaLicensed.Count) enabled licensed user(s) have no MFA method: $(& $List $NoMfaLicensed).$Extra Disabling SMS/voice does not affect them, but they can be enrolled by whoever first gets their password." 'Require MFA registration (Conditional Access or security defaults) and run a registration campaign.'
    }

    # --- Readiness against the current policy ---
    $SmsOn = $SmsState -eq 'enabled'
    $VoiceOn = $VoiceState -eq 'enabled'
    if ($SmsOn -and $SmsDependent.Count -eq 0 -and $Rows.Count -gt 0) {
        & $Add 'ReadyToDisableSms' 'Info' 'SMS readiness' '' 'SMS is enabled, but no enabled user relies on it as their only MFA method, so it can be turned off.' 'Enable the DisableSMS standard (Entra > Authentication methods > Policies > SMS).'
    }
    if ($VoiceOn -and $VoiceDependent.Count -eq 0 -and $Rows.Count -gt 0) {
        & $Add 'ReadyToDisableVoice' 'Info' 'Voice readiness' '' 'Voice call is enabled, but no enabled user relies on it as their only MFA method, so it can be turned off.' 'Enable the DisableVoice standard.'
    }
    if (-not $SmsOn -and $SmsState -ne 'unknown' -and $SmsDependent.Count -gt 0) {
        $Fallback = if ($VoiceOn) { ' Voice calls are still enabled, so they can only use a phone call.' } else { ' Voice is also off, so they cannot complete MFA at all.' }
        & $Add 'SmsOffUsersDependent' 'Warning' 'SMS readiness' '' "SMS is already disabled, but $($SmsDependent.Count) enabled user(s) only have a mobile phone for MFA: $(& $List $SmsDependent).$Fallback" 'Help these users register Microsoft Authenticator or a passkey.'
    }
    if ($null -eq $Policy) {
        & $Add 'PolicyUnknown' 'Info' 'Authentication methods policy' '' 'The authentication methods policy could not be read, so the current SMS and voice state is unknown.' 'Check Entra > Authentication methods > Policies by hand.'
    }

    # --- Retirement of Microsoft-provided SMS/voice (CIPP-46) ---
    # Returns @{ Value = ... } when the property exists (even if null) and $null when it does not, so "never set"
    # (optOutSettings: null, seen live 2026-11-01) can be told from "this API version has no such property".
    $Prop = {
        param($Obj, [string]$Name)
        if ($null -eq $Obj) { return $null }
        if ($Obj -is [System.Collections.IDictionary]) {
            if ($Obj.Contains($Name)) { return @{ Value = $Obj[$Name] } }
            return $null
        }
        $P = $Obj.PSObject.Properties[$Name]
        if ($P) { return @{ Value = $P.Value } }
        return $null
    }
    $Config = {
        param([string]$Id)
        if ($null -eq $Policy) { return $null }
        @($Policy.authenticationMethodConfigurations | Where-Object { $_ -and [string]$_.id -eq $Id }) | Select-Object -First 1
    }

    # Temporary opt-out of the Sept 2026 passkey auto-enablement and Microsoft-managed campaign. Ends 2027-02-01
    # and never stops enforcement. 'true' / 'false' / 'unknown' (policy unreadable or property absent).
    $OptOut = 'unknown'
    $OptOutProp = & $Prop $Policy 'optOutSettings'
    if ($OptOutProp) {
        if ($null -eq $OptOutProp.Value) { $OptOut = 'false' }
        else {
            $Pd = & $Prop $OptOutProp.Value 'passkeyDynamicMigration'
            $OptOut = if ($Pd -and $Pd.Value -eq $true) { 'true' } else { 'false' }
        }
    }

    # Passkey (FIDO2) method: state and who it is enabled for.
    $Fido = & $Config 'Fido2'
    $PasskeyState = if ($Fido) { [string]$Fido.state } else { 'unknown' }
    $FidoTargets = @($Fido.includeTargets | Where-Object { $_ })
    $PasskeyScope = if ($PasskeyState -eq 'unknown') { 'unknown' }
    elseif ($PasskeyState -ne 'enabled') { 'None' }
    elseif (@($FidoTargets | Where-Object { [string]$_.id -eq 'all_users' }).Count -gt 0) { 'AllUsers' }
    elseif ($FidoTargets.Count -gt 0) { 'Groups' }
    else { 'None' }
    $PasskeyGroups = if ($PasskeyScope -eq 'Groups') { $FidoTargets.Count } else { 0 }

    # Registration campaign. state 'default' is what the portal calls Microsoft managed. targetedAuthenticationMethod
    # values seen live 2026-11-01: microsoftAuthenticator (3endt.com), FIDO2 (aspendora.com).
    $Campaign = $null
    if ($null -ne $Policy) { $Campaign = $Policy.registrationEnforcement.authenticationMethodsRegistrationCampaign }
    $CampaignState = if ($Campaign -and $Campaign.state) { [string]$Campaign.state } else { 'unknown' }
    $CampaignTargets = @($Campaign.includeTargets | Where-Object { $_ })
    $CampaignMethods = @($CampaignTargets | ForEach-Object { [string]$_.targetedAuthenticationMethod } | Where-Object { $_ } | Select-Object -Unique)
    $CampaignTargetsPasskey = @($CampaignMethods | Where-Object { $_ -match '^(fido2|passkey\w*)$' }).Count -gt 0
    $CampaignAllUsers = @($CampaignTargets | Where-Object { [string]$_.id -eq 'all_users' }).Count -gt 0
    $CampaignOk = $CampaignState -in @('default', 'enabled') -and $CampaignTargetsPasskey

    # Telephony provider from Microsoft Security Store. The Sms and Voice configurations carry
    # telecomProviderSettings (null on every tenant read 2026-11-01, i.e. Microsoft-provided). The shape of a
    # configured provider has not been seen, so any non-null value counts as configured. Absent property on both
    # = NotDetectable.
    $Telephony = 'unknown'
    if ($null -ne $Policy) {
        $SeenTel = $false
        $HasTel = $false
        foreach ($MethodId in 'Sms', 'Voice') {
            $T = & $Prop (& $Config $MethodId) 'telecomProviderSettings'
            if ($T) {
                $SeenTel = $true
                if ($null -ne $T.Value) { $HasTel = $true }
            }
        }
        $Telephony = if ($HasTel) { 'Configured' } elseif ($SeenTel) { 'MicrosoftProvided' } else { 'NotDetectable' }
    }

    # Who is blocked when: phone-only members and phone-only enabled guests.
    $FebIso = $FebDate.ToString('yyyy-MM-dd')
    $JulIso = $JulDate.ToString('yyyy-MM-dd')
    $GuestPhoneOnly = @($GuestRows | Where-Object Category -EQ 'PhoneOnly')
    $RetireAll = @(@($PhoneOnly) + @($GuestPhoneOnly))
    $FebGroup = @($RetireAll | Where-Object RetirementDate -EQ $FebIso)
    $JulGroup = @($RetireAll | Where-Object RetirementDate -EQ $JulIso)
    $FebDays = & $DaysTo $FebDate
    $JulDays = & $DaysTo $JulDate
    $NearestDeadline = $null
    $NearestDays = $null
    $NearestUsers = 0
    if ($FebGroup.Count -gt 0) { $NearestDeadline = $FebIso; $NearestDays = $FebDays; $NearestUsers = $FebGroup.Count }
    elseif ($JulGroup.Count -gt 0) { $NearestDeadline = $JulIso; $NearestDays = $JulDays; $NearestUsers = $JulGroup.Count }

    $Blocked = {
        param([int]$Days, [string]$Date)
        if ($Days -gt 0) { "will be blocked at sign-in from $Date ($Days day(s) from today, US Central)" }
        elseif ($Days -eq 0) { "are blocked at sign-in from today, $Date" }
        else { "have been blocked at sign-in since $Date" }
    }
    $TelNote = if ($Telephony -eq 'Configured') { ' A telephony provider appears to be configured on the SMS/voice policy; accounts already moved to it are not blocked, so confirm which of these are.' } else { '' }
    $RetSeverity = if ($Telephony -eq 'Configured') { 'Warning' } else { 'Error' }
    if ($FebGroup.Count -gt 0) {
        & $Add 'SmsRetirementFebruary' $RetSeverity 'SMS/voice retirement (Feb 2027)' '' "$($FebGroup.Count) account(s) whose only MFA method is SMS/voice $(& $Blocked $FebDays $FebIso) until they register a passkey: $(& $List $FebGroup).$TelNote" 'Move these users to a passkey (Microsoft Authenticator, synced passkey or FIDO2 key) or Windows Hello before the date: run a passkey registration campaign and follow up one by one. Microsoft offers no opt-out from this enforcement.'
    }
    if ($JulGroup.Count -gt 0) {
        $Eligible = @($JulGroup | Where-Object RetirementBasis -EQ 'GlobalAdministratorEligible').Count
        $EligibleNote = if ($Eligible -gt 0) { " $Eligible of them are only PIM-eligible for Global Administrator; Microsoft has not said whether that counts, so treat them as February to be safe." } else { '' }
        & $Add 'SmsRetirementJuly' 'Warning' 'SMS/voice retirement (Jul 2027)' '' "$($JulGroup.Count) Global Administrator or external account(s) whose only MFA method is SMS/voice $(& $Blocked $JulDays $JulIso) until they register a passkey: $(& $List $JulGroup).$EligibleNote$TelNote" 'Register a passkey for each Global Administrator now; ask external users to use a phishing-resistant method in their home tenant (with cross-tenant MFA trust) or register one here.'
    }
    if ($OptOut -eq 'true') {
        & $Add 'SmsRetirementOptOut' 'Info' 'SMS/voice retirement opt-out' '' "The tenant has opted out (optOutSettings.passkeyDynamicMigration = true) of the September 2026 automatic passkey enablement and Microsoft-managed registration campaign. The opt-out only lasts until $FebIso and does not stop enforcement." 'Use the time to move users to passkeys yourself; the blocking prompt still arrives on each retirement date.'
    }
    if ($PasskeyState -eq 'disabled') {
        & $Add 'SmsRetirementPasskeyDisabled' 'Info' 'SMS/voice retirement: passkeys' '' 'Passkey (FIDO2) is disabled in the authentication methods policy, so users cannot register the method Microsoft will require after the SMS/voice retirement.' 'Enable Passkey (FIDO2) for all users (Entra > Authentication methods > Policies > Passkey (FIDO2)).'
    } elseif ($PasskeyScope -eq 'Groups') {
        & $Add 'SmsRetirementPasskeyScoped' 'Info' 'SMS/voice retirement: passkeys' '' "Passkey (FIDO2) is enabled for $PasskeyGroups group(s) only. Phone-only users outside those groups cannot register a passkey." 'Include all users in the Passkey (FIDO2) policy, or make sure every SMS/voice user is in one of its groups.'
    }
    if ($CampaignState -ne 'unknown' -and -not $CampaignOk) {
        $What = if ($CampaignState -notin @('default', 'enabled')) { "is $CampaignState" } else { "targets $(if ($CampaignMethods.Count) { $CampaignMethods -join ', ' } else { 'no method' }), not passkeys" }
        & $Add 'SmsRetirementCampaign' 'Info' 'SMS/voice retirement: registration campaign' '' "The registration campaign $What." 'Set the registration campaign to Microsoft managed (or enabled) targeting passkeys, including your SMS/voice users (Entra > Authentication methods > Registration campaign).'
    }
    if ($Telephony -eq 'Configured') {
        & $Add 'SmsRetirementTelephonyProvider' 'Info' 'SMS/voice retirement: telephony provider' '' 'A telephony provider setting is present on the SMS or voice method, so SMS/voice may continue past the retirement dates for users moved to it.' 'Check the provider in Entra > Authentication methods and which users it covers.'
    }
    if (-not $GaKnown -and $RetireAll.Count -gt 0) {
        & $Add 'SmsRetirementGlobalAdminsUnknown' 'Info' 'SMS/voice retirement' '' "Global Administrator holders could not be read, so every member account is dated $FebIso (the earlier date) even if it holds Global Administrator." 'Check Global Administrator holders by hand.'
    }

    $Summary = [pscustomobject]@{
        UsersEnabled           = $Rows.Count
        AuthenticatorOrPasskey = $Strong.Count
        CoveragePercent        = $Coverage
        PhoneOnly              = $PhoneOnly.Count
        SmsDependent           = $SmsDependent.Count
        VoiceDependent         = $VoiceDependent.Count
        DefaultPhone           = $DefaultPhone.Count
        NoMfa                  = $NoMfa.Count
        Admins                 = @($Rows | Where-Object IsAdmin).Count
        AdminsPhoneOnly        = @($PhoneOnly | Where-Object IsAdmin).Count
        AdminsDefaultPhone     = @($DefaultPhone | Where-Object IsAdmin).Count
        AdminsNoMfa            = @($NoMfa | Where-Object IsAdmin).Count
        SmsState               = $SmsState
        VoiceState             = $VoiceState
        ReadyToDisableSms      = $SmsDependent.Count -eq 0
        ReadyToDisableVoice    = $VoiceDependent.Count -eq 0
        ReadyToDisableBoth     = $PhoneOnly.Count -eq 0
        UsersFilteredByAccount = $UsersKnown
        # CIPP-46 retirement fields.
        RetirementFebruary2027             = $FebGroup.Count
        RetirementJuly2027                 = $JulGroup.Count
        GuestsPhoneOnly                    = $GuestPhoneOnly.Count
        DaysToFebruary2027                 = $FebDays
        DaysToJuly2027                     = $JulDays
        NearestDeadline                    = $NearestDeadline
        NearestDeadlineDaysRemaining       = $NearestDays
        NearestDeadlineUsers               = $NearestUsers
        ReadyByFeb2027                     = $FebGroup.Count -eq 0
        ReadyByJul2027                     = $JulGroup.Count -eq 0
        PasskeyDynamicMigrationOptOut      = $OptOut
        PasskeyState                       = $PasskeyState
        PasskeyScope                       = $PasskeyScope
        PasskeyGroups                      = $PasskeyGroups
        RegistrationCampaignState          = $CampaignState
        RegistrationCampaignMethods        = ($CampaignMethods -join ', ')
        RegistrationCampaignAllUsers       = $CampaignAllUsers
        RegistrationCampaignTargetsPasskey = $CampaignTargetsPasskey
        RegistrationCampaignOk             = $CampaignOk
        TelephonyProvider                  = $Telephony
        GlobalAdminsKnown                  = $GaKnown
        GlobalAdmins                       = $GaSet.Count
        TodayCentral                       = $TodayCentral.ToString('yyyy-MM-dd')
    }

    $Order = @{ Error = 0; Warning = 1; Info = 2 }
    $CatOrder = @{ PhoneOnly = 0; NoMfa = 1; DefaultPhone = 2; Ready = 3 }
    [pscustomobject]@{
        Summary  = $Summary
        Users    = @($Rows | Sort-Object @{ e = { -not $_.IsAdmin } }, @{ e = { $CatOrder[$_.Category] } }, UserPrincipalName)
        Guests   = @($GuestPhoneOnly | Sort-Object UserPrincipalName)
        Findings = @($Findings | Sort-Object { $Order[$_.Severity] }, Account, Check)
    }
}
