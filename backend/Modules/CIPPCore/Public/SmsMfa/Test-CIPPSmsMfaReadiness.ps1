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

        Report only: nothing is changed. Aspendora fork addition (Vikunja CIPP-6).
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
        [int]$ListLimit = 25
    )

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

    $Rows = foreach ($R in @($Registrations)) {
        if (-not $R.id) { continue }
        if ([string]$R.userType -eq 'guest') { continue }
        $U = $UserById[[string]$R.id]
        if ($UsersKnown) {
            if (-not $U) { continue } # deleted or not a user object
            if ($U.accountEnabled -eq $false) { continue }
            if ([string]$U.userType -eq 'Guest') { continue }
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

        [pscustomobject]@{
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
        }
    }
    $Rows = @($Rows)

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
    }

    $Order = @{ Error = 0; Warning = 1; Info = 2 }
    $CatOrder = @{ PhoneOnly = 0; NoMfa = 1; DefaultPhone = 2; Ready = 3 }
    [pscustomobject]@{
        Summary  = $Summary
        Users    = @($Rows | Sort-Object @{ e = { -not $_.IsAdmin } }, @{ e = { $CatOrder[$_.Category] } }, UserPrincipalName)
        Findings = @($Findings | Sort-Object { $Order[$_.Severity] }, Account, Check)
    }
}
