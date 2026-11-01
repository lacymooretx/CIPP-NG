function Test-CIPPCAGrantSatisfiable {
    <#
    .SYNOPSIS
        Says whether a principal with the given registered authentication methods can meet a policy's grant controls.
    .DESCRIPTION
        Pure: no Graph calls. Returns Outcome:
          Satisfiable - the principal can meet the controls (or there are none, only session controls)
          Blocked     - block control, or no registered method meets an MFA / authentication-strength requirement
          Unknown     - the answer depends on the device or app (compliant / hybrid-joined device, approved or
                        protected app, custom controls), or the methods could not be read
        Methods accepts userRegistrationDetails.methodsRegistered names (fido2, microsoftAuthenticatorPush, ...)
        or authentication method @odata.type strings; pass $null when unknown.
        Aspendora fork addition (Vikunja CIPP-5).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Policy,
        [AllowNull()][object[]]$Methods
    )

    # Built-in authentication strengths (ids are fixed by Microsoft).
    $BuiltInStrengths = @{
        '00000000-0000-0000-0000-000000000002' = @('windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor', 'deviceBasedPush', 'temporaryAccessPassOneTime', 'temporaryAccessPassMultiUse', 'password,microsoftAuthenticatorPush', 'password,softwareOath', 'password,hardwareOath', 'password,sms', 'password,voice', 'federatedMultiFactor', 'microsoftAuthenticatorPush,federatedSingleFactor', 'softwareOath,federatedSingleFactor', 'hardwareOath,federatedSingleFactor', 'sms,federatedSingleFactor', 'voice,federatedSingleFactor')
        '00000000-0000-0000-0000-000000000003' = @('windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor', 'deviceBasedPush')
        '00000000-0000-0000-0000-000000000004' = @('windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor')
    }
    # Registered method -> the authentication-strength combinations it can satisfy on its own (with the password).
    $MethodCombos = @{
        fido2                              = @('fido2')
        passKeyDeviceBound                 = @('fido2')
        passKeyDeviceBoundAuthenticator    = @('fido2')
        passKeyDeviceBoundWindowsHello     = @('fido2', 'windowsHelloForBusiness')
        passKeySynced                      = @('fido2')
        windowsHelloForBusiness            = @('windowsHelloForBusiness')
        macOsSecureEnclaveKey              = @('windowsHelloForBusiness')
        x509CertificateMultiFactor         = @('x509CertificateMultiFactor')
        microsoftAuthenticatorPasswordless = @('deviceBasedPush')
        microsoftAuthenticatorPush         = @('password,microsoftAuthenticatorPush')
        softwareOneTimePasscode            = @('password,softwareOath')
        hardwareOneTimePasscode            = @('password,hardwareOath')
        mobilePhone                        = @('password,sms', 'password,voice', 'sms')
        alternateMobilePhone               = @('password,voice')
        officePhone                        = @('password,voice')
    }
    # Authentication method @odata.type -> registration name.
    $TypeNames = @{
        fido2AuthenticationMethod                   = 'fido2'
        windowsHelloForBusinessAuthenticationMethod = 'windowsHelloForBusiness'
        platformCredentialAuthenticationMethod      = 'macOsSecureEnclaveKey'
        x509CertificateAuthenticationMethod         = 'x509CertificateMultiFactor'
        microsoftAuthenticatorAuthenticationMethod  = 'microsoftAuthenticatorPush'
        softwareOathAuthenticationMethod            = 'softwareOneTimePasscode'
        hardwareOathAuthenticationMethod            = 'hardwareOneTimePasscode'
        phoneAuthenticationMethod                   = 'mobilePhone'
        temporaryAccessPassAuthenticationMethod     = 'temporaryAccessPass'
        emailAuthenticationMethod                   = 'email'
        passwordAuthenticationMethod                = 'password'
    }

    $Known = $null -ne $Methods
    $Names = @(foreach ($M in @($Methods)) {
            $S = ([string]$M) -replace '^#microsoft\.graph\.', ''
            if ($TypeNames.ContainsKey($S)) { $TypeNames[$S] } elseif ($S) { $S }
        })
    $UserCombos = @($Names | ForEach-Object { $MethodCombos[$_] } | Where-Object { $_ } | Select-Object -Unique)

    $G = $Policy.grantControls
    $Controls = @($G.builtInControls | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $Strength = $G.authenticationStrength
    $Terms = @($G.termsOfUse | Where-Object { $_ })
    $Custom = @($G.customAuthenticationFactors | Where-Object { $_ })

    $Result = { param($Outcome, $Required, $Reason) [pscustomobject]@{ Outcome = $Outcome; Required = $Required; Reason = $Reason } }

    if ($Controls -contains 'block') { return (& $Result 'Blocked' 'block' 'The policy blocks access.') }
    if (-not $Controls -and -not $Strength -and -not $Terms -and -not $Custom) {
        return (& $Result 'Satisfiable' 'none' 'No grant controls (session controls only).')
    }

    $Parts = [System.Collections.Generic.List[object]]::new()
    foreach ($C in $Controls) {
        switch ($C) {
            'mfa' {
                $Mfa = @($Names | Where-Object { $MethodCombos.ContainsKey($_) })
                if (-not $Known) { $Parts.Add(@('Unknown', 'MFA', 'registered methods unknown')) }
                elseif ($Mfa) { $Parts.Add(@('Satisfiable', 'MFA', "registered: $($Mfa -join ', ')")) }
                else { $Parts.Add(@('Blocked', 'MFA', 'no MFA method registered')) }
            }
            'passwordChange' { $Parts.Add(@('Satisfiable', 'password change', 'user can change the password')) }
            default { $Parts.Add(@('Unknown', $C, 'depends on the device or app used')) }
        }
    }
    if ($Strength) {
        $Allowed = @($Strength.allowedCombinations | Where-Object { $_ })
        if (-not $Allowed -and $Strength.id -and $BuiltInStrengths.ContainsKey([string]$Strength.id)) { $Allowed = $BuiltInStrengths[[string]$Strength.id] }
        $Label = "authentication strength '$($Strength.displayName ?? $Strength.id)'"
        if (-not $Allowed) { $Parts.Add(@('Unknown', $Label, 'allowed combinations unknown')) }
        elseif (-not $Known) { $Parts.Add(@('Unknown', $Label, 'registered methods unknown')) }
        else {
            $Hit = @($UserCombos | Where-Object { $_ -in $Allowed })
            if ($Hit) { $Parts.Add(@('Satisfiable', $Label, "meets it with $($Hit -join ', ')")) }
            else { $Parts.Add(@('Blocked', $Label, 'no registered method meets it')) }
        }
    }
    if ($Terms) { $Parts.Add(@('Satisfiable', 'terms of use', 'user can accept the terms')) }
    if ($Custom) { $Parts.Add(@('Unknown', 'custom control', 'custom controls cannot be evaluated')) }

    $Outcomes = @($Parts | ForEach-Object { $_[0] })
    $Required = ($Parts | ForEach-Object { $_[1] }) -join ($(if ($G.operator -eq 'AND') { ' AND ' } else { ' OR ' }))
    $Reason = ($Parts | ForEach-Object { "$($_[1]): $($_[2])" }) -join '; '
    $Outcome = if ($G.operator -eq 'AND') {
        if ($Outcomes -contains 'Blocked') { 'Blocked' } elseif ($Outcomes -contains 'Unknown') { 'Unknown' } else { 'Satisfiable' }
    } else {
        if ($Outcomes -contains 'Satisfiable') { 'Satisfiable' } elseif ($Outcomes -contains 'Unknown') { 'Unknown' } else { 'Blocked' }
    }
    & $Result $Outcome $Required $Reason
}
