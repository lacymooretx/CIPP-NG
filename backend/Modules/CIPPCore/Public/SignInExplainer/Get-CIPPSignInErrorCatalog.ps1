function Get-CIPPSignInErrorCatalog {
    <#
    .SYNOPSIS
        Plain-language meaning and recommended fix for the common Entra sign-in (AADSTS) error codes.
    .DESCRIPTION
        Keyed by the numeric code as a string. Each entry: Name (Microsoft's internal name where the reference gives
        one, otherwise a short label in the same style), Category, Interrupt
        (true when Microsoft treats the code as a normal step of a sign-in that usually continues, e.g. an MFA
        prompt), Title, Explanation, Fix.

        Meanings checked 2026-11-01 against Microsoft's "Microsoft Entra authentication & authorization error codes"
        (learn.microsoft.com/entra/identity-platform/reference-error-codes). 500121 is not in that table; its text
        follows the failureReason the sign-in log returns. Two codes do not mean what they are often assumed to:
        530032 is "BlockedByConditionalAccessOnSecurityPolicy" (a tenant security policy), not security-info
        registration (that is 53004 / 53010), and 7000218 is a missing client secret, i.e. an app configuration
        problem rather than a user one.

        Fixes follow Aspendora practice: never recommend a password reset only because a password is being guessed;
        reset only on evidence the password is known to someone else (an MFA prompt the user did not start).
        Aspendora fork addition (Vikunja CIPP-10).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param()

    $E = {
        param($Name, $Category, [bool]$Interrupt, $Title, $Explanation, $Fix)
        [pscustomobject]@{ Name = $Name; Category = $Category; Interrupt = $Interrupt; Title = $Title; Explanation = $Explanation; Fix = $Fix }
    }

    $NotUser = 'This is not something the user can fix; it is a setting in the app or the tenant.'

    [ordered]@{
        # --- Password and account state ---
        '50126'   = & $E 'InvalidUserNameOrPassword' 'Password' $false 'Wrong user name or password' `
            'The password (or user name) was wrong. A few of these are ordinary typos. Many in a short time, particularly from IP addresses or countries the user does not use, mean someone is guessing the password.' `
            'If it was the user: check Caps Lock and keyboard layout, and look for an old saved password on a phone, a mail app or a mapped drive that keeps retrying. If the attempts are not from the user, the account is being attacked: make sure MFA is registered and enforced and block the source with Conditional Access. Do not reset the password only because it is being guessed.'
        '50053'   = & $E 'IdsLocked' 'Lockout' $false 'Account locked (smart lockout) or sign-in from a malicious IP' `
            'Entra smart lockout locked the account for a while after repeated wrong passwords. Microsoft returns the same code when the sign-in came from an IP address it considers malicious, so the two cases cannot be told apart from the code alone. Smart lockout keeps the user''s familiar locations separate from unfamiliar ones, so an attacker abroad does not normally lock the user out at the office.' `
            'The lockout clears on its own after the lockout period (60 seconds by default, longer after repeated lockouts). If the attempts come from addresses the user does not use, it is an attack on the account; see the failed-password summary and consider a Conditional Access block for the source. If the user locked themselves out, find the device retrying an old password. For synced users with pass-through authentication or AD FS, also check the on-premises AD lockout.'
        '50057'   = & $E 'UserDisabled' 'Account' $false 'Account is disabled' `
            'The account is disabled, so Entra refuses every sign-in.' `
            'If the user should have access, enable the account (Edit user, or in on-premises AD for synced users, then wait for the next sync). If it was disabled on purpose (offboarding or a compromise), check the audit log for who disabled it before turning it back on.'
        '50055'   = & $E 'InvalidPasswordExpiredPassword' 'Password' $false 'Password expired' `
            'The cloud password has expired.' `
            'The user can change it at the sign-in prompt or with self-service password reset; otherwise reset it for them. Check whether the tenant still uses a password expiry policy.'
        '50144'   = & $E 'InvalidPasswordExpiredOnPremPassword' 'Password' $false 'On-premises AD password expired' `
            'The user''s Active Directory password has expired.' `
            'Reset it in on-premises AD (or let the user use self-service password reset if password writeback is enabled), then wait for sync.'
        '50056'   = & $E 'InvalidOrNullPassword' 'Password' $false 'No password stored for this user' `
            'There is no password in the directory for this user (for example a synced user whose password hash has not synced, or a user created without one).' `
            'Set a password for the user, or check that password hash sync is working for synced users.'
        '50133'   = & $E 'SsoArtifactRevoked' 'Session' $true 'Session ended after a password change' `
            'The saved session is no longer valid because the password expired or was changed recently.' `
            'Sign in again with the current password, and update the password on phones and other devices that cache it.'
        '50132'   = & $E 'SsoArtifactInvalidOrExpired' 'Session' $true 'Session ended after a password change' `
            'The saved session is no longer valid because the password expired or was changed recently.' `
            'Sign in again with the current password, and update the password on phones and other devices that cache it.'
        '50173'   = & $E 'FreshTokenNeeded' 'Session' $true 'Saved sign-in revoked' `
            'The app''s saved sign-in (refresh token) was revoked, usually because the password was changed or reset, or an admin revoked the user''s sessions.' `
            'Sign in to that app again. This is expected after a password change or session revocation.'
        '50034'   = & $E 'UserAccountNotFound' 'Account' $false 'Account not found in this tenant' `
            'No account with that user name exists in this tenant. Usually a typo, or the app sent the user to the wrong tenant.' `
            'Check the spelling of the sign-in name and that the user is signing in with their work account.'
        '51004'   = & $E 'UserAccountNotInDirectory' 'Account' $false 'Account not in this directory' `
            'The account does not exist in this tenant; the app most likely chose the wrong tenant.' `
            'Sign in with the right account. If this person should have access, invite them as a guest.'
        '50059'   = & $E 'MissingTenantRealmAndNoUserInformationProvided' 'Account' $false 'Could not tell which tenant to use' `
            'Nothing in the request identified the tenant.' `
            'Retry with the full work email address as the sign-in name.'
        '50128'   = & $E 'InvalidDomainName' 'Account' $false 'Unknown domain name' `
            'No tenant could be found from the domain in the sign-in name.' `
            'Check the domain part of the sign-in name for typos.'

        # --- MFA ---
        '50076'   = & $E 'UserStrongAuthClientAuthNRequired' 'MFA' $true 'MFA required' `
            'The user had to complete MFA for this sign-in (because of Conditional Access, per-user MFA, security defaults or a new location). This is normally a prompt, not a failure; it only matters if no successful sign-in follows.' `
            'Nothing to do if a successful sign-in follows. If the user cannot complete MFA, check their registered methods (Authenticator app, phone) and issue a Temporary Access Pass to re-register if needed.'
        '50074'   = & $E 'UserStrongAuthClientAuthNRequiredInterrupt' 'MFA' $true 'MFA required, not completed' `
            'Strong authentication was required and the user did not pass the MFA challenge in this attempt. Usually the prompt was shown and the user completed it in the next step, or closed it.' `
            'Nothing to do if a successful sign-in follows with the same correlation ID. If not, ask whether the user saw the prompt; check their registered methods and issue a Temporary Access Pass to re-register if needed.'
        '50079'   = & $E 'UserStrongAuthEnrollmentRequired' 'MfaRegistration' $true 'MFA registration required' `
            'The user must register security info (MFA methods) before they can continue.' `
            'Let the user complete registration at the prompt or at https://aka.ms/mysecurityinfo. If they cannot (lost phone, new device), issue a Temporary Access Pass.'
        '50072'   = & $E 'UserStrongAuthEnrollmentRequiredInterrupt' 'MfaRegistration' $true 'MFA registration required' `
            'The user was asked to register a second factor.' `
            'Let the user complete registration at the prompt or at https://aka.ms/mysecurityinfo; issue a Temporary Access Pass if they cannot.'
        '500121'  = & $E 'StrongAuthenticationFailed' 'MFA' $false 'MFA failed or was denied' `
            'Authentication failed during the MFA step: the user denied or ignored the prompt, entered a wrong code, or the prompt never reached them.' `
            'Ask the user whether they started this sign-in and saw the prompt. If they denied a prompt they did not start, someone else knows the password: revoke sessions, reset the password and review where the sign-in came from. If prompts never arrive, check the Authenticator app (notifications, phone time, new phone) and the registered methods; a Temporary Access Pass lets them re-register.'
        '50078'   = & $E 'UserStrongAuthExpired' 'MFA' $true 'MFA needs to be repeated' `
            'The earlier MFA has expired under the tenant''s policies (for example sign-in frequency), so the user must do MFA again.' `
            'Expected behaviour; the user completes MFA again.'
        '50158'   = & $E 'ExternalSecurityChallenge' 'MFA' $true 'External security challenge not completed' `
            'The user was sent to another provider or page to finish signing in (a third-party MFA provider such as an external authentication method, or terms of use) and had not finished it in this attempt.' `
            'Nothing to do if a successful sign-in follows. If not, check the external provider (for example Duo) for that user.'
        '53004'   = & $E 'ProofUpBlockedDueToRisk' 'MfaRegistration' $false 'MFA registration blocked' `
            'The user has to register MFA before continuing, but Microsoft blocked registration from this sign-in (ProofUpBlockedDueToRisk), usually because the sign-in looked risky.' `
            'Have the user register from a trusted location or device, or issue a Temporary Access Pass. Check the user under Identity Protection (risky users / risky sign-ins) and dismiss the risk only if you are sure it is a false positive.'
        '53010'   = & $E 'ProofUpBlockedDueToSecurityInfoAcr' 'MfaRegistration' $false 'MFA registration not allowed from here' `
            'The organisation only allows security info to be registered from specific locations or devices (a Conditional Access policy on "Register security information"), and this sign-in did not meet it.' `
            'Have the user register from the office or a managed device, or issue a Temporary Access Pass, which most such policies accept.'
        '90072'   = & $E 'PassThroughUserMfaError' 'Guest' $false 'External account cannot do MFA in this tenant' `
            'The account the user signed in with does not exist in this tenant, so it cannot satisfy this tenant''s MFA requirement. For synced users this can also be an ImmutableID (source anchor) mismatch.' `
            'Invite the person as a guest, or have them sign in with the account that was invited. For synced users, check the source anchor matches.'

        # --- Conditional Access and security policy ---
        '53003'   = & $E 'BlockedByConditionalAccess' 'ConditionalAccess' $false 'Blocked by Conditional Access' `
            'A Conditional Access policy blocked the sign-in on purpose.' `
            'Look at the blocking policy below and the conditions it matched (location/country, device platform, app, client type, risk). If the block is correct, tell the user how to sign in so that it does not match (for example from the office or a managed device). If this user needs an exception (travel, a service account), add them to the policy''s exclusion group for a limited time (CIPP: Conditional Access exclusion or Vacation mode) rather than turning the policy off.'
        '53000'   = & $E 'DeviceNotCompliant' 'Device' $false 'Device is not compliant' `
            'A Conditional Access policy requires a compliant (Intune-managed) device, and this device is not compliant or did not prove it is.' `
            'Check the device in Intune: is it enrolled, and which compliance setting fails? Have the user open Company Portal and run Check status / Sync. If the device details below show no device ID, the browser or app did not send the device identity: on Windows use Edge signed in with the work account (or Chrome with the Microsoft single sign-on extension); on macOS and mobile use Company Portal / the Authenticator broker.'
        '53001'   = & $E 'DeviceNotDomainJoined' 'Device' $false 'Device is not hybrid joined' `
            'A Conditional Access policy requires a hybrid Microsoft Entra joined (domain joined) device, and this device is not.' `
            'Use a corporate, domain-joined computer. On the PC, "dsregcmd /status" shows whether it is hybrid joined (AzureAdJoined and DomainJoined both YES).'
        '53002'   = & $E 'ApplicationUsedIsNotAnApprovedApp' 'Device' $false 'Not an approved client app' `
            'Conditional Access only allows approved apps (for example Outlook and Teams mobile) and the user tried another app, such as the phone''s built-in mail app.' `
            'Have the user use the Microsoft app (Outlook, Teams, OneDrive) instead.'
        '50005'   = & $E 'DevicePolicyError' 'Device' $false 'Device platform not supported by Conditional Access' `
            'The user signed in from a device platform the Conditional Access policy does not support.' `
            'Use a supported platform, or review the policy''s device platform condition.'
        '50127'   = & $E 'BrokerAppNotInstalled' 'Device' $true 'Broker app needed' `
            'The user needs a broker app (Microsoft Authenticator or Company Portal) to reach this content, typically because of an app protection policy on mobile.' `
            'Install Microsoft Authenticator (iOS) or Company Portal (Android) and sign in again.'
        '50129'   = & $E 'DeviceIsNotWorkplaceJoined' 'Device' $false 'Device must be registered' `
            'Workplace join (device registration) is required.' `
            'Register the device (Settings > Accounts > Access work or school on Windows, or Company Portal on mobile).'
        '50097'   = & $E 'DeviceAuthenticationRequired' 'Device' $true 'Device authentication requested' `
            'Not an error. Entra asked the device to prove its identity because a Conditional Access policy or the app needs the device ID. The next step shows whether the device passed.' `
            'Nothing to do unless the sign-in then fails with a device error such as 53000.'
        '50155'   = & $E 'DeviceAuthenticationFailed' 'Device' $false 'Device authentication failed' `
            'The device could not prove its identity, usually because its Entra device object was deleted or disabled, or its certificate is broken.' `
            'Check the device under Entra ID > Devices (present and enabled?). Re-register or re-join the device if needed.'
        '530032'  = & $E 'BlockedByConditionalAccessOnSecurityPolicy' 'ConditionalAccess' $false 'Blocked by a tenant security policy' `
            'A tenant-level security policy configured by an admin blocked this request.' `
            'Review the tenant''s security policies: Conditional Access (the table below), Identity Protection risk policies, authentication method and token protection settings. Run the Sign-in Diagnostic with the correlation ID for the exact policy.'
        '530035'  = & $E 'BlockedBySecurityDefaults' 'ConditionalAccess' $false 'Blocked by security defaults' `
            'Security defaults blocked the request, because it used legacy authentication or was judged unsafe.' `
            'Move the app or device to modern authentication (Outlook rather than IMAP/POP, modern SMTP AUTH alternatives). Security defaults cannot be tuned per user; tenants that need exceptions use Conditional Access instead.'
        '50131'   = & $E 'ConditionalAccessFailed' 'ConditionalAccess' $false 'Conditional Access check failed' `
            'A Conditional Access or security decision failed: bad Windows device state, suspicious activity, an access policy or a security policy.' `
            'Check the Conditional Access table below and the risk details; run the Sign-in Diagnostic with the correlation ID.'
        '50142'   = & $E 'PasswordChangeRequiredConditionalAccess' 'Risk' $false 'Password change required by Conditional Access' `
            'A Conditional Access policy (usually a user-risk policy) requires the user to change their password.' `
            'The user completes MFA and changes the password at the prompt. If they cannot, reset the password and review the user''s risk in Identity Protection.'
        '50135'   = & $E 'PasswordChangeCompromisedPassword' 'Risk' $false 'Password change required because the account is at risk' `
            'Identity Protection considers the account at risk, so a password change is required.' `
            'The user performs a secure password change (MFA then new password). If they cannot, reset it for them and review the risk detections.'
        '53011'   = & $E 'UserBlockedDueToRiskOnHomeTenant' 'Risk' $false 'Blocked because of risk in the user''s home tenant' `
            'The user (usually a guest) is flagged as risky in their own organisation''s tenant.' `
            'The user''s home organisation has to clear the risk; this tenant cannot.'
        '530034'  = & $E 'DelegatedAdminBlockedDueToSuspiciousActivity' 'Risk' $false 'Partner admin blocked due to risk' `
            'A delegated (GDAP) administrator was blocked because their account is risky in their home tenant.' `
            'Clear the risk on the admin''s account in the partner tenant.'
        '70043'   = & $E 'BadTokenDueToSignInFrequency' 'Session' $true 'Sign-in frequency reached' `
            'A Conditional Access sign-in frequency control ended the session, so the user must sign in again.' `
            'Expected; the user signs in again.'

        # --- Apps, consent and guests ---
        '50105'   = & $E 'EntitlementGrantsNotFound' 'App' $false 'User not assigned to the app' `
            'The app requires assignment and this user (or a group they are in) is not assigned to it.' `
            'Assign the user or their group under Enterprise applications > the app > Users and groups, or set "Assignment required" to No if everyone should have it.'
        '65001'   = & $E 'DelegationDoesNotExist' 'Consent' $false 'App needs consent' `
            'Neither the user nor an admin has consented to the permissions this app asks for.' `
            'If the app is approved, grant admin consent (Enterprise applications > the app > Permissions). If not, this is working as intended.'
        '90095'   = & $E 'AdminConsentRequiredRequestAccess' 'Consent' $true 'Admin consent required' `
            'The user was told the app needs admin approval and offered to request it.' `
            'Review the request under Enterprise applications > Admin consent requests.'
        '700016'  = & $E 'UnauthorizedClient_DoesNotMatchRequest' 'App' $false 'App not found in this tenant' `
            'The application was not found in the tenant: it has not been added or consented here, or the app sent the wrong app ID or tenant.' `
            "$NotUser Have an admin consent to the app in this tenant, or ask the vendor to check their configuration."
        '7000112' = & $E 'UnauthorizedClientApplicationDisabled' 'App' $false 'App is disabled' `
            'The application is disabled in this tenant.' `
            'If it should work, set "Enabled for users to sign in" to Yes under Enterprise applications > the app > Properties.'
        '7000218' = & $E 'MissingClientCredential' 'App' $false 'App sent no client secret' `
            'The request needed a client secret or certificate and contained neither. With user sign-ins this is usually a script or tool using a user name and password (ROPC) or device code flow against an app registration that is not set as a public client.' `
            "$NotUser In the app registration, Authentication > Allow public client flows, or fix the app's credentials."
        '50011'   = & $E 'InvalidReplyTo' 'App' $false 'App reply URL mismatch' `
            'The app''s reply (redirect) address does not match what is registered.' `
            "$NotUser Fix the redirect URI in the app registration or ask the vendor."
        '50196'   = & $E 'LoopDetected' 'App' $false 'App stuck in a sign-in loop' `
            'The app made the same request too many times in a short period.' `
            'Close and reopen the app, clear its cached sign-in, or update it. Persistent loops are an app bug.'
        '50020'   = & $E 'UserUnauthorized' 'Guest' $false 'Account not in this tenant' `
            'The account the user signed in with does not exist in the tenant that owns the app, so it cannot get in. Typical when a guest uses a different account than the one invited, or opens a link to the wrong tenant.' `
            'Invite the person as a guest with the account they use, or have them sign out and sign in with the invited account.'
        '16000'   = & $E 'InteractionRequired' 'Guest' $true 'Account not in this tenant (account picker)' `
            'The selected account does not exist in this tenant; usually the user picked the wrong account in the account picker.' `
            'Sign in with the account that belongs to (or was invited to) this tenant.'
        '5000224' = & $E 'NotAllowedTenantBlockedTenantFraud' 'Account' $false 'Tenant blocked by Microsoft' `
            'Microsoft has blocked the tenant.' `
            'Contact Microsoft support.'

        # --- Normal prompts (interrupts) ---
        '50140'   = & $E 'KmsiInterrupt' 'Interrupt' $true '"Stay signed in?" prompt' `
            'Not an error: the user was shown the "Stay signed in?" prompt.' `
            'Nothing to do.'
        '50199'   = & $E 'CmsiInterrupt' 'Interrupt' $true 'Confirm-app prompt' `
            'Not an error: the user was asked to confirm that this app is the one they meant to sign in to (a protection against spoofed apps, common in mobile browsers).' `
            'Nothing to do.'
        '50125'   = & $E 'PasswordResetRegistrationRequiredInterrupt' 'Interrupt' $true 'Password reset registration prompt' `
            'The sign-in was paused to ask the user to register for password reset.' `
            'Nothing to do; the user completes or skips registration.'
        '50058'   = & $E 'UserInformationNotProvided' 'Interrupt' $true 'Silent sign-in not possible' `
            'An app tried to sign the user in silently and there was no session yet. Expected before a normal sign-in.' `
            'Nothing to do unless the user keeps getting asked to sign in, which points to blocked cookies or a browser setting.'
        '81010'   = & $E 'DesktopSsoAuthTokenInvalid' 'Interrupt' $true 'Seamless SSO did not work' `
            'Seamless single sign-on failed because the Kerberos ticket was expired or invalid, so the user was asked for a password instead.' `
            'Usually nothing. If it happens to everyone, check the Seamless SSO computer account (AZUREADSSOACC) and its key rollover.'
        '50089'   = & $E 'FlowTokenExpired' 'Interrupt' $true 'Sign-in took too long' `
            'The sign-in page was left open too long and its session expired.' `
            'Start the sign-in again.'
        '9002341' = & $E 'SsoConsentRequired' 'Interrupt' $true 'User must allow single sign-on' `
            'The user has not allowed the app to sign them in with single sign-on yet.' `
            'The user accepts the prompt.'
    }
}
