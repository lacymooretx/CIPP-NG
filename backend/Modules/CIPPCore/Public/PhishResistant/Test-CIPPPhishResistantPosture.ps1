function Test-CIPPPhishResistantPosture {
    <#
    .SYNOPSIS
        Evaluates a tenant's phishing-resistant MFA posture for privileged role holders from already-collected data.
    .DESCRIPTION
        Pure rules, no Graph or table calls; Get-CIPPPhishResistantPosture collects the inputs. Returns
        @{ Summary; Admins; Findings }. Each finding has a stable Key, so the weekly alert notifies once per problem
        and resolves when it is fixed.

        Phishing-resistant = FIDO2 security key or passkey (device-bound, Authenticator, Windows Hello or synced),
        Windows Hello for Business, macOS Platform Credential (Secure Enclave key) and certificate-based auth.
        Synced passkeys are counted (they are origin-bound), but the admin table shows which kind each admin has.
        Break-glass accounts only count when they have a FIDO2 key or passkey: Windows Hello and Platform Credential
        are tied to one device, which is no use in an emergency.

        Report only: nothing is changed. Aspendora fork addition (Vikunja CIPP-7).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        # userRegistrationDetails rows (id, userPrincipalName, userType, methodsRegistered). $null = report unreadable.
        [object[]]$Registrations,
        # One entry per privileged user:
        #   @{ Id; UserPrincipalName; DisplayName; AccountEnabled; Mail; SkuIds (assigned skuIds; or LicenseCount);
        #      Roles = @(@{ RoleTemplateId; Kind = 'Active'|'Eligible'; Via = 'Direct'|'Group: <name>' });
        #      Methods = array of methodsRegistered names, or $null if unknown }
        # Methods may be omitted; they are then looked up in Registrations by Id.
        [object[]]$Holders = @(),
        # Object ids of registered break-glass accounts.
        [string[]]$BreakGlassIds = @(),
        # beta policies/authenticationMethodsPolicy, or $null if unreadable.
        $Policy,
        # $false when PIM eligibility could not be read (no Entra ID P2): eligible-only admins are then not seen.
        [bool]$EligibleKnown = $true,
        [int]$MinGlobalAdmins = 2,
        [int]$MaxGlobalAdmins = 4
    )

    $RoleNames = [ordered]@{
        '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
        'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
        '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
        '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
        'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
        'c4e39bd9-1100-46d3-8c65-fb160da0071f' = 'Authentication Administrator'
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
        '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
        '3a2c62db-5318-420d-8d74-23affee5d9d5' = 'Intune Administrator'
        '729827e3-9c14-49f7-bb1b-9608f156bbb8' = 'Helpdesk Administrator'
        'b0f54661-2d74-4c50-afa3-1ec803f12efe' = 'Billing Administrator'
    }
    $GlobalAdmin = '62e90394-69f5-4237-9190-012177145e10'
    # Roles that can take over the tenant outright: missing phishing-resistant MFA here is an Error.
    $Tier0 = @($GlobalAdmin, 'e8611ab8-c189-46e8-94e1-60213ab1f814', '7be44c8a-adaf-4e2a-84d6-ab2649e08a13')
    # methodsRegistered names, verified against userRegistrationDetails in real tenants on 2026-10-31
    # (passKeyDeviceBound, passKeyDeviceBoundAuthenticator, passKeySynced, windowsHelloForBusiness seen live).
    # The rest are from Microsoft's documented enum, plus authentication/methods @odata.type names for the fallback.
    $PasskeyPattern = '^(fido2|passKey\w*|#microsoft\.graph\.fido2AuthenticationMethod)$'
    $PhishResPattern = '^(fido2|passKey\w*|windowsHelloForBusiness|macOsSecureEnclaveKey|platformCredential|x509Certificate\w*|#microsoft\.graph\.(fido2|windowsHelloForBusiness|platformCredential|x509Certificate)AuthenticationMethod)$'
    # Entra ID P1, P2, Governance, EMS E3, EMS E5, Intune (GUIDs from Config/ConversionTable.csv).
    $IdentityOnlySkus = @('078d2b04-f1bd-4111-bbd4-b4b1b354cef4', '84a661c4-e949-4bd2-a560-ed7766fcaf2b', 'cf6b0d46-4093-4546-a0ab-0b1546dcc10e',
        'efccb6f7-5641-4e0e-bd10-b4976e1bf68e', 'b05e124f-c7cc-45a0-a6aa-8cf78c946968', '061f9ace-7d42-4136-88ac-31dc755f143f')
    $AuthenticatorAaguids =[ordered]@{ 'de1e552d-db1d-4423-a619-566b625cdc84' = 'Android'; '90a3ccdf-635c-4729-a248-9b709135078f' = 'iOS' }

    $Findings = [System.Collections.Generic.List[object]]::new()
    $Add = {
        param($Key, $Severity, $Check, $Account, $Message, $Fix)
        $Findings.Add([pscustomobject]@{ Key = $Key; Severity = $Severity; Check = $Check; Account = [string]$Account; Message = $Message; Fix = $Fix })
    }
    $Short = { param($M) [string]$M -replace '^#microsoft\.graph\.', '' -replace 'AuthenticationMethod$', '' }

    $RegKnown = $null -ne $Registrations
    $RegById = @{}
    foreach ($R in @($Registrations)) { if ($R.id) { $RegById[[string]$R.id] = $R } }

    # --- Per-admin table and findings ---
    $Admins = foreach ($H in @($Holders)) {
        $Id = [string]$H.Id
        $Upn = if ($H.UserPrincipalName) { $H.UserPrincipalName } else { $Id }
        $IsBreakGlass = $Id -in $BreakGlassIds
        # Assigned inside the branches: an empty array returned from an if expression would collapse to $null (= unknown).
        $Methods = $null
        if ($H.PSObject.Properties.Name -contains 'Methods' -and $null -ne $H.Methods) { $Methods = @($H.Methods) }
        elseif ($RegById.ContainsKey($Id)) { $Methods = @($RegById[$Id].methodsRegistered) }
        $Strong = if ($null -ne $Methods) { @($Methods | Where-Object { [string]$_ -match $PhishResPattern }) }
        $Passkeys = if ($null -ne $Methods) { @($Methods | Where-Object { [string]$_ -match $PasskeyPattern }) }
        $Qualifies = if ($null -eq $Methods) { $null } elseif ($IsBreakGlass) { $Passkeys.Count -gt 0 } else { $Strong.Count -gt 0 }

        $RoleIds = @($H.Roles | ForEach-Object { [string]$_.RoleTemplateId } | Select-Object -Unique)
        $Kinds = @($H.Roles | ForEach-Object { [string]$_.Kind } | Select-Object -Unique | Sort-Object)
        $Via = @($H.Roles | ForEach-Object { [string]$_.Via } | Select-Object -Unique)
        $Names = @($RoleIds | ForEach-Object { $RoleNames[$_] ?? $_ })
        # Identity-only licences (Entra P1/P2, Governance, EMS, Intune) are what an admin account should have; only
        # other SKUs (mailbox, Office apps) count as "licensed for daily work". Without SkuIds fall back to the count.
        if ($H.PSObject.Properties.Name -contains 'SkuIds') {
            $WorkSkuCount = @($H.SkuIds | Where-Object { $_ -and ([string]$_).ToLower() -notin $IdentityOnlySkus }).Count
            $LicenceText = "$WorkSkuCount mailbox/productivity licence(s)"
        } else {
            $WorkSkuCount = [int]$H.LicenseCount
            $LicenceText = "$WorkSkuCount licence(s)"
        }
        $Licensed = $WorkSkuCount -gt 0
        $HasMail = -not [string]::IsNullOrWhiteSpace([string]$H.Mail)
        $Enabled = $H.AccountEnabled -ne $false
        $IsGuest = $Upn -match '#EXT#'

        if ($Enabled) {
            $IsTier0 = @($RoleIds | Where-Object { $_ -in $Tier0 }).Count -gt 0
            $RoleText = ($Names -join ', ') + $(if ($Kinds -notcontains 'Active') { ' (PIM-eligible)' })
            if ($null -eq $Qualifies) {
                & $Add "MethodsUnknown|$Id" 'Info' 'Phishing-resistant MFA' $Upn "Could not read the registered authentication methods of $Upn ($RoleText)." 'Check the account by hand in Entra > Users > Authentication methods.'
            } elseif (-not $Qualifies) {
                $Have = if (@($Methods).Count) { "registered: $((@($Methods) | ForEach-Object { & $Short $_ }) -join ', ')" } else { 'no MFA methods registered' }
                if ($IsBreakGlass) {
                    & $Add "NoPhishRes|$Id" 'Error' 'Phishing-resistant MFA' $Upn "Break-glass account $Upn ($RoleText) has no FIDO2 key or passkey ($Have). Windows Hello and Platform Credential are tied to one device, so they do not count for an emergency account." 'Register at least two FIDO2 security keys (or a passkey kept in the shared Keeper vault) and store them apart. The break-glass posture check covers the rest of its setup.'
                } else {
                    $Guest = if ($IsGuest) { ' It is a guest account: methods registered in its home tenant are not visible here, so check whether cross-tenant access settings trust the home tenant''s MFA.' } else { '' }
                    & $Add "NoPhishRes|$Id" ($IsTier0 ? 'Error' : 'Warning') 'Phishing-resistant MFA' $Upn "Admin $Upn ($RoleText) has no phishing-resistant method ($Have). Push, OTP and SMS can be relayed by an adversary-in-the-middle phishing kit, which hands over a session token that works for the admin portals.$Guest" 'Register a passkey (FIDO2 key, or a passkey in Microsoft Authenticator) or Windows Hello for Business, then enable the CIPP-7 Conditional Access policy that requires phishing-resistant MFA for admin roles.'
                }
            }
            if ($Licensed -and -not $IsGuest) {
                $What = @($LicenceText; if ($HasMail) { "mail $($H.Mail)" }) -join ' and '
                & $Add "DailyUse|$Id" 'Warning' 'Separate admin account' $Upn "Admin $Upn ($RoleText) has $What, so it looks like it is also used for daily work. Email and browsing from a privileged account put the admin session in front of every phishing message." 'Give the person a separate admin account with no mailbox or Office licence (an Entra ID P2 licence for PIM is fine), and remove the admin roles from the day-to-day one.'
            } elseif ($HasMail -and -not $IsGuest) {
                # A mail address without a mailbox licence is usually left over from an old mailbox or set by hand.
                & $Add "DailyUse|$Id" 'Info' 'Separate admin account' $Upn "Admin $Upn ($RoleText) has mail address $($H.Mail) set but no mailbox licence. It is probably not used for email, but check it is not a shared or forwarding target." 'If the address is not needed, clear it; make sure nobody signs in to read mail with this account.'
            }
        }

        [pscustomobject]@{
            UserPrincipalName        = $Upn
            DisplayName              = $H.DisplayName
            Roles                    = ($Names -join ', ')
            Assignment               = ($Kinds -join ', ')
            Via                      = ($Via -join ', ')
            Methods                  = if ($null -eq $Methods) { 'Unknown' } else { (@($Methods) | ForEach-Object { & $Short $_ }) -join ', ' }
            PhishingResistant        = if ($null -eq $Qualifies) { 'Unknown' } elseif ($Qualifies) { 'Yes' } else { 'No' }
            PhishingResistantMethods = (@($Strong) | ForEach-Object { & $Short $_ }) -join ', '
            Licensed                 = $Licensed
            HasMail                  = $HasMail
            BreakGlass               = $IsBreakGlass
            AccountEnabled           = $Enabled
            IsGlobalAdmin            = $RoleIds -contains $GlobalAdmin
            Id                       = $Id
        }
    }
    $Admins = @($Admins)

    # --- Global Administrator count (active + eligible, enabled accounts, break-glass included) ---
    $GaCount = @($Admins | Where-Object { $_.IsGlobalAdmin -and $_.AccountEnabled }).Count
    $EligibleNote = if (-not $EligibleKnown) { ' PIM-eligible assignments could not be read, so eligible-only Global Admins are not counted.' } else { '' }
    if ($GaCount -lt $MinGlobalAdmins) {
        & $Add 'GaCount|Low' 'Warning' 'Global Admin count' '' "Only $GaCount Global Administrator(s), break-glass included. With fewer than $MinGlobalAdmins, one lost key or one departure can leave the tenant without a Global Admin.$EligibleNote" 'Have two to four Global Admins: two break-glass accounts plus PIM-eligible named admins.'
    } elseif ($GaCount -gt $MaxGlobalAdmins) {
        & $Add 'GaCount|High' 'Warning' 'Global Admin count' '' "$GaCount Global Administrators (active and PIM-eligible, break-glass included). Microsoft recommends fewer than five; every extra one is another account that can take over the tenant.$EligibleNote" 'Move day-to-day admins to least-privilege roles (Exchange, User, Intune, Helpdesk Administrator) and keep Global Admin for break-glass plus one or two named admins.'
    }
    if (-not $EligibleKnown) {
        & $Add 'EligibleUnknown' 'Info' 'PIM eligibility' '' 'PIM-eligible role assignments could not be read (the tenant probably has no Entra ID P2 or Governance licence). Only active assignments were checked.' 'Nothing to fix if the tenant does not use PIM.'
    }
    if (-not $RegKnown) {
        & $Add 'RegistrationUnknown' 'Info' 'Registration report' '' 'The authentication methods registration report could not be read (it needs Entra ID P1), so tenant-wide user counts are missing. Admin methods were read per user instead.' 'Nothing to fix; the admin checks above still apply.'
    }

    # --- Authentication methods policy ---
    $PasskeysEnabled = $null; $SelfService = $null; $Campaign = $null
    if ($null -ne $Policy) {
        $Fido = @($Policy.authenticationMethodConfigurations | Where-Object { $_.id -eq 'Fido2' }) | Select-Object -First 1
        if (-not $Fido -or $Fido.state -ne 'enabled') {
            $PasskeysEnabled = $false
            & $Add 'PasskeysDisabled' 'Warning' 'Passkey (FIDO2) policy' '' 'The Passkey (FIDO2) authentication method is disabled in the authentication methods policy, so nobody can register a security key or an Authenticator passkey.' 'Entra > Authentication methods > Policies > Passkey (FIDO2): enable it for All users (or at least the admin group), with self-service set up allowed.'
        } else {
            $PasskeysEnabled = $true
            $SelfService = $Fido.isSelfServiceRegistrationAllowed -ne $false
            if (-not $SelfService) {
                & $Add 'PasskeySelfServiceOff' 'Warning' 'Passkey (FIDO2) policy' '' 'Passkeys are enabled but self-service set up is not allowed, so admins cannot register a passkey themselves at aka.ms/mysecurityinfo.' 'Turn on "Allow self-service set up" in the Passkey (FIDO2) policy.'
            }
            if (-not (@($Fido.includeTargets) | Where-Object { $_.id -eq 'all_users' })) {
                & $Add 'PasskeysScoped' 'Info' 'Passkey (FIDO2) policy' '' "Passkeys are enabled only for selected groups ($(@($Fido.includeTargets | ForEach-Object { $_.id }) -join ', ')). Admins outside those groups cannot register one." 'Make sure every admin account is in a targeted group, or target All users.'
            }
            # Key restrictions live on the method (legacy) and, since passkey profiles, on each profile.
            $Restrictions = @([pscustomobject]@{ Name = 'Passkey (FIDO2) policy'; R = $Fido.keyRestrictions }) +
                @($Fido.passkeyProfiles | ForEach-Object { [pscustomobject]@{ Name = "passkey profile '$($_.name)'"; R = $_.keyRestrictions } })
            foreach ($X in $Restrictions) {
                if (-not $X.R -or $X.R.isEnforced -ne $true) { continue }
                $Listed = @($X.R.aaGuids | ForEach-Object { ([string]$_).ToLower() })
                $Blocked = if ($X.R.enforcementType -eq 'allow') { @($AuthenticatorAaguids.Keys | Where-Object { $_ -notin $Listed }) } else { @($AuthenticatorAaguids.Keys | Where-Object { $_ -in $Listed }) }
                if ($Blocked.Count -eq 0) { continue }
                $Which = ($Blocked | ForEach-Object { "$($AuthenticatorAaguids[$_]) $_" }) -join ', '
                $How = if ($X.R.enforcementType -eq 'allow') { 'enforces an AAGUID allow list that does not include' } else { 'blocks' }
                & $Add "AaguidBlocksAuthenticator|$($X.Name)" 'Warning' 'Passkey key restrictions' '' "The $($X.Name) $How Microsoft Authenticator's passkey AAGUID ($Which), so users cannot create a passkey in Authenticator, the easiest phishing-resistant method for most admins." "Add de1e552d-db1d-4423-a619-566b625cdc84 (Android) and 90a3ccdf-635c-4729-a248-9b709135078f (iOS) to the allow list, or remove them from the block list."
            }
        }

        $C = $Policy.registrationEnforcement.authenticationMethodsRegistrationCampaign
        if ($C) {
            $Campaign = [pscustomobject]@{
                State   = $C.state
                Targets = (@($C.includeTargets) | ForEach-Object { "$($_.id) -> $($_.targetedAuthenticationMethod)" }) -join '; '
                Exclude = (@($C.excludeTargets) | ForEach-Object { $_.id }) -join ', '
            }
            if ($C.state -eq 'disabled') {
                & $Add 'CampaignDisabled' 'Info' 'Registration campaign' '' 'The authentication methods registration campaign (nudge) is disabled, so users who only have SMS or voice are not prompted to set up something stronger at sign-in.' 'Entra > Authentication methods > Registration campaign: set it to Enabled (or Microsoft managed).'
            }
        }
    }

    # --- Summary ---
    $Members = @($Registrations | Where-Object { $_.userType -ne 'guest' })
    $Summary = [pscustomobject]@{
        UsersTotal                     = if ($RegKnown) { $Members.Count } else { $null }
        UsersPhishingResistant         = if ($RegKnown) { @($Members | Where-Object { @($_.methodsRegistered | Where-Object { [string]$_ -match $PhishResPattern }).Count -gt 0 }).Count } else { $null }
        AdminsTotal                    = @($Admins | Where-Object AccountEnabled).Count
        AdminsPhishingResistant        = @($Admins | Where-Object { $_.AccountEnabled -and $_.PhishingResistant -eq 'Yes' }).Count
        AdminsWithoutPhishingResistant = @($Admins | Where-Object { $_.AccountEnabled -and $_.PhishingResistant -eq 'No' }).Count
        AdminsAlsoDailyUse             = @($Findings | Where-Object { $_.Key -like 'DailyUse|*' -and $_.Severity -eq 'Warning' }).Count
        GlobalAdmins                   = $GaCount
        EligibleKnown                  = $EligibleKnown
        PasskeysEnabled                = $PasskeysEnabled
        PasskeySelfService             = $SelfService
        RegistrationCampaign           = $Campaign
    }

    $Order = @{ Error = 0; Warning = 1; Info = 2 }
    [pscustomobject]@{
        Summary  = $Summary
        Admins   = @($Admins | Sort-Object @{ e = { @{ No = 0; Unknown = 1; Yes = 2 }[$_.PhishingResistant] } }, UserPrincipalName)
        Findings = @($Findings | Sort-Object { $Order[$_.Severity] }, Account, Check)
    }
}
