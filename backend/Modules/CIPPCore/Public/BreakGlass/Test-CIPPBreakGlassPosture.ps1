function Test-CIPPBreakGlassPosture {
    <#
    .SYNOPSIS
        Evaluates a tenant's break-glass (emergency access) posture from already-collected data.
    .DESCRIPTION
        Pure rules, no Graph or table calls; Get-CIPPBreakGlassPosture collects the inputs. Based on Microsoft's
        emergency-access guidance and the Breakglass Immaturity Model. Each finding has a stable Key, so the weekly
        alert notifies once per problem and resolves when it is fixed.

        Not checkable through Graph, so not covered: credentials stored in email, the account being caught by a
        cleanup/inactivity job, and SSPR scope.
        Aspendora fork addition (Vikunja CIPP-4).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        # One entry per registered break-glass account:
        #   @{ Id; UserPrincipalName; Exists; AccountEnabled; OnPremisesSyncEnabled; PasswordPolicies;
        #      PasswordNeverExpiresByDomain; ActiveGlobalAdmin; EligibleGlobalAdmin; GroupIds; RoleTemplateIds;
        #      Methods (array of @odata.type strings, or $null if unreadable); SignInActivityKnown; LastSuccessfulSignIn }
        [object[]]$Accounts = @(),
        # Conditional Access policies (Graph objects).
        [object[]]$Policies = @(),
        # Hashtable userId -> UPN, used to name accounts with broad CA exclusions.
        [hashtable]$UserNames = @{},
        [datetime]$Now = (Get-Date).ToUniversalTime(),
        [int]$TestSignInDays = 90,
        # A non-registered user excluded from at least this many enabled All-users policies is flagged.
        [int]$BroadExclusionThreshold = 3
    )

    $GlobalAdmin = '62e90394-69f5-4237-9190-012177145e10'
    $Findings = [System.Collections.Generic.List[object]]::new()
    $Add = {
        param($Key, $Severity, $Check, $Account, $Message, $Fix)
        $Findings.Add([pscustomobject]@{ Key = $Key; Severity = $Severity; Check = $Check; Account = [string]$Account; Message = $Message; Fix = $Fix })
    }

    $Usable = @($Accounts | Where-Object { $_.Exists -and $_.AccountEnabled -ne $false })
    if (@($Accounts).Count -eq 0) {
        & $Add 'Count|0' 'Error' 'Account count' '' 'This tenant has no registered break-glass (emergency access) account. If a Conditional Access mistake, MFA outage or federation failure locks out the normal admins, there is no way back in short of a Microsoft Support recovery.' 'Create two cloud-only *.onmicrosoft.com accounts with permanent Global Administrator and FIDO2 keys, exclude them from every Conditional Access policy, store the credentials in Keeper, and register them with ExecBreakGlassAccounts.'
    } elseif ($Usable.Count -lt 2) {
        & $Add 'Count|1' 'Warning' 'Account count' '' "Only $($Usable.Count) usable break-glass account. Microsoft recommends two, so one lost key or one mistaken change does not leave the tenant without a way in." 'Create a second break-glass account with a separate FIDO2 key stored apart from the first, and register it.'
    }

    $Active = @($Policies | Where-Object { $_.state -in @('enabled', 'enabledForReportingButNotEnforced') })
    foreach ($A in $Accounts) {
        $Upn = if ($A.UserPrincipalName) { $A.UserPrincipalName } else { $A.Id }
        if (-not $A.Exists) { & $Add "Missing|$($A.Id)" 'Error' 'Exists' $Upn "Registered break-glass account $Upn no longer exists." 'Restore it from Deleted users, or create a replacement and update the registry.'; continue }
        if ($A.AccountEnabled -eq $false) { & $Add "Disabled|$($A.Id)" 'Error' 'Enabled' $Upn "Break-glass account $Upn is disabled, so it cannot be used in an emergency." 'Re-enable it, and find out from the audit log who disabled it.' }
        if ($A.OnPremisesSyncEnabled -eq $true) { & $Add "Synced|$($A.Id)" 'Error' 'Cloud-only' $Upn "Break-glass account $Upn is synced from on-premises AD, so an AD or Entra Connect outage, or an on-prem compromise, takes it out too." 'Use a cloud-only account created in Entra.' }
        if ($Upn -notmatch '@[^@]+\.onmicrosoft\.com$') { & $Add "Domain|$($A.Id)" 'Warning' 'onmicrosoft.com' $Upn "Break-glass account $Upn uses a custom domain. If that domain is federated, lapses or is misconfigured, the account can stop working." 'Use the tenant''s *.onmicrosoft.com domain for break-glass accounts.' }

        if (-not $A.ActiveGlobalAdmin) {
            if ($A.EligibleGlobalAdmin) {
                & $Add "GaEligible|$($A.Id)" 'Error' 'Permanent Global Admin' $Upn "Break-glass account $Upn only has Global Administrator as PIM-eligible. Activating it needs MFA and PIM to be working, which is exactly what fails in an emergency." 'Make the Global Administrator assignment permanent and active.'
            } else {
                & $Add "NoGa|$($A.Id)" 'Error' 'Permanent Global Admin' $Upn "Break-glass account $Upn does not hold Global Administrator, so it cannot undo a tenant-wide lockout." 'Assign Global Administrator permanently (active, not eligible).'
            }
        }

        # Conditional Access: does any active policy apply to this account without excluding it?
        # Scope resolution shared with the CA pre-flight gate (Vikunja CIPP-5).
        foreach ($P in $Active) {
            if (-not (Test-CIPPCAPolicyUserScope -Policy $P -Principal $A).InScope) { continue }
            $Controls = @($P.grantControls.builtInControls) + @(if ($P.grantControls.authenticationStrength) { 'authentication strength' }) + @(if ($P.sessionControls.signInFrequency.isEnabled) { 'sign-in frequency' })
            $ReportOnly = $P.state -eq 'enabledForReportingButNotEnforced'
            & $Add "CA|$($A.Id)|$($P.id)" ($ReportOnly ? 'Warning' : 'Error') 'Excluded from all CA' $Upn "Break-glass account $Upn is NOT excluded from Conditional Access policy '$($P.displayName)'$(if ($ReportOnly) { ' (report-only today)' }) ($(@($Controls | Where-Object { $_ }) -join ', ')). A mistake in that policy can lock out the emergency account along with everyone else." 'Exclude the account (or the break-glass group) from this policy. Exclude a group rather than individual accounts, so new policies are easy to get right.'
        }

        $NeverExpires = ([string]$A.PasswordPolicies -match 'DisablePasswordExpiration') -or $A.PasswordNeverExpiresByDomain
        if (-not $NeverExpires) { & $Add "PwdExpiry|$($A.Id)" 'Warning' 'Password never expires' $Upn "Break-glass account $Upn has an expiring password. An expired password at the moment of an emergency is a lockout of its own." 'Set passwordPolicies to DisablePasswordExpiration on the account.' }

        if ($null -eq $A.Methods) {
            & $Add "MethodsUnknown|$($A.Id)" 'Info' 'FIDO2' $Upn "Could not read the authentication methods of $Upn." 'Check them by hand in Entra.'
        } else {
            $Types = @($A.Methods | ForEach-Object { [string]$_ })
            if (-not ($Types -match 'fido2')) { & $Add "NoFido2|$($A.Id)" 'Warning' 'FIDO2' $Upn "Break-glass account $Upn has no FIDO2 security key or passkey. Microsoft's mandatory admin-portal MFA means it needs a phishing-resistant method that is not tied to one person." 'Register at least one FIDO2 key or a passkey kept in the shared Keeper vault.' }
            $Personal = @($Types | Where-Object { $_ -match 'phoneAuthenticationMethod|microsoftAuthenticatorAuthenticationMethod|softwareOath' })
            if ($Personal) { & $Add "PersonalMfa|$($A.Id)" 'Warning' 'Not tied to a person' $Upn "Break-glass account $Upn has a phone, Authenticator or OTP method ($(($Personal | ForEach-Object { $_ -replace '#microsoft.graph.', '' -replace 'AuthenticationMethod', '' }) -join ', ')). Those usually live on one person's device, which defeats an emergency account." 'Remove personal methods and rely on FIDO2 keys kept in the safe or the shared vault.' }
        }

        # SignInActivityKnown is false when the tenant has no P1 or the read failed: unknown is not "untested".
        if ($A.SignInActivityKnown) {
            $Last = try { if ($A.LastSuccessfulSignIn) { ([datetimeoffset]$A.LastSuccessfulSignIn).UtcDateTime } } catch { $null }
            if (-not $Last -or $Last -lt $Now.AddDays(-$TestSignInDays)) {
                $When = if ($Last) { "was last used successfully on $($Last.ToString('yyyy-MM-dd'))" } else { 'has no recorded successful sign-in' }
                & $Add "Untested|$($A.Id)" 'Warning' "Tested within $TestSignInDays days" $Upn "Break-glass account $Upn $When. An emergency account that has not been tested may not work when it is needed." "Sign in with it (planned, announced) at least every $TestSignInDays days and confirm it reaches the admin portals. The break-glass activity alert will fire; note the test on the ticket."
            }
        }
    }

    # Anti-pattern: other accounts quietly excluded from many All-users policies.
    $Registered = @($Accounts | ForEach-Object { [string]$_.Id })
    $Counts = @{}
    foreach ($P in @($Policies | Where-Object { $_.state -eq 'enabled' -and (@($_.conditions.users.includeUsers) -contains 'All') })) {
        foreach ($Id in @($P.conditions.users.excludeUsers | Where-Object { $_ -and $_ -ne 'GuestsOrExternalUsers' })) { $Counts[$Id] = 1 + ($Counts[$Id] ?? 0) }
    }
    foreach ($Id in $Counts.Keys) {
        if ($Id -in $Registered -or $Counts[$Id] -lt $BroadExclusionThreshold) { continue }
        $Name = $UserNames[$Id] ?? $Id
        & $Add "BroadExclusion|$Id" 'Warning' 'Broad CA exclusions' $Name "$Name is not a registered break-glass account but is excluded from $($Counts[$Id]) enabled All-users Conditional Access policies. Every exclusion is a control that does not protect that account, and day-to-day or service accounts are what attackers target." 'Remove the exclusions it does not need. If it is a break-glass account, register it; if it is a service account, scope it with a workload identity or a narrow exclusion.'
    }

    $Order = @{ Error = 0; Warning = 1; Info = 2 }
    return @($Findings | Sort-Object { $Order[$_.Severity] }, Account, Check)
}
