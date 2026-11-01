function Get-CIPPGuestInventory {
    <#
    .SYNOPSIS
        Inventory every guest in a tenant with origin, redemption state, activity, memberships and a recommended action.
    .DESCRIPTION
        Read only. Shared by ListGuestInventory (the Guest Inventory page) and the GuestReview report (client-facing PDF).

        Per guest: invitation state and age, sign-in activity (tenants with Entra ID P1 only - Graph rejects signInActivity
        otherwise), account type from the federated identity issuer (personal Microsoft account, email one-time passcode,
        work/school, Google, Facebook), consumer email domains, the inviting user (beta users/{id}/invitedBy) and whether
        that user is still enabled, and group / Team memberships.

        Origin, verified 2026-11-01: invitedBy only ever returns a person. A guest SharePoint/OneDrive created through the
        Entra B2B integration shows the user who shared, exactly like an Entra invite, so the two cannot be told apart per
        guest and the directory audit log keeps only 30 days. The tenant's SharePoint B2B integration and sharing level are
        returned as context instead. Guests with no inviter were created by an admin, an app or before invitedBy was kept.

        Recommended action, first match wins:
          REMOVE  - invitation never redeemed after PendingDays (default 30); or already disabled with no sign-in for StaleDays
          DISABLE - enabled, redeemed, and no sign-in for StaleDays (default 90) or never signed in after StaleDays
          REVIEW  - personal account or consumer domain, the inviter is disabled or deleted, or activity is unknown (no P1)
                    and the guest is older than StaleDays
          KEEP    - everything else
        Aspendora fork addition (Vikunja CIPP-14).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [int]$StaleDays = 90,
        [int]$PendingDays = 30,
        [switch]$SkipTenantContext
    )

    $ConsumerDomains = @(
        'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'passport.com',
        'yahoo.com', 'ymail.com', 'rocketmail.com', 'aol.com', 'icloud.com', 'me.com', 'mac.com',
        'protonmail.com', 'proton.me', 'pm.me', 'gmx.com', 'gmx.net', 'mail.com', 'zoho.com', 'yandex.com',
        'att.net', 'sbcglobal.net', 'bellsouth.net', 'comcast.net', 'verizon.net', 'cox.net', 'charter.net', 'earthlink.net'
    )
    $Now = (Get-Date).ToUniversalTime()
    $Errors = [System.Collections.Generic.List[string]]::new()

    function Get-AgeDays($Value) {
        if (-not $Value) { return $null }
        try {
            $When = if ($Value -is [datetime]) { $Value.ToUniversalTime() } else { ([datetimeoffset]$Value).UtcDateTime }
            return [int][math]::Floor(($Now - $When).TotalDays)
        } catch { return $null }
    }

    $SignInCapable = [bool](Test-CIPPStandardLicense -StandardName 'GuestInventory' -TenantFilter $TenantFilter -Preset Entra -SkipLog)
    $Select = @('id', 'displayName', 'mail', 'userPrincipalName', 'createdDateTime', 'creationType', 'accountEnabled',
        'externalUserState', 'externalUserStateChangeDateTime', 'identities')
    if ($SignInCapable) { $Select += 'signInActivity' }
    $Top = if ($SignInCapable) { 500 } else { 999 }
    $Guests = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/users?`$filter=userType eq 'Guest'&`$select=$($Select -join ',')&`$count=true&`$top=$Top" -tenantid $TenantFilter -ComplexFilter)

    # Inviter and memberships, batched. One failed sub-request leaves that guest's field unknown, not the whole run.
    $InvitedBy = @{}
    $MemberOf = @{}
    if ($Guests.Count -gt 0) {
        $Requests = foreach ($Guest in $Guests) {
            @{ id = "inv-$($Guest.id)"; method = 'GET'; url = "users/$($Guest.id)/invitedBy" }
            @{ id = "mem-$($Guest.id)"; method = 'GET'; url = "users/$($Guest.id)/memberOf?`$select=id,displayName,groupTypes,resourceProvisioningOptions,securityEnabled" }
        }
        try {
            foreach ($Response in @(New-GraphBulkRequest -Requests @($Requests) -tenantid $TenantFilter -asapp $true)) {
                if ([int]$Response.status -ge 300) { continue }
                $Key = [string]$Response.id
                $Value = @($Response.body.value)
                if ($Key.StartsWith('inv-')) { $InvitedBy[$Key.Substring(4)] = $Value }
                elseif ($Key.StartsWith('mem-')) { $MemberOf[$Key.Substring(4)] = $Value }
            }
        } catch {
            $Errors.Add("Inviter and membership lookup failed: $((Get-CippException -Exception $_).NormalizedError)")
        }
    }

    $Rows = foreach ($Guest in $Guests) {
        $Id = [string]$Guest.id
        $Mail = [string]$Guest.mail
        $Domain = if ($Mail -like '*@*') { ($Mail -split '@')[-1].ToLower() } else { $null }

        $Issuers = @($Guest.identities | Where-Object { $_.signInType -eq 'federated' } | ForEach-Object { [string]$_.issuer })
        $AccountType = if ($Issuers -contains 'MicrosoftAccount') { 'Personal Microsoft account' }
        elseif ($Issuers -contains 'mail') { 'Email one-time passcode' }
        elseif ($Issuers -contains 'ExternalAzureAD') { 'Work or school (Entra)' }
        elseif ($Issuers -contains 'google.com') { 'Google' }
        elseif ($Issuers -contains 'facebook.com') { 'Facebook' }
        elseif ([string]$Guest.externalUserState -eq 'PendingAcceptance') { 'Not redeemed yet' }
        else { 'Unknown' }
        $Personal = ($AccountType -in @('Personal Microsoft account', 'Google', 'Facebook')) -or ($Domain -and $ConsumerDomains -contains $Domain)

        $LastSignIn = $null
        foreach ($Candidate in @($Guest.signInActivity.lastSignInDateTime, $Guest.signInActivity.lastNonInteractiveSignInDateTime, $Guest.signInActivity.lastSuccessfulSignInDateTime)) {
            if ($Candidate -and (-not $LastSignIn -or ([datetimeoffset]$Candidate) -gt ([datetimeoffset]$LastSignIn))) { $LastSignIn = $Candidate }
        }
        $DaysSinceSignIn = Get-AgeDays $LastSignIn
        $AgeDays = Get-AgeDays $Guest.createdDateTime
        $Pending = ([string]$Guest.externalUserState -eq 'PendingAcceptance')
        # Re-sending an invitation moves externalUserStateChangeDateTime, so it measures the latest invitation.
        $PendingSinceDays = if ($Pending) { Get-AgeDays ($Guest.externalUserStateChangeDateTime ?? $Guest.createdDateTime) } else { $null }

        $InviterKnown = $InvitedBy.ContainsKey($Id)
        $Inviter = if ($InviterKnown) { @($InvitedBy[$Id])[0] } else { $null }
        $InviterName = if ($Inviter) { [string]($Inviter.displayName ?? $Inviter.userPrincipalName) } else { $null }
        $InviterState = if (-not $InviterKnown) { 'Unknown' } elseif (-not $Inviter) { 'None recorded' } elseif ($Inviter.accountEnabled -eq $false) { 'Disabled' } else { 'Active' }

        $Groups = if ($MemberOf.ContainsKey($Id)) { @($MemberOf[$Id] | Where-Object { [string]$_.'@odata.type' -eq '#microsoft.graph.group' }) } else { $null }
        $Teams = @($Groups | Where-Object { @($_.resourceProvisioningOptions) -contains 'Team' })

        $Reasons = [System.Collections.Generic.List[string]]::new()
        $Action = 'KEEP'
        if ($Pending -and $null -ne $PendingSinceDays -and $PendingSinceDays -ge $PendingDays) {
            $Action = 'REMOVE'; $Reasons.Add("Invitation not redeemed for $PendingSinceDays days")
        } elseif ($Guest.accountEnabled -eq $false -and $SignInCapable -and ($null -eq $DaysSinceSignIn -or $DaysSinceSignIn -ge $StaleDays)) {
            $Action = 'REMOVE'; $Reasons.Add($(if ($null -eq $DaysSinceSignIn) { 'Disabled and never signed in' } else { "Disabled, no sign-in for $DaysSinceSignIn days" }))
        } elseif ($Guest.accountEnabled -ne $false -and -not $Pending -and $SignInCapable -and $null -ne $DaysSinceSignIn -and $DaysSinceSignIn -ge $StaleDays) {
            $Action = 'DISABLE'; $Reasons.Add("No sign-in for $DaysSinceSignIn days")
        } elseif ($Guest.accountEnabled -ne $false -and -not $Pending -and $SignInCapable -and $null -eq $DaysSinceSignIn -and $null -ne $AgeDays -and $AgeDays -ge $StaleDays) {
            $Action = 'DISABLE'; $Reasons.Add("Redeemed but never signed in (created $AgeDays days ago)")
        }
        if ($Personal) {
            $What = if ($AccountType -in @('Personal Microsoft account', 'Google', 'Facebook')) { $AccountType } else { "consumer domain $Domain" }
            $Reasons.Add("Personal account ($What)")
        }
        if ($InviterState -eq 'Disabled') { $Reasons.Add("Inviter $InviterName is disabled") }
        if (-not $SignInCapable -and $null -ne $AgeDays -and $AgeDays -ge $StaleDays -and -not $Pending) { $Reasons.Add('Sign-in activity unavailable (no Entra ID P1)') }
        if ($Action -eq 'KEEP' -and $Reasons.Count -gt 0) { $Action = 'REVIEW' }

        [pscustomobject]@{
            id                   = $Id
            displayName          = [string]$Guest.displayName
            mail                 = $Mail
            userPrincipalName    = [string]$Guest.userPrincipalName
            sourceDomain         = $Domain
            accountType          = $AccountType
            personalAccount      = [bool]$Personal
            accountEnabled       = $Guest.accountEnabled
            creationType         = [string]$Guest.creationType
            externalUserState    = [string]$Guest.externalUserState
            pendingSinceDays     = $PendingSinceDays
            createdDateTime      = $Guest.createdDateTime
            ageDays              = $AgeDays
            lastSignInDateTime   = $LastSignIn
            daysSinceSignIn      = $DaysSinceSignIn
            invitedBy            = $InviterName
            invitedByUpn         = if ($Inviter) { [string]$Inviter.userPrincipalName } else { $null }
            inviterState         = $InviterState
            groupCount           = if ($null -ne $Groups) { $Groups.Count } else { $null }
            teams                = (@($Teams.displayName) -join ', ')
            groups               = (@($Groups | Where-Object { @($_.resourceProvisioningOptions) -notcontains 'Team' } | ForEach-Object { $_.displayName }) -join ', ')
            recommendedAction    = $Action
            reasons              = ($Reasons -join '; ')
        }
    }
    $Rows = @($Rows)

    $Context = $null
    if (-not $SkipTenantContext) {
        $Context = [ordered]@{ SignInActivityAvailable = $SignInCapable }
        try {
            $Spo = Get-CIPPSPOTenant -TenantFilter $TenantFilter | Select-Object -First 1
            $Context.SharePointB2BIntegration = $Spo.EnableAzureADB2BIntegration
            $Context.SharePointSharingCapability = [string]$Spo.SharingCapability
        } catch {
            $Errors.Add("SharePoint tenant settings: $((Get-CippException -Exception $_).NormalizedError)")
        }
        try {
            $Auth = New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' -tenantid $TenantFilter | Select-Object -First 1
            $Context.AllowInvitesFrom = [string]$Auth.allowInvitesFrom
            $Context.GuestUserRole = switch ([string]$Auth.guestUserRoleId) {
                'a0b1b346-4d3e-4e8b-98f8-753987be4970' { 'Same as members' }
                '10dae51f-b6af-4016-8d66-8c2a99b929b3' { 'Limited (default)' }
                '2af84b1e-32c8-42b7-82bc-daa82404023b' { 'Restricted' }
                default { [string]$Auth.guestUserRoleId }
            }
        } catch {
            $Errors.Add("Guest invite settings: $((Get-CippException -Exception $_).NormalizedError)")
        }
    }

    $Summary = [ordered]@{
        Total       = $Rows.Count
        Remove      = @($Rows | Where-Object recommendedAction -EQ 'REMOVE').Count
        Disable     = @($Rows | Where-Object recommendedAction -EQ 'DISABLE').Count
        Review      = @($Rows | Where-Object recommendedAction -EQ 'REVIEW').Count
        Keep        = @($Rows | Where-Object recommendedAction -EQ 'KEEP').Count
        Pending     = @($Rows | Where-Object externalUserState -EQ 'PendingAcceptance').Count
        Personal    = @($Rows | Where-Object personalAccount).Count
        InviterGone = @($Rows | Where-Object inviterState -EQ 'Disabled').Count
        InTeams     = @($Rows | Where-Object { $_.teams }).Count
    }

    return [pscustomobject]@{
        Tenant        = $TenantFilter
        StaleDays     = $StaleDays
        PendingDays   = $PendingDays
        Summary       = $Summary
        TenantContext = $Context
        Guests        = $Rows
        Errors        = @($Errors)
    }
}
