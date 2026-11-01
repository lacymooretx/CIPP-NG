function Get-CIPPSignInExplanation {
    <#
    .SYNOPSIS
        Explains why a user's recent sign-ins failed: error code, Conditional Access, MFA source, device, risk, fix.
    .DESCRIPTION
        Read only. Shared by ListSignInExplanation (the Sign-in Failure Explainer page) and ExecSignInExplanationNote
        (the ConnectWise note). Give either a UserPrincipalName with an hours lookback (default 24, max 720), or a
        CorrelationId / request ID (searched over the last 30 days, the sign-in log retention).

        Steps:
          1. The user (beta users: perUserMfaState, accountEnabled) and whether security defaults are on.
          2. One page (up to 999, newest first) of beta auditLogs/signIns with a light $select. Interactive only
             unless IncludeNonInteractive. Verified 2026-11-01: authenticationDetails,
             authenticationRequirementPolicies and networkLocationDetails cannot be $select-ed ("Unsupported
             Query"), so step 3 fetches the full records instead.
          3. The newest MaxResults failures and interrupts plus the latest success, in full, by id
             (auditLogs/signIns/{id}, batched).
          4. If any of them has a failed or report-only-failed Conditional Access policy, the tenant's CA policies and
             named locations, to name locations and the grant operator.
          5. ConvertTo-CIPPSignInExplanation per sign-in; an interrupt or failure followed by a success with the same
             correlation ID is marked ResolvedLater.
        Also summarises wrong-password / lockout attempts across the window (IPs, countries), which is how a
        password-spray against the account shows up.

        Sign-in logs need Entra ID P1. Without it Graph refuses the request; the result then has LicenseRequired
        true and a plain message instead of throwing. All times are US Central with UTC alongside.
        Aspendora fork addition (Vikunja CIPP-10).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [string]$UserPrincipalName,
        [ValidateRange(1, 720)]
        [int]$Hours = 24,
        [string]$CorrelationId,
        [switch]$IncludeNonInteractive,
        [ValidateRange(1, 100)]
        [int]$MaxResults = 25
    )

    $UserPrincipalName = "$UserPrincipalName".Trim()
    $CorrelationId = "$CorrelationId".Trim()
    if (-not $UserPrincipalName -and -not $CorrelationId) { throw 'Give a user principal name, or a correlation ID / request ID.' }
    $Guid = [guid]::Empty
    if ($CorrelationId -and -not [guid]::TryParse($CorrelationId, [ref]$Guid)) { throw "'$CorrelationId' is not a correlation ID or request ID (expected a GUID)." }

    $Errors = [System.Collections.Generic.List[string]]::new()
    $IsoFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
    $EndUtc = [datetime]::UtcNow
    $StartUtc = if ($CorrelationId) { $EndUtc.AddDays(-30) } else { $EndUtc.AddHours(-$Hours) }
    $LicenseRegex = 'Authentication_RequestFromNonPremiumTenantOrB2CTenant|premium licen|NonPremium|\bP1\b'

    # --- 1. User and tenant context ---
    $User = $null
    if ($UserPrincipalName) {
        try {
            $User = New-GraphGetRequest -uri "https://graph.microsoft.com/beta/users/$([uri]::EscapeDataString($UserPrincipalName))?`$select=id,displayName,userPrincipalName,accountEnabled,perUserMfaState,userType,onPremisesSyncEnabled" -tenantid $TenantFilter -noPagination $true | Select-Object -First 1
        } catch {
            $Errors.Add("Could not read the user $($UserPrincipalName): $((Get-CippException -Exception $_).NormalizedError)")
        }
    }
    $SecurityDefaults = $null
    try {
        $SecurityDefaults = [bool](New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' -tenantid $TenantFilter -noPagination $true | Select-Object -First 1).isEnabled
    } catch {
        $Errors.Add("Security defaults state: $((Get-CippException -Exception $_).NormalizedError)")
    }

    # --- 2. Light list ---
    $Clauses = [System.Collections.Generic.List[string]]::new()
    if ($CorrelationId) {
        $Clauses.Add("(correlationId eq '$CorrelationId' or id eq '$CorrelationId')")
    } elseif ($User.id) {
        $Clauses.Add("userId eq '$($User.id)'")
    } else {
        $Clauses.Add("userPrincipalName eq '$($UserPrincipalName -replace "'", "''")'")
    }
    $Clauses.Add("createdDateTime ge $($StartUtc.ToString($IsoFormat))")
    if ($IncludeNonInteractive) { $Clauses.Add("(signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser'))") }
    $Filter = $Clauses -join ' and '
    $LightSelect = 'id,createdDateTime,userPrincipalName,userId,appDisplayName,ipAddress,clientAppUsed,correlationId,conditionalAccessStatus,status,location'
    $ListUri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$([uri]::EscapeDataString($Filter))&`$select=$LightSelect&`$orderby=createdDateTime desc&`$top=999"

    $Base = [ordered]@{
        Tenant                = $TenantFilter
        UserPrincipalName     = if ($User.userPrincipalName) { [string]$User.userPrincipalName } else { $UserPrincipalName }
        CorrelationId         = $CorrelationId
        Hours                 = if ($CorrelationId) { 720 } else { $Hours }
        IncludeNonInteractive = [bool]$IncludeNonInteractive
        WindowStart           = ConvertTo-CIPPCentralTime -Value $StartUtc
        WindowEnd             = ConvertTo-CIPPCentralTime -Value $EndUtc
        GeneratedAt           = ConvertTo-CIPPCentralTime -Value $EndUtc
        TimeZone              = 'Times are US Central (America/Chicago) with UTC alongside.'
        LicenseRequired       = $false
        User                  = if ($User) {
            [pscustomobject]@{
                Id = [string]$User.id; DisplayName = [string]$User.displayName; UserPrincipalName = [string]$User.userPrincipalName
                AccountEnabled = $User.accountEnabled; PerUserMfaState = [string]$User.perUserMfaState; UserType = [string]$User.userType
                Synced = [bool]$User.onPremisesSyncEnabled
            }
        } else { $null }
        SecurityDefaultsEnabled = $SecurityDefaults
    }

    try {
        $Light = @(New-GraphGetRequest -uri $ListUri -tenantid $TenantFilter -noPagination $true -ErrorAction Stop | Where-Object { $_ })
    } catch {
        $Message = (Get-CippException -Exception $_).NormalizedError
        if ("$Message $($_.Exception.Message)" -match $LicenseRegex) {
            $Base.LicenseRequired = $true
            $Base.Headline = 'This tenant has no Entra ID P1 licence, so Microsoft does not provide sign-in logs to CIPP. Check the account state below, or ask the user for the exact error screen (it shows the AADSTS code and a correlation ID).'
            $Base.Counts = [ordered]@{ Total = 0; Failures = 0; Interrupts = 0; Successes = 0; Shown = 0 }
            $Base.SignIns = @()
            $Base.ByError = @()
            $Base.PasswordAttempts = $null
            $Base.Truncated = $false
            $Base.Errors = @($Errors)
            $Bundle = [pscustomobject]$Base
            $Bundle | Add-Member -NotePropertyName SummaryText -NotePropertyValue (ConvertTo-CIPPSignInExplanationNote -Bundle $Bundle)
            return $Bundle
        }
        throw
    }

    $Catalog = Get-CIPPSignInErrorCatalog
    $CodeOf = { param($S) $C = 0; [void][int]::TryParse("$($S.status.errorCode)", [ref]$C); $C }
    $UtcOf = { param($S) (ConvertTo-CIPPCentralTime -Value $S.createdDateTime).Utc }
    $IsInterrupt = { param($C) $E = $Catalog["$C"]; [bool]($E -and $E.Interrupt) }

    $Successes = @($Light | Where-Object { (& $CodeOf $_) -eq 0 })
    $Problems = @($Light | Where-Object { (& $CodeOf $_) -ne 0 })
    # Newest first; the list is already ordered, but sort again so a mocked or reordered page cannot change the pick.
    $Problems = @($Problems | Sort-Object -Property { & $UtcOf $_ } -Descending)
    $LatestSuccess = $Successes | Sort-Object -Property { & $UtcOf $_ } -Descending | Select-Object -First 1
    $Pick = @($Problems | Select-Object -First $MaxResults)
    if ($LatestSuccess) { $Pick += $LatestSuccess }

    # --- 3. Full records for the picked sign-ins ---
    $Full = @{}
    $BulkFailed = $false
    if ($Pick.Count -gt 0) {
        $Requests = @($Pick | ForEach-Object { @{ id = [string]$_.id; method = 'GET'; url = "auditLogs/signIns/$($_.id)" } })
        try {
            foreach ($Response in @(New-GraphBulkRequest -Requests $Requests -tenantid $TenantFilter -Version 'beta')) {
                if ([int]$Response.status -lt 300 -and $Response.body) { $Full[[string]$Response.id] = $Response.body }
            }
        } catch {
            $BulkFailed = $true
            $Errors.Add("Full sign-in details could not be read, so Conditional Access and MFA details are missing: $((Get-CippException -Exception $_).NormalizedError)")
        }
        $Missing = @($Pick | Where-Object { -not $Full.ContainsKey([string]$_.id) }).Count
        if ($Missing -gt 0 -and -not $BulkFailed) { $Errors.Add("$Missing sign-in(s) are shown without Conditional Access details (their detail request failed).") }
    }
    $Records = @($Pick | ForEach-Object { if ($Full.ContainsKey([string]$_.id)) { $Full[[string]$_.id] } else { $_ } })

    # Correlation mode: the user comes from the sign-in itself.
    if (-not $User -and $Records.Count -gt 0 -and $Records[0].userId) {
        try {
            $User = New-GraphGetRequest -uri "https://graph.microsoft.com/beta/users/$($Records[0].userId)?`$select=id,displayName,userPrincipalName,accountEnabled,perUserMfaState,userType,onPremisesSyncEnabled" -tenantid $TenantFilter -noPagination $true | Select-Object -First 1
            if ($User) {
                $Base.UserPrincipalName = [string]$User.userPrincipalName
                $Base.User = [pscustomobject]@{
                    Id = [string]$User.id; DisplayName = [string]$User.displayName; UserPrincipalName = [string]$User.userPrincipalName
                    AccountEnabled = $User.accountEnabled; PerUserMfaState = [string]$User.perUserMfaState; UserType = [string]$User.userType
                    Synced = [bool]$User.onPremisesSyncEnabled
                }
            }
        } catch {
            $Errors.Add("Could not read the signed-in user: $((Get-CippException -Exception $_).NormalizedError)")
        }
    }

    # --- 4. CA policy definitions, only when a policy failed ---
    $PolicyMap = @{}
    $LocationMap = @{}
    $NeedPolicies = @($Records | Where-Object { @($_.appliedConditionalAccessPolicies | Where-Object { [string]$_.result -in @('failure', 'reportOnlyFailure', 'reportOnlyInterrupted') }).Count -gt 0 }).Count -gt 0
    if ($NeedPolicies) {
        try {
            foreach ($P in @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies' -tenantid $TenantFilter)) { if ($P.id) { $PolicyMap[[string]$P.id] = $P } }
            foreach ($L in @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/namedLocations' -tenantid $TenantFilter)) { if ($L.id) { $LocationMap[[string]$L.id] = [string]$L.displayName } }
        } catch {
            $Errors.Add("Conditional Access policy details: $((Get-CippException -Exception $_).NormalizedError)")
        }
    }

    # --- 5. Explain ---
    $PerUser = [string]$User.perUserMfaState
    $Rows = foreach ($Record in $Records) {
        $Row = ConvertTo-CIPPSignInExplanation -SignIn $Record -Policies $PolicyMap -NamedLocations $LocationMap -PerUserMfaState $PerUser -SecurityDefaultsEnabled $SecurityDefaults -TenantFilter $TenantFilter -Catalog $Catalog
        if ($Row.Outcome -ne 'Success' -and $Row.CorrelationId) {
            $Later = @($Successes | Where-Object { [string]$_.correlationId -eq $Row.CorrelationId -and (& $UtcOf $_) -ge $Row.TimeUtc })
            if ($Later.Count -gt 0) {
                $Row.ResolvedLater = $true
                if ($Row.Outcome -eq 'Interrupted') { $Row.Fix = 'Nothing to do: the user completed this step and signed in successfully straight afterwards (same correlation ID).' }
            }
        }
        $Row
    }
    $Rows = @($Rows | Sort-Object -Property TimeUtc -Descending)

    # Wrong password / lockout across the whole window, from the light list.
    $PasswordRows = @($Problems | Where-Object { (& $CodeOf $_) -in @(50126, 50053) })
    $PasswordAttempts = $null
    if ($PasswordRows.Count -gt 0) {
        $Ips = @($PasswordRows | ForEach-Object { [string]$_.ipAddress } | Where-Object { $_ } | Select-Object -Unique)
        $Countries = @($PasswordRows | ForEach-Object { [string]$_.location.countryOrRegion } | Where-Object { $_ } | Select-Object -Unique)
        $HomeCountry = if ($LatestSuccess) { [string]$LatestSuccess.location.countryOrRegion } else { $null }
        $Foreign = @($Countries | Where-Object { $HomeCountry -and $_ -ne $HomeCountry })
        $Attack = $Ips.Count -ge 3 -or $Foreign.Count -gt 0
        $PasswordAttempts = [pscustomobject]@{
            Count       = $PasswordRows.Count
            Lockouts    = @($PasswordRows | Where-Object { (& $CodeOf $_) -eq 50053 }).Count
            DistinctIPs = $Ips.Count
            Countries   = $Countries
            HomeCountry = $HomeCountry
            LikelyAttack = [bool]$Attack
            Summary     = "$($PasswordRows.Count) wrong-password or lockout events from $($Ips.Count) IP address(es) in $(if ($Countries.Count) { $Countries -join ', ' } else { 'unknown countries' })." + $(if ($Attack) { " This looks like someone else guessing the password$(if ($Foreign.Count) { " (the last successful sign-in was from $HomeCountry)" }), not the user mistyping it. Keep MFA enforced and consider a Conditional Access block for the source; do not reset the password only because of this." } else { ' This looks like the user (or one of their devices) using a wrong or old password.' })
        }
    }

    $ByError = @($Problems | Group-Object -Property { & $CodeOf $_ } | ForEach-Object {
            $C = [int]$_.Name
            $Entry = $Catalog["$C"]
            $Newest = $_.Group | Sort-Object -Property { & $UtcOf $_ } -Descending | Select-Object -First 1
            [pscustomobject]@{
                ErrorCode = $C
                Title     = if ($Entry) { $Entry.Title } else { [string]$Newest.status.failureReason }
                Outcome   = if ($Entry -and $Entry.Interrupt) { 'Interrupted' } else { 'Failure' }
                Count     = $_.Count
                LastSeen  = (ConvertTo-CIPPCentralTime -Value $Newest.createdDateTime).Display
            }
        } | Sort-Object -Property Count -Descending)

    # A failure or prompt followed by a success with the same correlation ID (a typo, an MFA prompt) is not the problem.
    $Real = @($Rows | Where-Object { $_.Outcome -ne 'Success' -and -not $_.ResolvedLater })
    $Who = if ($Base.UserPrincipalName) { $Base.UserPrincipalName } else { 'this user' }
    $Headline = if ($Light.Count -eq 0) {
        if ($CorrelationId) { "No sign-in with correlation or request ID $CorrelationId in the last 30 days$(if ($IncludeNonInteractive) { '' } else { ' (interactive sign-ins only; try including non-interactive)' })." }
        else { "No sign-ins for $Who in the last $Hours hours$(if ($IncludeNonInteractive) { '' } else { ' (interactive only)' }). If the user is getting an error, it may be from another account or tenant; ask for the correlation ID on the error screen." }
    } elseif ($Real.Count -gt 0) {
        $Top = $Real[0]
        "$($Top.Title) at $($Top.Time)$(if ($Top.ErrorCode) { " (AADSTS$($Top.ErrorCode))" }). $($Top.Explanation)"
    } elseif ($Problems.Count -gt 0) {
        "No unresolved failures: each of the $($Problems.Count) failed or interrupted sign-in(s) shown was followed by a successful sign-in."
    } else {
        "No failed sign-ins for $Who in this window; the latest sign-in succeeded at $((ConvertTo-CIPPCentralTime -Value $LatestSuccess.createdDateTime).Display)."
    }
    if ($Base.User -and $Base.User.AccountEnabled -eq $false) { $Headline = "The account is disabled. $Headline" }

    $Base.Headline = $Headline
    $Base.Counts = [ordered]@{
        Total      = $Light.Count
        Failures   = @($Problems | Where-Object { -not (& $IsInterrupt (& $CodeOf $_)) }).Count
        Interrupts = @($Problems | Where-Object { & $IsInterrupt (& $CodeOf $_) }).Count
        Successes  = $Successes.Count
        Shown      = $Rows.Count
    }
    $Base.LatestSuccess = if ($LatestSuccess) { (ConvertTo-CIPPCentralTime -Value $LatestSuccess.createdDateTime).Display } else { $null }
    $Base.Truncated = $Light.Count -ge 999
    $Base.ByError = $ByError
    $Base.PasswordAttempts = $PasswordAttempts
    $Base.SignIns = $Rows
    $Base.Errors = @($Errors)
    $Bundle = [pscustomobject]$Base
    $Bundle | Add-Member -NotePropertyName SummaryText -NotePropertyValue (ConvertTo-CIPPSignInExplanationNote -Bundle $Bundle)
    $Bundle
}
