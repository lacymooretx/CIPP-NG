function Get-CIPPAlertBreakGlassActivity {
    <#
    .SYNOPSIS
        Alert on ANY sign-in by, or directory change to, a registered break-glass (emergency access) account
    .DESCRIPTION
        Break-glass use is either a real outage or someone holding the keys to the tenant, so every event
        is raised as High:

          SignIn          - a successful sign-in (interactive or non-interactive)
          SignInFailed    - a failed sign-in (someone is trying the account)
          DirectoryChange - a directory audit event targeting the account (password reset, attribute
                            update, role assignment, MFA method change, group membership...) or
                            performed BY the account
          AccountMissing  - the registered account no longer exists
          AccountDisabled - the registered account is disabled, so it would not work in an emergency

        Accounts come from the BreakGlassAccounts registry (ExecBreakGlassAccounts). A tenant with none
        registered is skipped. Each run scans the last LookbackHours (default 2) so events that reach the
        Entra logs late are still caught; Write-AlertTrace -Append de-duplicates by event, so an event
        notifies once however many runs see it. Sign-in logs need Entra ID P1; without it the sign-in part
        is skipped with a logged warning and the directory checks still run.
        Aspendora fork addition (Vikunja CIPP-3).
    .FUNCTIONALITY
        Entrypoint
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Alias('input')]
        $InputValue,
        [Parameter(Mandatory)]
        $TenantFilter
    )

    $Accounts = @(Get-CIPPBreakGlassAccounts -TenantFilter $TenantFilter)
    if ($Accounts.Count -eq 0) { return }

    $LookbackHours = if ($InputValue.BreakGlassLookbackHours) { [int]$InputValue.BreakGlassLookbackHours } else { 2 }
    $Cutoff = (Get-Date).ToUniversalTime().AddHours(-$LookbackHours).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $Central = try { [System.TimeZoneInfo]::FindSystemTimeZoneById('America/Chicago') } catch { $null }
    $When = {
        param($Value)
        if (-not $Value) { return '' }
        $Utc = ([datetimeoffset]$Value).UtcDateTime
        if ($Central) {
            $Local = [System.TimeZoneInfo]::ConvertTimeFromUtc($Utc, $Central)
            $Zone = if ($Central.IsDaylightSavingTime($Local)) { 'CDT' } else { 'CST' }
            return "$($Local.ToString('yyyy-MM-dd HH:mm')) $Zone ($($Utc.ToString('HH:mm')) UTC)"
        }
        return "$($Utc.ToString('yyyy-MM-dd HH:mm')) UTC"
    }

    $Rows = [System.Collections.Generic.List[object]]::new()
    $SignInsAvailable = $true
    foreach ($Account in $Accounts) {
        $UserId = [string]$Account.RowKey
        $Label = if ($Account.UserPrincipalName) { $Account.UserPrincipalName } else { $UserId }

        # Does the account still exist and is it usable?
        try {
            $User = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users/$($UserId)?`$select=id,userPrincipalName,accountEnabled" -tenantid $TenantFilter -ErrorAction Stop
            if ($User.userPrincipalName) { $Label = $User.userPrincipalName }
            if ($User.accountEnabled -eq $false) {
                $Rows.Add([pscustomobject]@{ Id = "AccountDisabled|$UserId"; Severity = 'High'; Type = 'AccountDisabled'; Account = $Label; When = ''; Message = "Break-glass account $Label is DISABLED, so it will not work in an emergency. If nobody here disabled it on purpose, find out who did (Entra audit log) and treat it as a possible attack on the tenant's recovery path." })
            }
        } catch {
            $Err = (Get-CippException -Exception $_).NormalizedError
            if ($Err -match 'Request_ResourceNotFound|does not exist|404') {
                $Rows.Add([pscustomobject]@{ Id = "AccountMissing|$UserId"; Severity = 'High'; Type = 'AccountMissing'; Account = $Label; When = ''; Message = "Registered break-glass account $Label ($UserId) no longer exists. Check the Entra audit log for who deleted it, restore it from Deleted users if that wasn't planned, and update the registry (ExecBreakGlassAccounts)." })
                continue
            }
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Break-glass activity: could not read account $($Label): $Err" -sev Warning
        }

        # Sign-ins, success and failure, interactive and non-interactive.
        if ($SignInsAvailable) {
            try {
                $Filter = "userId eq '$UserId' and createdDateTime ge $Cutoff and (signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser'))"
                $SignIns = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$Filter&`$select=id,createdDateTime,userPrincipalName,appDisplayName,ipAddress,location,status,signInEventTypes,clientAppUsed&`$top=100" -tenantid $TenantFilter -ErrorAction Stop | Where-Object { $_.id })
                foreach ($S in $SignIns) {
                    $Ok = [int]$S.status.errorCode -eq 0
                    $Where = @($S.location.city, $S.location.countryOrRegion) | Where-Object { $_ }
                    $Detail = "from $($S.ipAddress)$(if ($Where) { " ($($Where -join ', '))" }) to $($S.appDisplayName)"
                    $Rows.Add([pscustomobject]@{
                            Id       = "SignIn|$($S.id)"
                            Severity = 'High'
                            Type     = if ($Ok) { 'SignIn' } else { 'SignInFailed' }
                            Account  = $Label
                            When     = & $When $S.createdDateTime
                            IP       = $S.ipAddress
                            App      = $S.appDisplayName
                            Result   = if ($Ok) { 'Success' } else { "Failed: $($S.status.errorCode) $($S.status.failureReason)" }
                            Message  = if ($Ok) {
                                "Break-glass account $Label SIGNED IN $Detail. If this is not a known emergency, treat the tenant as compromised: revoke the account's sessions, reset its credentials and review what it did."
                            } else {
                                "Someone tried to sign in as break-glass account $Label $Detail and failed ($($S.status.errorCode) $($S.status.failureReason)). The account name is known to whoever tried; confirm it was us."
                            }
                        })
                }
            } catch {
                $Err = (Get-CippException -Exception $_).NormalizedError
                if ($Err -match 'premium|P1|license|Authentication_RequestFromNonPremiumTenantOrB2CTenant') {
                    $SignInsAvailable = $false
                    Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message 'Break-glass activity: sign-in logs need Entra ID P1; only directory changes are checked for this tenant.' -sev Warning
                } else {
                    Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Break-glass activity: sign-in check failed for $($Label): $Err" -sev Warning
                }
            }
        }

        # Directory changes targeting the account, or made by it.
        foreach ($AuditFilter in @("targetResources/any(t: t/id eq '$UserId')", "initiatedBy/user/id eq '$UserId'")) {
            try {
                $Audits = @(New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDateTime ge $Cutoff and $AuditFilter&`$top=100" -tenantid $TenantFilter -ErrorAction Stop | Where-Object { $_.id })
                foreach ($A in $Audits) {
                    # Exchange Online's directory sync ("Microsoft Substrate Management") logs routine 'Update user'
                    # events that change nothing but TargetId.UserType. Skip exactly those; any other property counts.
                    $Changed = @($A.targetResources | Where-Object { $_.id -eq $UserId } | ForEach-Object { $_.modifiedProperties } | Where-Object { $_.displayName -notin @('Included Updated Properties', 'TargetId.UserType') })
                    if ($A.activityDisplayName -eq 'Update user' -and $A.initiatedBy.app.displayName -eq 'Microsoft Substrate Management' -and $Changed.Count -eq 0) { continue }
                    $Actor = $A.initiatedBy.user.userPrincipalName ?? $A.initiatedBy.app.displayName ?? 'unknown'
                    $ByAccount = [string]$A.initiatedBy.user.id -eq $UserId
                    $Rows.Add([pscustomobject]@{
                            Id       = "Audit|$($A.id)"
                            Severity = 'High'
                            Type     = 'DirectoryChange'
                            Account  = $Label
                            When     = & $When $A.activityDateTime
                            Actor    = $Actor
                            Result   = $A.result
                            Message  = if ($ByAccount) {
                                "Break-glass account $Label performed '$($A.activityDisplayName)' ($($A.result)). Confirm this is a known emergency."
                            } else {
                                "'$($A.activityDisplayName)' was done TO break-glass account $Label by $Actor ($($A.result)). Changes to the emergency account must be planned; if this wasn't, check the account's credentials, roles and Conditional Access exclusions now."
                            }
                        })
                }
            } catch {
                Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Break-glass activity: directory audit check failed for $($Label): $((Get-CippException -Exception $_).NormalizedError)" -sev Warning
            }
        }
    }

    # The same audit event can match both filters (an account acting on itself).
    $Rows = @($Rows | Group-Object Id | ForEach-Object { $_.Group[0] })
    if ($Rows.Count -eq 0) { return }
    $CmdletName = [string]$MyInvocation.MyCommand
    @(Write-AlertTrace -cmdletName $CmdletName -tenantFilter $TenantFilter -data @($Rows) -Append | Where-Object { $_ })
}
