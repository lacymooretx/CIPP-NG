function Test-CIPPCAPreflight {
    <#
    .SYNOPSIS
        Pre-flight rules for turning a Conditional Access policy on (state = enabled): would it lock admins out?
    .DESCRIPTION
        Pure: no Graph or table calls; Get-CIPPCAPreflightContext collects the inputs. The policy is always
        evaluated as if enforced, whatever its state in the input.

        Checks (Status Pass / Warn / Fail / Info; Passed = no Fail):
          BreakGlassExcluded  every registered break-glass account is excluded from (or outside) the policy
          GlobalAdminAccess   at least one Global Administrator who is not a break-glass account is excluded,
                              or has a registered method that meets the grant controls
          WhatIf              the executing admin and the break-glass accounts, evaluated against the policy
          ReportOnlySoak      the policy has been in report-only for at least RequiredDays
          WouldBeBlocked      report-only sign-ins in the window that the policy would have failed

        The What-If here is CIPP's own evaluation of users, groups, roles, external user types and grant
        controls. Application, platform, location, client-app and risk conditions are treated as matching
        (worst case), and device- or app-based controls come back as Unknown (Warn). Graph's own What-If API
        is a POST and evaluates only policies that already exist, so it is not used.
        Aspendora fork addition (Vikunja CIPP-5).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        # The policy as it would be written (ids resolved). authenticationStrength may carry allowedCombinations.
        [Parameter(Mandatory)]$Policy,
        # The policy as it is in the tenant today; $null for a new policy.
        $ExistingPolicy,
        # Registered break-glass accounts: @{ Id; UserPrincipalName; Exists; MembershipKnown; GroupIds; RoleTemplateIds; Methods }
        [object[]]$BreakGlassAccounts = @(),
        # Global Administrators (users): @{ Id; UserPrincipalName; IsBreakGlass; MembershipKnown; GroupIds; RoleTemplateIds; Methods ($null = unknown) }
        [object[]]$GlobalAdmins = @(),
        [bool]$GlobalAdminsKnown = $true,
        # The admin running the change: @{ Id; UserPrincipalName; IsExternal; ExternalUserType; HomeTenantId; GroupIds; RoleTemplateIds; Methods }, or $null (timer).
        $Executor,
        # Directory audit events for this policy, newest first or any order:
        # @{ ActivityDateTime; Activity; OldState; NewState; InitiatedBy }
        [object[]]$AuditEvents = @(),
        [bool]$AuditKnown = $false,
        [string]$AuditError,
        # @{ Collected; Known; Error; WindowDays; Totals (hashtable of result -> count); Samples (rows from Get-CIPPCAPolicyImpact) }
        $SignIns,
        [int]$RequiredDays = 7,
        [datetime]$Now = (Get-Date).ToUniversalTime()
    )

    $ReportOnly = 'enabledForReportingButNotEnforced'
    $Checks = [System.Collections.Generic.List[object]]::new()
    $Add = { param($Key, $Name, $Status, $Message, $Fix) $Checks.Add([pscustomobject]@{ Key = $Key; Check = $Name; Status = $Status; Message = $Message; Fix = $Fix }) }
    $Name = { param($P) if ($P.UserPrincipalName) { [string]$P.UserPrincipalName } else { [string]$P.Id } }
    $AsUtc = { param($V) if (-not $V) { return $null }; try { ([datetimeoffset]$V).UtcDateTime } catch { $null } }
    $Fmt = { param($D) if ($D) { "$($D.ToString('yyyy-MM-dd HH:mm')) UTC" } else { 'an unknown date' } }
    $PolicyName = [string]($Policy.displayName ?? $ExistingPolicy.displayName)

    $Evaluate = {
        param($P, $Role)
        $Scope = Test-CIPPCAPolicyUserScope -Policy $Policy -Principal $P
        $Grant = if ($Scope.InScope) { Test-CIPPCAGrantSatisfiable -Policy $Policy -Methods $P.Methods } else { $null }
        $Outcome = if (-not $Scope.InScope) { 'NotApplied' } else { $Grant.Outcome }
        if ($Scope.InScope -and $P.MembershipKnown -eq $false -and $Outcome -eq 'Satisfiable') { $Outcome = 'Unknown' }
        [pscustomobject]@{
            Role              = $Role
            UserPrincipalName = & $Name $P
            Id                = [string]$P.Id
            External          = $P.IsExternal -eq $true
            InScope           = $Scope.InScope
            ScopeReason       = $Scope.Reason
            Required          = $Grant.Required
            GrantReason       = $Grant.Reason
            Outcome           = $Outcome
        }
    }

    # 1. Break-glass accounts excluded.
    $BgRows = @($BreakGlassAccounts | Where-Object { $_.Exists -ne $false } | ForEach-Object { & $Evaluate $_ 'Break-glass' })
    $Missing = @($BreakGlassAccounts | Where-Object { $_.Exists -eq $false })
    $BgUnknown = @($BreakGlassAccounts | Where-Object { $_.Exists -ne $false -and $_.MembershipKnown -eq $false })
    if (@($BreakGlassAccounts).Count -eq 0) {
        & $Add 'BreakGlassExcluded' 'Break-glass accounts excluded' 'Fail' 'No break-glass account is registered for this tenant, so CIPP cannot confirm an emergency account survives this policy.' 'Register the break-glass accounts (Identity > Break-glass accounts) and exclude them, or their group, from the policy.'
    } elseif ($InScope = @($BgRows | Where-Object InScope)) {
        & $Add 'BreakGlassExcluded' 'Break-glass accounts excluded' 'Fail' "Break-glass account(s) $(($InScope.UserPrincipalName) -join ', ') would be subject to '$PolicyName' ($(($InScope | ForEach-Object { $_.ScopeReason } | Select-Object -Unique) -join '; ')). This is how a tenant loses its way back in." 'Add the break-glass group (or the accounts) to the policy''s excluded users before enabling it.'
    } elseif (@($BgRows).Count -eq 0) {
        & $Add 'BreakGlassExcluded' 'Break-glass accounts excluded' 'Fail' "Every registered break-glass account ($(($Missing | ForEach-Object { & $Name $_ }) -join ', ')) no longer exists." 'Restore or recreate the break-glass accounts and update the registry.'
    } elseif ($BgUnknown) {
        & $Add 'BreakGlassExcluded' 'Break-glass accounts excluded' 'Warn' "Not excluded directly, and the group/role membership of $(($BgUnknown | ForEach-Object { & $Name $_ }) -join ', ') could not be read, so a group- or role-based inclusion cannot be ruled out." 'Exclude the break-glass accounts directly, or check their group membership by hand.'
    } else {
        $Status = if ($Missing) { 'Warn' } else { 'Pass' }
        $Msg = "All $(@($BgRows).Count) registered break-glass account(s) are outside the policy ($(($BgRows | ForEach-Object { "$($_.UserPrincipalName): $($_.ScopeReason)" }) -join '; '))."
        if ($Missing) { $Msg += " Registered but missing: $(($Missing | ForEach-Object { & $Name $_ }) -join ', ')." }
        & $Add 'BreakGlassExcluded' 'Break-glass accounts excluded' $Status $Msg ($(if ($Missing) { 'Clean up the break-glass registry.' } else { '' }))
    }

    # 2. At least one Global Administrator can still get in.
    $GaRows = @($GlobalAdmins | ForEach-Object { $R = & $Evaluate $_ 'Global Admin'; $R | Add-Member -NotePropertyName IsBreakGlass -NotePropertyValue ($_.IsBreakGlass -eq $true) -PassThru })
    $Through = { param($Rows) @($Rows | Where-Object { $_.Outcome -in @('NotApplied', 'Satisfiable') }) }
    $NonBg = @($GaRows | Where-Object { -not $_.IsBreakGlass })
    $NonBgOk = & $Through $NonBg
    if (-not $GlobalAdminsKnown) {
        & $Add 'GlobalAdminAccess' 'A Global Admin can still sign in' 'Warn' 'The Global Administrator role members could not be read.' 'Check by hand that at least one Global Administrator is excluded or has a method that meets the grant controls.'
    } elseif ($NonBgOk) {
        & $Add 'GlobalAdminAccess' 'A Global Admin can still sign in' 'Pass' "$($NonBgOk.Count) of $($NonBg.Count) Global Administrator(s) are excluded or can meet the controls: $(($NonBgOk | Select-Object -First 5 | ForEach-Object { "$($_.UserPrincipalName) ($(if ($_.Outcome -eq 'NotApplied') { $_.ScopeReason } else { $_.GrantReason }))" }) -join '; ')." ''
    } elseif ($NonBg.Count -eq 0) {
        & $Add 'GlobalAdminAccess' 'A Global Admin can still sign in' 'Warn' 'The only Global Administrators in this tenant are break-glass accounts (day-to-day admin is through GDAP), so the What-If for the executing admin is the check that matters.' ''
    } elseif ($Unk = @($NonBg | Where-Object Outcome -EQ 'Unknown')) {
        & $Add 'GlobalAdminAccess' 'A Global Admin can still sign in' 'Warn' "No Global Administrator is certain to get through; for $(($Unk.UserPrincipalName) -join ', ') it depends on the device/app or on methods CIPP could not read ($(($Unk | ForEach-Object GrantReason | Select-Object -Unique) -join '; '))." 'Make sure at least one Global Administrator is excluded or has a method that meets the controls.'
    } else {
        & $Add 'GlobalAdminAccess' 'A Global Admin can still sign in' 'Fail' "None of the $($NonBg.Count) Global Administrator(s) is excluded or can meet the controls ($(($NonBg | ForEach-Object { "$($_.UserPrincipalName): $($_.GrantReason)" }) -join '; '))." 'Register a method that meets the grant controls for at least one Global Administrator (check /reports/authenticationMethods/userRegistrationDetails), or exclude one, before enabling.'
    }

    # 3. What-If for the executing admin and the break-glass accounts.
    $ExecRow = if ($Executor) { & $Evaluate $Executor 'Executing admin' } else { $null }
    $WhatIf = @(@($ExecRow) + $BgRows + @($GaRows | Where-Object { -not $_.IsBreakGlass } | Select-Object -First 25) | Where-Object { $_ })
    $Bad = @(@($ExecRow) + $BgRows | Where-Object { $_ -and $_.Outcome -eq 'Blocked' })
    $Unsure = @(@($ExecRow) + $BgRows | Where-Object { $_ -and $_.Outcome -eq 'Unknown' })
    $ExecText = if (-not $ExecRow) { 'No interactive executing admin (scheduled deploy).' }
    elseif (-not $ExecRow.InScope) { "Executing admin $($ExecRow.UserPrincipalName): not applied ($($ExecRow.ScopeReason))." }
    else { "Executing admin $($ExecRow.UserPrincipalName)$(if ($ExecRow.External) { ' (service-provider/GDAP user in this tenant)' }): in scope ($($ExecRow.ScopeReason)), $($ExecRow.Outcome) - $($ExecRow.GrantReason)." }
    $BgText = if ($BgRows) { " Break-glass: $(($BgRows | ForEach-Object { "$($_.UserPrincipalName) $($_.Outcome)" }) -join ', ')." } else { '' }
    $Note = ' (CIPP evaluation of users, groups, roles and grant controls; app, platform, location and risk conditions are assumed to match.)'
    if ($Bad) {
        & $Add 'WhatIf' 'What-If: executing admin and break-glass' 'Fail' "$ExecText$BgText$Note" 'Exclude these identities, or make sure they can meet the controls, before enabling.'
    } elseif ($Unsure) {
        & $Add 'WhatIf' 'What-If: executing admin and break-glass' 'Warn' "$ExecText$BgText$Note" 'Confirm by hand (Entra What If) that these identities can still sign in.'
    } elseif (-not $ExecRow) {
        & $Add 'WhatIf' 'What-If: executing admin and break-glass' 'Info' "$ExecText$BgText$Note" ''
    } else {
        & $Add 'WhatIf' 'What-If: executing admin and break-glass' 'Pass' "$ExecText$BgText$Note" ''
    }

    # 4. Report-only soak.
    $Soak = [ordered]@{ RequiredDays = $RequiredDays; Since = $null; SinceIsLowerBound = $false; LastChanged = $null; Source = $null; DefinitionChanged = $false }
    $Fingerprint = {
        param($P)
        if (-not $P) { return '' }
        $U = $P.conditions.users; $A = $P.conditions.applications; $G = $P.grantControls
        $Parts = foreach ($L in @($U.includeUsers, $U.excludeUsers, $U.includeGroups, $U.excludeGroups, $U.includeRoles, $U.excludeRoles, $A.includeApplications, $A.excludeApplications, $A.includeUserActions, $G.builtInControls)) {
            (@($L | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLower() } | Sort-Object) -join ',')
        }
        (@($Parts) + @([string]$G.operator, [string]$G.authenticationStrength.id)) -join '|'
    }
    if (-not $ExistingPolicy) {
        & $Add 'ReportOnlySoak' "Ran in report-only for $RequiredDays days" 'Fail' 'This is a new policy. Created straight into On, it has never run in report-only, so nobody has seen what it would block.' "Deploy it as report-only, leave it for $RequiredDays days, review the would-be-blocked sign-ins, then enable it."
    } elseif ($ExistingPolicy.state -eq 'enabled') {
        & $Add 'ReportOnlySoak' "Ran in report-only for $RequiredDays days" 'Info' 'The policy is already enforced; this is an edit, so there is no report-only period to check. The checks above evaluate the new definition.' ''
    } elseif ($ExistingPolicy.state -ne $ReportOnly) {
        & $Add 'ReportOnlySoak' "Ran in report-only for $RequiredDays days" 'Fail' "The policy is '$($ExistingPolicy.state)', not report-only, so it has not collected any report-only results." "Set it to report-only for $RequiredDays days first."
    } else {
        $Last = & $AsUtc ($ExistingPolicy.modifiedDateTime ?? $ExistingPolicy.createdDateTime)
        $Soak.LastChanged = $Last
        # Most recent change INTO report-only (an Add in report-only, or an Update whose state moved to it).
        $Entered = @($AuditEvents | Where-Object { $_.NewState -eq $ReportOnly -and ($_.Activity -match '^Add' -or $_.OldState -ne $ReportOnly) } |
                Sort-Object { & $AsUtc $_.ActivityDateTime } -Descending) | Select-Object -First 1
        $Status = $null; $Msg = $null
        if ($Last -and $Last -le $Now.AddDays(-$RequiredDays)) {
            # Any write, state changes included, moves modifiedDateTime: untouched for N days and report-only now = report-only for N days.
            $Soak.Since = $Last; $Soak.SinceIsLowerBound = $true; $Soak.Source = 'modifiedDateTime'
            $Status = 'Pass'; $Msg = "Report-only and unchanged since $(& $Fmt $Last) ($([int]($Now - $Last).TotalDays) days)."
        } elseif ($Entered) {
            $Since = & $AsUtc $Entered.ActivityDateTime
            $Soak.Since = $Since; $Soak.Source = 'directoryAudit'
            $Days = [math]::Floor(($Now - $Since).TotalDays)
            if ($Since -le $Now.AddDays(-$RequiredDays)) {
                $Status = 'Warn'; $Msg = "Report-only since $(& $Fmt $Since) ($Days days, from the audit log), but the definition was changed again on $(& $Fmt $Last), so part of the window was evaluated against an older version."
            } else {
                $Status = 'Fail'; $Msg = "Report-only only since $(& $Fmt $Since) ($Days days, from the audit log); $RequiredDays are required."
            }
        } elseif ($AuditKnown) {
            # In report-only before the oldest audit event we can see; directory audits are kept 7 days (free) or 30 days (P1/P2).
            $Soak.Source = 'directoryAudit (no state change within retention)'
            if ($RequiredDays -le 7) {
                $Status = 'Warn'; $Msg = "No change into report-only in the retained audit log, so it has been report-only for at least 7 days (minimum audit retention), but the definition was edited on $(& $Fmt $Last)."
            } else {
                $Status = 'Warn'; $Msg = "No change into report-only in the retained audit log, and the definition was edited on $(& $Fmt $Last). Audit retention (7 days free, 30 days with P1) cannot prove $RequiredDays days."
            }
        } else {
            $Soak.Source = 'unknown'
            $Status = 'Warn'; $Msg = "The policy was changed on $(& $Fmt $Last) and the audit log could not be read$(if ($AuditError) { " ($AuditError)" }), so the report-only period cannot be confirmed."
        }
        if ((& $Fingerprint $Policy) -ne (& $Fingerprint $ExistingPolicy)) {
            $Soak.DefinitionChanged = $true
            if ($Status -eq 'Pass') { $Status = 'Warn' }
            $Msg += ' The definition being enabled differs from the one that ran in report-only (users, apps or grant controls changed in this same request).'
        }
        & $Add 'ReportOnlySoak' "Ran in report-only for $RequiredDays days" $Status $Msg ($(if ($Status -ne 'Pass') { "Leave the final definition in report-only for $RequiredDays days, then enable it." } else { '' }))
    }

    # 5. Would-be-blocked sign-ins from the report-only window.
    $Blocked = [ordered]@{ Collected = $false; WindowDays = $SignIns.WindowDays; Failures = 0; Interrupted = 0; Total = 0; Users = 0; AdminSignIns = @(); Samples = @() }
    if (-not $ExistingPolicy -or $ExistingPolicy.state -ne $ReportOnly) {
        & $Add 'WouldBeBlocked' 'Would-be-blocked sign-ins' 'Info' 'Not applicable: the policy is not in report-only, so there are no report-only results.' ''
    } elseif (-not $SignIns -or $SignIns.Collected -ne $true) {
        & $Add 'WouldBeBlocked' 'Would-be-blocked sign-ins' 'Info' 'Sign-ins were not collected for this run (use Run pre-flight for the full report).' ''
    } elseif ($SignIns.Known -ne $true) {
        & $Add 'WouldBeBlocked' 'Would-be-blocked sign-ins' 'Warn' "The report-only sign-ins could not be read$(if ($SignIns.Error) { ": $($SignIns.Error)" }). Sign-in logs need Entra ID P1." 'Review the policy''s report-only results in Entra (Sign-in logs > Report-only) by hand.'
    } else {
        $Totals = $SignIns.Totals
        $Samples = @($SignIns.Samples | Where-Object { $_.policyResult -in @('reportOnlyFailure', 'reportOnlyInterrupted') })
        $Blocked.Collected = $true
        $Blocked.Failures = [int]$Totals.reportOnlyFailure
        $Blocked.Interrupted = [int]$Totals.reportOnlyInterrupted
        $Blocked.Total = [int]$Totals.total
        $Blocked.Users = @($Samples | Where-Object policyResult -EQ 'reportOnlyFailure' | ForEach-Object userId | Select-Object -Unique).Count
        $Blocked.Samples = $Samples
        $Admins = @{}
        foreach ($P in @($BreakGlassAccounts) + @($GlobalAdmins) + @($Executor) | Where-Object { $_ -and $_.Id }) { $Admins[[string]$P.Id] = & $Name $P }
        $AdminHits = @($Samples | Where-Object { $_.policyResult -eq 'reportOnlyFailure' -and $Admins.ContainsKey([string]$_.userId) })
        $Blocked.AdminSignIns = $AdminHits
        $Window = "in the last $($SignIns.WindowDays) days"
        if ($AdminHits) {
            & $Add 'WouldBeBlocked' 'Would-be-blocked sign-ins' 'Fail' "$($Blocked.Failures) sign-in(s) $Window would have been blocked, including $($AdminHits.Count) by admin or break-glass account(s): $(($AdminHits | ForEach-Object userPrincipalName | Select-Object -Unique) -join ', ')." 'Find out why those admins fail the policy (missing method, unmanaged device) and fix it, or exclude them, before enabling.'
        } elseif ($Blocked.Failures -gt 0) {
            & $Add 'WouldBeBlocked' 'Would-be-blocked sign-ins' 'Warn' "$($Blocked.Failures) sign-in(s) by $($Blocked.Users)+ user(s) $Window would have been blocked once this is enforced (plus $($Blocked.Interrupted) that would be prompted). Review them below." 'Confirm each would-be-blocked sign-in is one you intend to block.'
        } else {
            & $Add 'WouldBeBlocked' 'Would-be-blocked sign-ins' 'Pass' "No sign-in $Window would have been blocked ($($Blocked.Total) evaluated, $($Blocked.Interrupted) would be prompted)." ''
        }
    }

    $Fails = @($Checks | Where-Object Status -EQ 'Fail')
    [pscustomobject]@{
        Passed         = $Fails.Count -eq 0
        Status         = if ($Fails) { 'Fail' } elseif ($Checks | Where-Object Status -EQ 'Warn') { 'Warn' } else { 'Pass' }
        PolicyName     = $PolicyName
        Checks         = @($Checks)
        WhatIf         = $WhatIf
        ReportOnly     = [pscustomobject]$Soak
        WouldBeBlocked = [pscustomobject]$Blocked
    }
}
