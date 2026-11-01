function Test-CIPPRoleAssignmentReport {
    <#
    .SYNOPSIS
        Evaluates a tenant's directory role assignments for standing and excess privilege, from already-collected data.
    .DESCRIPTION
        Pure rules, no Graph or table calls; Get-CIPPRoleAssignmentReport collects the inputs. Returns
        @{ Summary; Assignments; Recommendations; Findings }. Each finding has a stable Key (one per principal or per
        GDAP relationship), so the weekly StandingPrivilegedAccess alert notifies once per problem.

          StandingGA|<id>          permanent active Global Administrator that is not a registered break-glass
                                   account, with a least-privilege recommendation from its recent Entra audit
                                   activity (Warning)
          SpGlobalAdmin|<id>       a non-Microsoft service principal holding Global Administrator (Error; Info
                                   when allow-listed)
          SpPrivilegedRole|<id>    a non-Microsoft service principal holding another privileged role (Warning;
                                   Info when allow-listed or the roles are not privileged)
          GuestRole|<id>           a guest holding a directory role (Warning if privileged, otherwise Info)
          InactivePrivileged|<id>  enabled user with a privileged role (active or eligible) and no successful
                                   sign-in for InactiveDays (Warning). Break-glass accounts are left to the
                                   break-glass posture check.
          DisabledPrivileged|<id>  disabled user still holding an active role (Info)
          GdapGlobalAdmin|<relId>  active GDAP relationship that carries Global Administrator (Warning)
          PimUnavailable / SignInUnknown / ActivityUnknown / GdapUnknown  (Info) data that could not be read

        "Privileged" = Microsoft's isPrivileged flag on the role definition, plus Exchange, SharePoint, Teams,
        Intune, Helpdesk and Billing Administrator (as in the CIPP-7 phishing-resistant check).
        Microsoft first-party service principals (Office 365 Portal, Rights Management...) hold internal roles by
        design and are listed but never flagged. Report only. Aspendora fork addition (Vikunja CIPP-15).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        # beta roleDefinitions rows (id, displayName, isBuiltIn, isPrivileged).
        [object[]]$RoleDefinitions = @(),
        # Normalised assignment rows, one per principal x role x kind:
        #   @{ PrincipalId; PrincipalType = 'user'|'servicePrincipal'|...; PrincipalName; UserPrincipalName; UserType;
        #      AccountEnabled; AppId; AppOwnerOrganizationId; RoleDefinitionId; Kind = 'Active'|'Eligible';
        #      Permanent = $true|$false|$null; EndDateTime; Via = 'Direct'|'Group: <name>' }
        [object[]]$Assignments = @(),
        # $false when PIM schedules could not be read (no Entra ID P2): every active assignment is then standing
        # as far as anyone can tell, and eligible assignments are not seen.
        [bool]$PimKnown = $true,
        # user id -> last successful sign-in ([datetime] or $null for never). Ignored when SignInKnown is $false.
        [hashtable]$SignIns = @{},
        [bool]$SignInKnown = $true,
        # user id -> directoryAudits rows initiated by the user (activityDisplayName, loggedByService, category).
        # A missing key means unknown.
        [hashtable]$AdminActivity = @{},
        [int]$ActivityDays = 30,
        [string[]]$BreakGlassIds = @(),
        # Parsed Config/LeastPrivilegeRoles.json.
        $LeastPrivilege,
        # @{ Id; DisplayName; Status; EndDateTime; Roles = role ids; Assignments = @(@{ Id; Group; Roles; Status }) }
        [object[]]$GdapRelationships = @(),
        [bool]$GdapKnown = $true,
        # $false for the partner tenant itself or a direct tenant: GDAP does not apply.
        [bool]$GdapApplicable = $true,
        # appId or display-name patterns (-like) of service principals that are expected to hold roles.
        [string[]]$AllowedServicePrincipals = @(),
        [int]$InactiveDays = 45,
        [datetime]$Now = [datetime]::UtcNow
    )

    $GlobalAdmin = '62e90394-69f5-4237-9190-012177145e10'
    $MicrosoftOwners = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')
    $AlsoPrivileged = @(
        '29232cdf-9323-42fd-ade2-1d097af3e4de', 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', '69091246-20e8-4a56-aa4d-066075b2a7a8',
        '3a2c62db-5318-420d-8d74-23affee5d9d5', '729827e3-9c14-49f7-bb1b-9608f156bbb8', 'b0f54661-2d74-4c50-afa3-1ec803f12efe',
        '62e90394-69f5-4237-9190-012177145e10', 'e8611ab8-c189-46e8-94e1-60213ab1f814', '7be44c8a-adaf-4e2a-84d6-ab2649e08a13',
        '194ae4cb-b126-40b2-bd5b-6091b380977d', 'fe930be7-5e62-47db-91af-98c3a49a38b1', 'c4e39bd9-1100-46d3-8c65-fb160da0071f',
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', '158c047a-c907-4556-b7ef-446551a6b5f7'
    )

    $DefById = @{}
    foreach ($D in @($RoleDefinitions)) { if ($D.id) { $DefById[([string]$D.id).ToLower()] = $D } }
    $RoleName = { param($Id) $D = $DefById[([string]$Id).ToLower()]; if ($D) { [string]$D.displayName } else { "Role $Id" } }
    $IsPrivileged = { param($Id) $L = ([string]$Id).ToLower(); ($L -in $AlsoPrivileged) -or ($DefById[$L].isPrivileged -eq $true) }

    $Findings = [System.Collections.Generic.List[object]]::new()
    $Add = {
        param($Key, $Severity, $Check, $Account, $Message, $Fix)
        $Findings.Add([pscustomobject]@{ Key = $Key; Severity = $Severity; Check = $Check; Account = [string]$Account; Message = $Message; Fix = $Fix })
    }
    $Fmt = { param($D) if ($D) { ([datetime]$D).ToUniversalTime().ToString('yyyy-MM-dd') } else { '' } }
    $Allowed = {
        param($A)
        foreach ($P in @($AllowedServicePrincipals | Where-Object { $_ })) {
            $P = $P.Trim()
            if (([string]$A.AppId -like $P) -or ([string]$A.PrincipalName -like $P)) { return $true }
        }
        $false
    }

    # Least-privilege suggestion from a GA's recent Entra audit entries (first matching rule per entry).
    $Rules = @($LeastPrivilege.auditRules.rules)
    $Suggest = {
        param($Rows)
        $Roles = [System.Collections.Generic.List[string]]::new()
        $Unmapped = 0
        foreach ($R in @($Rows)) {
            $Hit = $null
            foreach ($Rule in $Rules) {
                if ($Rule.activity -and [string]$R.activityDisplayName -notmatch $Rule.activity) { continue }
                if ($Rule.service -and [string]$R.loggedByService -notmatch $Rule.service) { continue }
                if ($Rule.category -and [string]$R.category -notmatch $Rule.category) { continue }
                $Hit = $Rule; break
            }
            if (-not $Hit) { $Unmapped++; continue }
            if ($Hit.selfService -eq $true) { continue } # the admin's own SSPR/registration, not admin work
            if ($Hit.role -and -not $Roles.Contains([string]$Hit.role)) { $Roles.Add([string]$Hit.role) }
        }
        [pscustomobject]@{ Roles = @($Roles); Unmapped = $Unmapped; Count = @($Rows).Count }
    }

    # --- Assignment table ---
    $Table = foreach ($A in @($Assignments)) {
        $Id = [string]$A.PrincipalId
        $Last = if ($SignInKnown -and $SignIns.ContainsKey($Id)) { $SignIns[$Id] } else { $null }
        $Permanent = if ($A.Kind -eq 'Eligible') { 'Eligible' } elseif ($A.Permanent -eq $true) { 'Yes' } elseif ($A.Permanent -eq $false) { "No (ends $(& $Fmt $A.EndDateTime))" } else { 'Unknown (no PIM)' }
        [pscustomobject]@{
            Principal         = if ($A.UserPrincipalName) { $A.UserPrincipalName } else { $A.PrincipalName }
            DisplayName       = $A.PrincipalName
            PrincipalType     = $A.PrincipalType
            UserType          = $A.UserType
            Role              = & $RoleName $A.RoleDefinitionId
            Privileged        = [bool](& $IsPrivileged $A.RoleDefinitionId)
            Kind              = $A.Kind
            Permanent         = $Permanent
            Via               = $A.Via
            AccountEnabled    = $A.AccountEnabled -ne $false
            LastSignIn        = if ($A.PrincipalType -ne 'user') { '' } elseif (-not $SignInKnown) { 'Unknown' } elseif ($SignIns.ContainsKey($Id) -and $null -ne $Last) { & $Fmt $Last } elseif ($SignIns.ContainsKey($Id)) { 'Never' } else { 'Unknown' }
            BreakGlass        = $Id -in $BreakGlassIds
            MicrosoftService  = ([string]$A.AppOwnerOrganizationId).ToLower() -in $MicrosoftOwners
            PrincipalId       = $Id
            RoleDefinitionId  = [string]$A.RoleDefinitionId
        }
    }
    $Table = @($Table)

    # --- Per-principal findings ---
    $Recommendations = [System.Collections.Generic.List[object]]::new()
    foreach ($G in @($Table | Group-Object PrincipalId)) {
        $Id = [string]$G.Name
        $Rows = @($G.Group)
        $First = $Rows[0]
        $Label = $First.Principal
        $Active = @($Rows | Where-Object Kind -EQ 'Active')
        $Priv = @($Rows | Where-Object Privileged)
        $RoleList = (@($Rows | ForEach-Object { "$($_.Role)$(if ($_.Kind -eq 'Eligible') { ' (eligible)' })" } | Select-Object -Unique) -join ', ')

        if ($First.PrincipalType -eq 'servicePrincipal') {
            if ($First.MicrosoftService) { continue }
            $IsAllowed = & $Allowed ($Assignments | Where-Object { [string]$_.PrincipalId -eq $Id } | Select-Object -First 1)
            if (@($Rows | Where-Object { $_.RoleDefinitionId -eq $GlobalAdmin }).Count -gt 0) {
                & $Add "SpGlobalAdmin|$Id" ($IsAllowed ? 'Info' : 'Error') 'Service principal role' $Label "Service principal $Label holds Global Administrator ($RoleList). Anyone with its credentials owns the tenant, and app sign-ins are not covered by user MFA or most Conditional Access." 'Replace Global Administrator with the specific role the app documents (or Graph application permissions), or remove the app. If it is genuinely required, add it to the alert''s allow-list.'
            } elseif ($Priv.Count -gt 0) {
                & $Add "SpPrivilegedRole|$Id" ($IsAllowed ? 'Info' : 'Warning') 'Service principal role' $Label "Service principal $Label holds privileged directory role(s): $RoleList." 'Confirm the vendor still needs these roles and that the app is still in use; add expected apps (security tools, CIPP-SAM) to the alert''s allow-list.'
            } else {
                & $Add "SpPrivilegedRole|$Id" 'Info' 'Service principal role' $Label "Service principal $Label holds directory role(s): $RoleList." 'Confirm the app still needs them.'
            }
            continue
        }
        if ($First.PrincipalType -ne 'user') { continue }

        $IsGuest = $First.UserType -eq 'Guest' -or [string]$First.Principal -match '#EXT#'
        $Enabled = @($Rows | Where-Object { -not $_.AccountEnabled }).Count -eq 0
        $IsBreakGlass = $First.BreakGlass

        if (-not $Enabled) {
            if ($Active.Count -gt 0) {
                & $Add "DisabledPrivileged|$Id" 'Info' 'Disabled account with roles' $Label "Disabled account $Label still holds $RoleList." 'Remove the role assignments; a disabled account that is re-enabled gets them back.'
            }
            continue
        }

        if ($IsGuest) {
            & $Add "GuestRole|$Id" ($Priv.Count -gt 0 ? 'Warning' : 'Info') 'Guest with directory role' $Label "Guest $Label holds $RoleList. A guest's password, MFA and lifecycle are controlled by its home tenant, not this one." 'Use GDAP or a member admin account in this tenant instead; if the guest must stay, make the role PIM-eligible and require MFA from it with Conditional Access.'
        }

        # Inactive privileged accounts.
        if ($SignInKnown -and $Priv.Count -gt 0 -and -not $IsBreakGlass -and $SignIns.ContainsKey($Id)) {
            $Last = $SignIns[$Id]
            $Stale = ($null -eq $Last) -or (([datetime]$Last).ToUniversalTime() -lt $Now.AddDays(-$InactiveDays))
            if ($Stale) {
                $When = if ($null -eq $Last) { 'has never signed in successfully' } else { "last signed in successfully on $(& $Fmt $Last)" }
                & $Add "InactivePrivileged|$Id" 'Warning' 'Inactive privileged account' $Label "$Label $When but holds $(@($Priv | ForEach-Object { $_.Role } | Select-Object -Unique) -join ', ') (more than $InactiveDays days). An unused admin account is a credential nobody is watching." 'Remove the roles (or the account). If it is a service or emergency account, register it as break-glass or replace it with an app registration.'
            }
        }

        # Standing Global Admin.
        $StandingGa = @($Active | Where-Object { $_.RoleDefinitionId -eq $GlobalAdmin -and $_.Permanent -notlike 'No*' })
        if ($StandingGa.Count -gt 0 -and -not $IsBreakGlass) {
            $Evidence = ''
            $Suggested = @()
            if ($AdminActivity.ContainsKey($Id)) {
                $S = & $Suggest $AdminActivity[$Id]
                $Suggested = @($S.Roles)
                $Evidence = if ($S.Count -eq 0) {
                    "No Entra directory changes by this account in the last $ActivityDays days."
                } elseif ($Suggested -contains 'Global Administrator') {
                    "Some of its $($S.Count) Entra directory change(s) in the last $ActivityDays days need Global Administrator; the rest map to: $(@($Suggested | Where-Object { $_ -ne 'Global Administrator' }) -join ', ')."
                } elseif ($Suggested.Count -gt 0) {
                    "Its $($S.Count) Entra directory change(s) in the last $ActivityDays days could have been made with: $($Suggested -join ', ')$(if ($S.Unmapped) { " ($($S.Unmapped) not classified)" })."
                } else {
                    "Its $($S.Count) Entra directory change(s) in the last $ActivityDays days could not be classified."
                }
            } else { $Evidence = 'Its recent directory activity could not be read.' }
            $Pim = if ($PimKnown) { 'is a permanent active Global Administrator' } else { 'is an active Global Administrator, and without Entra ID P2 there is no PIM, so the assignment is standing' }
            $Fix = if ($PimKnown) {
                'Convert the assignment to PIM-eligible (activation with MFA and approval), or replace it with the smaller roles above. Exchange, Intune, SharePoint and Teams work is not in the Entra audit log: see the task lookup.'
            } else {
                'Replace it with the smaller roles above (Exchange, Intune, SharePoint and Teams work is not in the Entra audit log: see the task lookup), or license Entra ID P2 and make it PIM-eligible. Keep Global Administrator for the break-glass accounts.'
            }
            & $Add "StandingGA|$Id" 'Warning' 'Standing Global Administrator' $Label "$Label $Pim and is not a registered break-glass account. $Evidence" $Fix
            $Recommendations.Add([pscustomobject]@{
                    UserPrincipalName = $Label
                    CurrentRoles      = $RoleList
                    SuggestedRoles    = if ($Suggested.Count -gt 0) { ($Suggested -join ', ') } else { 'None from Entra activity: check the task lookup' }
                    Evidence          = $Evidence
                    PrincipalId       = $Id
                })
        }
    }

    # --- GDAP ---
    $GdapGa = @()
    if ($GdapApplicable -and $GdapKnown) {
        foreach ($Rel in @($GdapRelationships | Where-Object { $_.Status -eq 'active' })) {
            if ($GlobalAdmin -notin @($Rel.Roles)) { continue }
            $GdapGa += $Rel
            $Using = @($Rel.Assignments | Where-Object { $_.Status -ne 'deleted' -and $GlobalAdmin -in @($_.Roles) } | ForEach-Object { $_.Group })
            $UseText = if ($Using.Count) { "Access assignment(s) granting it: $($Using -join ', ')." } else { 'No access assignment uses it, so it only widens what could be granted.' }
            & $Add "GdapGlobalAdmin|$($Rel.Id)" 'Warning' 'GDAP Global Administrator' $Rel.DisplayName "GDAP relationship '$($Rel.DisplayName)' includes Global Administrator. $UseText A relationship with Global Administrator cannot auto-extend, and every technician in a granting group is a Global Admin of this customer." 'Create a relationship without Global Administrator (CIPP GDAP role templates), move the access assignments to least-privilege roles, then let this relationship lapse or terminate it.'
        }
    }

    # --- What could not be read ---
    if (-not $PimKnown) {
        & $Add 'PimUnavailable' 'Info' 'PIM' '' 'PIM schedules could not be read (the tenant has no Entra ID P2 or Governance licence). Every active assignment is treated as standing and PIM-eligible assignments are not seen.' 'Nothing to fix if the tenant does not use PIM. Entra ID P2 for the admin accounts enables just-in-time roles.'
    }
    if (-not $SignInKnown) {
        & $Add 'SignInUnknown' 'Info' 'Sign-in activity' '' 'Sign-in activity could not be read (it needs Entra ID P1 and AuditLog.Read.All), so inactive privileged accounts are not checked.' 'Nothing to fix; the other checks still apply.'
    }
    if ($GdapApplicable -and -not $GdapKnown) {
        & $Add 'GdapUnknown' 'Info' 'GDAP' '' 'The GDAP relationships for this customer could not be read from the partner tenant.' 'Check the GDAP health page.'
    }

    $Users = @($Table | Where-Object PrincipalType -EQ 'user')
    $Summary = [pscustomobject]@{
        ActiveAssignments                    = @($Table | Where-Object Kind -EQ 'Active').Count
        EligibleAssignments                  = @($Table | Where-Object Kind -EQ 'Eligible').Count
        PermanentActiveAssignments           = if ($PimKnown) { @($Table | Where-Object Permanent -EQ 'Yes').Count } else { $null }
        PrivilegedUsers                      = @($Users | Where-Object Privileged | Select-Object -ExpandProperty PrincipalId -Unique).Count
        StandingGlobalAdmins                 = @($Findings | Where-Object { $_.Key -like 'StandingGA|*' }).Count
        BreakGlassGlobalAdmins               = @($Users | Where-Object { $_.BreakGlass -and $_.RoleDefinitionId -eq $GlobalAdmin -and $_.Kind -eq 'Active' } | Select-Object -ExpandProperty PrincipalId -Unique).Count
        GuestsWithRoles                      = @($Findings | Where-Object { $_.Key -like 'GuestRole|*' }).Count
        ServicePrincipalsWithPrivilegedRoles = @($Findings | Where-Object { $_.Key -like 'Sp*' -and $_.Severity -ne 'Info' }).Count
        InactivePrivileged                   = @($Findings | Where-Object { $_.Key -like 'InactivePrivileged|*' }).Count
        GdapRelationshipsWithGlobalAdmin     = $GdapGa.Count
        PimAvailable                         = $PimKnown
        SignInActivityAvailable              = $SignInKnown
        GdapAvailable                        = if ($GdapApplicable) { $GdapKnown } else { $null }
    }

    $Order = @{ Error = 0; Warning = 1; Info = 2 }
    [pscustomobject]@{
        Summary         = $Summary
        Assignments     = @($Table | Sort-Object @{ e = { -not $_.Privileged } }, Role, Principal)
        Recommendations = @($Recommendations)
        Findings        = @($Findings | Sort-Object { $Order[$_.Severity] }, Check, Account)
    }
}
