function Test-CIPPEntraEntitlement {
    <#
    .SYNOPSIS
        Compares a tenant's Entra ID P1/P2 licence pools with the users its Conditional Access policies cover.
    .DESCRIPTION
        Pure: no Graph calls. Licensing rules, from Microsoft Learn (read 2026-11-02): Conditional Access needs
        Entra ID P1 and risk-based policies (sign-in risk, user risk) need Entra ID P2, which is ID Protection. Guests
        are billed on monthly active users, so they are reported and never counted against the pools.

        Pools are counted by service plan, not SKU name: AAD_PREMIUM (any SKU carrying it, such as Business Premium)
        and AAD_PREMIUM_P2. A P2 plan also entitles P1. Only prepaidUnits.enabled counts, so a suspended trial adds
        nothing, and a seat holder of two SKUs counts twice, so the pools are the most generous reading.

        Scope comes from Test-CIPPCAPolicyUserScope, so it means "in scope for at least some sign-ins": apps,
        locations and platforms are not considered. Report-only policies do not count towards the shortfall. They are
        shown separately as what enabling them would need.

        Severity: a pool smaller than the users in scope of enforced policies is a Warning. Users in scope with no plan
        assigned are Info: true-up evidence, not a failure. Shared and resource mailbox accounts are left out of the
        counts and reported, because they are not people, though an enabled one can still sign in.

        Report only. Aspendora fork addition (Vikunja CIPP-47), written from Microsoft's documentation.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        # v1.0 subscribedSkus rows.
        [object[]]$Skus = @(),
        # v1.0 users rows (id, displayName, userPrincipalName, accountEnabled, userType, assignedPlans).
        [object[]]$Users = @(),
        # Conditional Access policies in Graph shape.
        [object[]]$Policies = @(),
        # Group id -> transitive member user ids, for groups the policies reference.
        [hashtable]$GroupMembers = @{},
        # Role template id -> user ids holding the role, active or PIM-eligible.
        [hashtable]$RoleMembers = @{},
        # Object ids of shared, room and equipment mailbox accounts.
        [string[]]$NonPersonIds = @(),
        # Accounts named per aggregate finding before "and N more".
        [int]$ListLimit = 25
    )

    $P1Plan = '41781fb2-bc02-4b7c-bd55-b576c07bb09d'
    $P2Plan = 'eec0eb4f-6444-4f95-aba0-50c24d67f998'

    # --- Licence pools ---
    $SkuRows = [System.Collections.Generic.List[object]]::new()
    $P1Pool = 0
    $P2Pool = 0
    foreach ($Sku in @($Skus)) {
        if ($Sku.appliesTo -and [string]$Sku.appliesTo -ne 'User') { continue }
        $Plans = @($Sku.servicePlans | Where-Object { [string]$_.servicePlanId -in @($P1Plan, $P2Plan) })
        if ($Plans.Count -eq 0) { continue }
        $Live = @($Plans | Where-Object { [string]$_.provisioningStatus -ne 'Disabled' })
        $Enabled = [int]($Sku.prepaidUnits.enabled ?? 0)
        $CarriesP2 = @($Live | Where-Object { [string]$_.servicePlanId -eq $P2Plan }).Count -gt 0
        if ($Live.Count -gt 0) { $P1Pool += $Enabled }
        if ($CarriesP2) { $P2Pool += $Enabled }
        $SkuRows.Add([pscustomobject]@{
                Sku       = [string]$Sku.skuPartNumber
                Status    = [string]$Sku.capabilityStatus
                Enabled   = $Enabled
                Suspended = [int]($Sku.prepaidUnits.suspended ?? 0)
                Warning   = [int]($Sku.prepaidUnits.warning ?? 0)
                Consumed  = [int]($Sku.consumedUnits ?? 0)
                Plans     = (@($Plans | ForEach-Object { if ([string]$_.servicePlanId -eq $P2Plan) { 'P2' } else { 'P1' } }) | Sort-Object -Unique) -join ', '
            })
    }

    # --- Policies by tier ---
    $IsRisk = { param($P) @($P.conditions.signInRiskLevels).Where({ $_ }).Count -gt 0 -or @($P.conditions.userRiskLevels).Where({ $_ }).Count -gt 0 }
    $Enforced = @($Policies | Where-Object { [string]$_.state -eq 'enabled' })
    $ReportOnly = @($Policies | Where-Object { [string]$_.state -eq 'enabledForReportingButNotEnforced' })
    $EnforcedRisk = @($Enforced | Where-Object { & $IsRisk $_ })
    $ReportOnlyRisk = @($ReportOnly | Where-Object { & $IsRisk $_ })

    # --- Principal lookups: user id -> groups and roles the policies reference ---
    $GroupsByUser = @{}
    foreach ($GroupId in @($GroupMembers.Keys)) {
        foreach ($UserId in @($GroupMembers[$GroupId])) {
            $Key = ([string]$UserId).ToLowerInvariant()
            if (-not $GroupsByUser.ContainsKey($Key)) { $GroupsByUser[$Key] = [System.Collections.Generic.List[string]]::new() }
            $GroupsByUser[$Key].Add([string]$GroupId)
        }
    }
    $RolesByUser = @{}
    foreach ($RoleId in @($RoleMembers.Keys)) {
        foreach ($UserId in @($RoleMembers[$RoleId])) {
            $Key = ([string]$UserId).ToLowerInvariant()
            if (-not $RolesByUser.ContainsKey($Key)) { $RolesByUser[$Key] = [System.Collections.Generic.List[string]]::new() }
            $RolesByUser[$Key].Add([string]$RoleId)
        }
    }
    $NonPerson = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Id in @($NonPersonIds)) { if ($Id) { [void]$NonPerson.Add([string]$Id) } }

    $InScopeOfAny = {
        param($PolicyList, $Principal)
        foreach ($P in $PolicyList) {
            if ((Test-CIPPCAPolicyUserScope -Policy $P -Principal $Principal).InScope) { return $true }
        }
        return $false
    }

    # --- Per-user evaluation ---
    $Rows = [System.Collections.Generic.List[object]]::new()
    $EnabledMembers = 0
    $NonPersonExcluded = 0
    $GuestsEnabled = 0
    $GuestsInScope = 0
    foreach ($U in @($Users)) {
        if ($U.accountEnabled -ne $true) { continue }
        $Key = ([string]$U.id).ToLowerInvariant()
        $Principal = @{
            Id              = [string]$U.id
            GroupIds        = @($GroupsByUser[$Key])
            RoleTemplateIds = @($RolesByUser[$Key])
        }
        if ([string]$U.userType -eq 'Guest') {
            $GuestsEnabled++
            $Principal.IsExternal = $true
            $Principal.ExternalUserType = 'b2bCollaborationGuest'
            if (& $InScopeOfAny $Enforced $Principal) { $GuestsInScope++ }
            continue
        }
        if ($NonPerson.Contains([string]$U.id)) { $NonPersonExcluded++; continue }
        $EnabledMembers++

        $P1Scope = & $InScopeOfAny $Enforced $Principal
        $P2Scope = & $InScopeOfAny $EnforcedRisk $Principal
        $P1Planned = $P1Scope -or (& $InScopeOfAny $ReportOnly $Principal)
        $P2Planned = $P2Scope -or (& $InScopeOfAny $ReportOnlyRisk $Principal)
        if (-not $P1Planned) { continue }

        $Assigned = @($U.assignedPlans | Where-Object { [string]$_.capabilityStatus -in @('Enabled', 'Warning') } | ForEach-Object { [string]$_.servicePlanId })
        $HasP2 = $Assigned -contains $P2Plan
        $HasP1 = $HasP2 -or $Assigned -contains $P1Plan
        $Rows.Add([pscustomobject]@{
                Id                = [string]$U.id
                UserPrincipalName = [string]$U.userPrincipalName
                DisplayName       = [string]$U.displayName
                InP1Scope         = [bool]$P1Scope
                InP2Scope         = [bool]$P2Scope
                InReportOnlyScope = [bool]($P1Planned -and -not $P1Scope)
                HasP1Plan         = [bool]$HasP1
                HasP2Plan         = [bool]$HasP2
                P1Gap             = [bool]($P1Scope -and -not $HasP1)
                P2Gap             = [bool]($P2Scope -and -not $HasP2)
                PlannedP2         = [bool]$P2Planned
            })
    }

    $P1InScope = @($Rows | Where-Object InP1Scope).Count
    $P2InScope = @($Rows | Where-Object InP2Scope).Count
    $P1WithReportOnly = $Rows.Count
    $P2WithReportOnly = @($Rows | Where-Object PlannedP2).Count
    $P1Gaps = @($Rows | Where-Object P1Gap)
    $P2Gaps = @($Rows | Where-Object P2Gap)
    $P1Short = [math]::Max(0, $P1InScope - $P1Pool)
    $P2Short = [math]::Max(0, $P2InScope - $P2Pool)

    # --- Findings ---
    $Findings = [System.Collections.Generic.List[object]]::new()
    $Add = {
        param($Key, $Severity, $Check, $Message, $Fix)
        $Findings.Add([pscustomobject]@{ Key = $Key; Severity = $Severity; Check = $Check; Account = ''; Message = $Message; Fix = $Fix })
    }
    $Names = {
        param($List)
        $Shown = @($List | Select-Object -First $ListLimit | ForEach-Object { $_.UserPrincipalName })
        $More = @($List).Count - $Shown.Count
        ($Shown -join ', ') + $(if ($More -gt 0) { " and $More more" } else { '' })
    }
    $SuspendedP2 = @($SkuRows | Where-Object { $_.Plans -match 'P2' -and $_.Suspended -gt 0 } | ForEach-Object { $_.Sku })

    if ($P1Short -gt 0) {
        & $Add 'P1Shortfall' 'Warning' 'Entra ID P1 pool smaller than Conditional Access scope' "$P1InScope enabled member user(s) are in scope of $($Enforced.Count) enforced Conditional Access policies, but the tenant owns $P1Pool seat(s) carrying Entra ID P1: $P1Short short." 'Buy more seats carrying Entra ID P1, or narrow the policies. Check for accounts that do not need to be enabled.'
    }
    if ($P2Short -gt 0) {
        $Why = if ($SuspendedP2.Count -gt 0) { " Suspended SKU(s) carrying P2, which add no seats: $($SuspendedP2 -join ', ')." } else { '' }
        & $Add 'P2Shortfall' 'Warning' 'Entra ID P2 pool smaller than risk-based policy scope' "$P2InScope enabled member user(s) are in scope of $($EnforcedRisk.Count) enforced risk-based Conditional Access policies ($(@($EnforcedRisk | ForEach-Object { $_.displayName }) -join ', ')), but the tenant owns $P2Pool seat(s) carrying Entra ID P2: $P2Short short.$Why" 'Buy seats carrying Entra ID P2, or remove the risk conditions from these policies.'
    }
    if ($P1Gaps.Count -gt 0) {
        & $Add 'P1UserGaps' 'Info' 'In scope of Conditional Access with no P1 plan assigned' "True-up evidence: $($P1Gaps.Count) user(s): $(& $Names $P1Gaps)." 'Assign a licence carrying Entra ID P1 where the account is a person. Service accounts need a decision.'
    }
    if ($P2Gaps.Count -gt 0) {
        & $Add 'P2UserGaps' 'Info' 'In scope of risk-based policies with no P2 plan assigned' "True-up evidence: $($P2Gaps.Count) user(s): $(& $Names $P2Gaps)." 'Assign a licence carrying Entra ID P2, or narrow the policy to users who hold one.'
    }
    if ($P1WithReportOnly -gt $P1Pool -and $P1Short -eq 0) {
        & $Add 'P1ReportOnlyShortfall' 'Info' 'Enabling report-only policies would exceed the P1 pool' "$P1WithReportOnly user(s) would be in scope if every report-only policy were enabled; the tenant owns $P1Pool P1 seat(s)." 'Plan the licences before enforcing those policies.'
    }
    if ($P2WithReportOnly -gt $P2Pool -and $P2Short -eq 0) {
        & $Add 'P2ReportOnlyShortfall' 'Info' 'Enabling report-only risk policies would exceed the P2 pool' "$P2WithReportOnly user(s) would be in scope if every report-only risk policy were enabled; the tenant owns $P2Pool P2 seat(s)." 'Plan the licences before enforcing those policies.'
    }
    if ($GuestsInScope -gt 0) {
        & $Add 'GuestsInScope' 'Info' 'Guests in scope (not counted against the pools)' "$GuestsInScope enabled guest(s) are in scope of enforced policies. Guests are billed on monthly active users." 'No seat needed. Check that the tenant is linked to an Azure subscription if guests use premium features beyond the free tier.'
    }
    if ($NonPersonExcluded -gt 0) {
        & $Add 'NonPersonAccountsExcluded' 'Info' 'Shared and resource mailbox accounts left out of the counts' "$NonPersonExcluded enabled shared, room or equipment mailbox account(s) were not counted." 'Block sign-in on these accounts if nothing signs in with them.'
    }

    $Order = @{ Warning = 0; Info = 1 }
    [pscustomobject]@{
        Summary  = [pscustomobject]@{
            CoveredP1             = $P1Short -eq 0
            CoveredP2             = $P2Short -eq 0
            P1Pool                = $P1Pool
            P2Pool                = $P2Pool
            P1InScope             = $P1InScope
            P2InScope             = $P2InScope
            P1Shortfall           = $P1Short
            P2Shortfall           = $P2Short
            P1UserGaps            = $P1Gaps.Count
            P2UserGaps            = $P2Gaps.Count
            P1InScopeWithReportOnly = $P1WithReportOnly
            P2InScopeWithReportOnly = $P2WithReportOnly
            EnforcedPolicies      = $Enforced.Count
            EnforcedRiskPolicies  = $EnforcedRisk.Count
            ReportOnlyPolicies    = $ReportOnly.Count
            ReportOnlyRiskPolicies = $ReportOnlyRisk.Count
            EnabledMembers        = $EnabledMembers
            NonPersonExcluded     = $NonPersonExcluded
            GuestsEnabled         = $GuestsEnabled
            GuestsInScope         = $GuestsInScope
        }
        Skus     = @($SkuRows)
        Users    = @($Rows)
        Findings = @($Findings | Sort-Object { $Order[$_.Severity] }, Check)
    }
}
