function Get-CIPPPhishResistantPosture {
    <#
    .SYNOPSIS
        Collects a tenant's privileged role holders, their MFA methods and the authentication methods policy, and
        evaluates them with Test-CIPPPhishResistantPosture.
    .DESCRIPTION
        Read only. Licence-dependent reads degrade instead of producing false findings: the registration report
        (Entra ID P1) falls back to reading each admin's methods; PIM eligibility (P2) is reported as unknown.
        Returns @{ Tenant; Summary; Admins; Findings; Errors }. Errors lists reads that should have worked and did not,
        so a caller can tell "could not check" from "clear". Aspendora fork addition (Vikunja CIPP-7).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TenantFilter)

    # Same list as Test-CIPPPhishResistantPosture and docs/ca-templates/cipp7-phishres-admins.json.
    $Privileged = @(
        '62e90394-69f5-4237-9190-012177145e10', 'e8611ab8-c189-46e8-94e1-60213ab1f814', '7be44c8a-adaf-4e2a-84d6-ab2649e08a13',
        '194ae4cb-b126-40b2-bd5b-6091b380977d', '29232cdf-9323-42fd-ade2-1d097af3e4de', 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c',
        'fe930be7-5e62-47db-91af-98c3a49a38b1', 'c4e39bd9-1100-46d3-8c65-fb160da0071f', 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9',
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', '158c047a-c907-4556-b7ef-446551a6b5f7', '3a2c62db-5318-420d-8d74-23affee5d9d5',
        '729827e3-9c14-49f7-bb1b-9608f156bbb8', 'b0f54661-2d74-4c50-afa3-1ec803f12efe'
    )
    $Errors = [System.Collections.Generic.List[string]]::new()
    $Graph = 'https://graph.microsoft.com'
    $UserSelect = 'id,userPrincipalName,displayName,mail,assignedLicenses,accountEnabled'
    $Get = {
        param($Uri)
        New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -ErrorAction Stop
    }
    $Err = { param($E) (Get-CippException -Exception $E).NormalizedError }

    # Registration report (P1). $null means unreadable; admins then get their methods read one by one.
    # Assigned inside try: an empty array returned from a try expression would collapse to $null.
    $Registrations = $null
    try {
        $Registrations = @(& $Get "$Graph/beta/reports/authenticationMethods/userRegistrationDetails?`$select=id,userPrincipalName,userType,methodsRegistered")
    } catch { $Registrations = $null }

    # Holders: userId -> @{ user fields; Roles list }
    $Holders = [ordered]@{}
    $Groups = @{}
    $AddHolder = {
        param($Principal, $RoleTemplateId, $Kind, $Via)
        $Id = [string]$Principal.id
        if (-not $Holders.Contains($Id)) {
            $Holders[$Id] = [ordered]@{ Id = $Id; UserPrincipalName = $Principal.userPrincipalName; DisplayName = $Principal.displayName; Mail = $Principal.mail
                AccountEnabled = $Principal.accountEnabled; SkuIds = @($Principal.assignedLicenses | Where-Object { $_ } | ForEach-Object { [string]$_.skuId }); HasDetails = ($null -ne $Principal.assignedLicenses)
                Roles = [System.Collections.Generic.List[object]]::new() }
        }
        $Holders[$Id].Roles.Add([pscustomobject]@{ RoleTemplateId = $RoleTemplateId; Kind = $Kind; Via = $Via })
    }
    $AddPrincipal = {
        param($Row, $Kind)
        $P = $Row.principal
        if (-not $P) { return }
        switch ([string]$P.'@odata.type') {
            '#microsoft.graph.user' { & $AddHolder $P $Row.roleDefinitionId $Kind 'Direct' }
            '#microsoft.graph.group' {
                $GroupId = [string]$P.id
                if (-not $Groups.ContainsKey($GroupId)) {
                    $Groups[$GroupId] = try { @(& $Get "$Graph/v1.0/groups/$GroupId/transitiveMembers/microsoft.graph.user?`$select=$UserSelect") }
                    catch { $Errors.Add("Members of role group $($P.displayName): $(& $Err $_)"); @() }
                }
                foreach ($U in $Groups[$GroupId]) { & $AddHolder $U $Row.roleDefinitionId $Kind "Group: $($P.displayName)" }
            }
            default { } # service principals: not people, no MFA
        }
    }

    try {
        $Assignments = @(& $Get "$Graph/v1.0/roleManagement/directory/roleAssignments?`$expand=principal(`$select=$UserSelect)")
        foreach ($Row in @($Assignments | Where-Object { $_.roleDefinitionId -in $Privileged })) { & $AddPrincipal $Row 'Active' }
    } catch { $Errors.Add("Active role assignments: $(& $Err $_)") }

    $EligibleKnown = $true
    try {
        $Eligible = @(& $Get "$Graph/v1.0/roleManagement/directory/roleEligibilitySchedules?`$expand=principal")
        foreach ($Row in @($Eligible | Where-Object { $_.roleDefinitionId -in $Privileged })) { & $AddPrincipal $Row 'Eligible' }
    } catch {
        $EligibleKnown = $false
        $Msg = & $Err $_
        # No P2/Governance licence is expected and degrades to "unknown"; anything else is a real read failure.
        if ($Msg -notmatch 'P2|Governance|licen[cs]e|AadPremium') { $Errors.Add("PIM eligible assignments: $Msg") }
    }

    # Eligible principals come without licence data; fill in user details where missing.
    foreach ($H in @($Holders.Values | Where-Object { -not $_.HasDetails })) {
        try {
            $U = & $Get "$Graph/v1.0/users/$($H.Id)?`$select=$UserSelect"
            $H.UserPrincipalName = $U.userPrincipalName; $H.DisplayName = $U.displayName; $H.Mail = $U.mail
            $H.AccountEnabled = $U.accountEnabled; $H.SkuIds = @($U.assignedLicenses | Where-Object { $_ } | ForEach-Object { [string]$_.skuId }); $H.HasDetails = $true
        } catch { $Errors.Add("User $($H.UserPrincipalName ?? $H.Id): $(& $Err $_)") }
    }

    # Methods: registration report row if there is one, otherwise read the user's methods (no licence needed).
    $RegIds = @{}
    foreach ($R in @($Registrations)) { if ($R.id) { $RegIds[[string]$R.id] = $true } }
    foreach ($H in $Holders.Values) {
        if ($RegIds.ContainsKey($H.Id)) { continue }
        $H.Methods = $null
        try { $H.Methods = @(& $Get "$Graph/v1.0/users/$($H.Id)/authentication/methods" | ForEach-Object { $_.'@odata.type' } | Where-Object { $_ -ne '#microsoft.graph.passwordAuthenticationMethod' }) } catch { $H.Methods = $null }
    }

    $BreakGlassIds = try { @(Get-CIPPBreakGlassAccounts -TenantFilter $TenantFilter | ForEach-Object { [string]$_.RowKey }) } catch { $Errors.Add("Break-glass registry: $(& $Err $_)"); @() }

    $Policy = try { & $Get "$Graph/beta/policies/authenticationMethodsPolicy" } catch { $Errors.Add("Authentication methods policy: $(& $Err $_)"); $null }

    $Params = @{
        Holders       = @($Holders.Values | ForEach-Object { [pscustomobject]$_ })
        BreakGlassIds = $BreakGlassIds
        Policy        = $Policy
        EligibleKnown = $EligibleKnown
    }
    if ($null -ne $Registrations) { $Params.Registrations = $Registrations }
    $Result = Test-CIPPPhishResistantPosture @Params

    [pscustomobject]@{
        Tenant   = $TenantFilter
        Summary  = $Result.Summary
        Admins   = $Result.Admins
        Findings = $Result.Findings
        Errors   = @($Errors)
    }
}
