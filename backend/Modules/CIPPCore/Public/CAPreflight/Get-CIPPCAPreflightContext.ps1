function Get-CIPPCAPreflightContext {
    <#
    .SYNOPSIS
        Collects from Graph everything Test-CIPPCAPreflight needs for one policy in one tenant.
    .DESCRIPTION
        Read-only. Returns a hashtable that splats straight into Test-CIPPCAPreflight, plus Errors.
        Every read that needs a licence the tenant may not have degrades to "unknown" (a Warn), never to a
        false Pass:
          userRegistrationDetails (Entra ID P1)  -> falls back to /users/{id}/authentication/methods
          directoryAudits (7 days free, 30 P1)   -> used only when modifiedDateTime cannot prove the soak
          sign-in logs (P1)                      -> report-only results via Get-CIPPCAPolicyImpact
        Global Administrators are active role assignments (users, and users of role-assignable groups), capped
        at 25; PIM-eligible-only admins are not counted, since activating needs the controls being changed.
        Aspendora fork addition (Vikunja CIPP-5).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantFilter,
        # Policy as it would be written: ids resolved.
        [Parameter(Mandatory)]$Policy,
        # Policy as it is in the tenant now, or $null for a new policy.
        $ExistingPolicy,
        # Request headers, to identify the executing admin. $null for scheduled (standards) runs.
        $Headers,
        [int]$RequiredDays = 7,
        # Skip the sign-in log read (the expensive part). Used by the standards path.
        [switch]$SkipSignIns,
        [int]$MaxGlobalAdmins = 25
    )

    $GA = '62e90394-69f5-4237-9190-012177145e10'
    $ReportOnly = 'enabledForReportingButNotEnforced'
    $Graph = 'https://graph.microsoft.com'
    $Now = (Get-Date).ToUniversalTime()
    $Errors = [System.Collections.Generic.List[string]]::new()
    $Get = { param($Uri) New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -ErrorAction Stop }
    $ErrText = { param($E) (Get-CippException -Exception $E).NormalizedError }

    # Work on a copy, so resolving the authentication strength never touches the caller's object.
    $Policy = ConvertTo-Json -InputObject $Policy -Depth 20 | ConvertFrom-Json
    $Strength = $Policy.grantControls.authenticationStrength
    if ($Strength.id -and -not $Strength.allowedCombinations) {
        try {
            $S = & $Get "$Graph/beta/identity/conditionalAccess/authenticationStrength/policies/$($Strength.id)"
            $Strength | Add-Member -NotePropertyName allowedCombinations -NotePropertyValue @($S.allowedCombinations) -Force
            $Strength | Add-Member -NotePropertyName displayName -NotePropertyValue $S.displayName -Force
        } catch { $Errors.Add("Authentication strength $($Strength.id): $(& $ErrText $_)") }
    }

    # Registered methods for admins in one read (P1); per-user fallback below.
    $Registered = @{}
    try {
        foreach ($R in @(& $Get "$Graph/beta/reports/authenticationMethods/userRegistrationDetails?`$filter=isAdmin eq true")) { $Registered[[string]$R.id] = @($R.methodsRegistered) }
    } catch { $Errors.Add("Authentication method registration report (needs Entra ID P1), using per-user methods instead: $(& $ErrText $_)") }
    $MethodsFor = {
        param($Id)
        if ($Registered.ContainsKey($Id)) { return , $Registered[$Id] }
        try { return , @(& $Get "$Graph/v1.0/users/$Id/authentication/methods" | ForEach-Object { $_.'@odata.type' }) } catch { $Errors.Add("Authentication methods for $($Id): $(& $ErrText $_)"); return $null }
    }
    $LoadUser = {
        param($Id, $Upn)
        $P = [ordered]@{ Id = [string]$Id; UserPrincipalName = $Upn; Exists = $true; MembershipKnown = $false; GroupIds = @(); RoleTemplateIds = @(); Methods = $null; IsExternal = $false }
        try {
            $Member = @(& $Get "$Graph/v1.0/users/$Id/transitiveMemberOf?`$select=id,roleTemplateId")
            $P.GroupIds = @($Member | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' } | ForEach-Object { [string]$_.id })
            $P.RoleTemplateIds = @($Member | Where-Object roleTemplateId | ForEach-Object { [string]$_.roleTemplateId })
            $P.MembershipKnown = $true
        } catch {
            $E = & $ErrText $_
            if ($E -match 'Request_ResourceNotFound|does not exist') { $P.Exists = $false } else { $Errors.Add("Group membership of $($Upn ?? $Id): $E") }
        }
        if ($P.Exists) { $P.Methods = & $MethodsFor ([string]$Id) }
        $P
    }

    # Global Administrators (active).
    $GaUsers = [ordered]@{}
    $GlobalAdminsKnown = $true
    try {
        # No $expand=principal: one assignment whose principal was deleted makes Graph reject the whole query
        # ("Resource ... does not exist"), seen in 3endt.com. Resolve principals with getByIds, which skips missing ids.
        $GaAssignments = @(& $Get "$Graph/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$GA'&`$select=id,principalId,directoryScopeId" | Where-Object { -not $_.directoryScopeId -or $_.directoryScopeId -eq '/' })
        $GaPrincipalIds = @($GaAssignments.principalId | Where-Object { $_ } | Sort-Object -Unique)
        $GaPrincipals = @()
        if ($GaPrincipalIds.Count -gt 0) {
            $Body = ConvertTo-Json -InputObject @{ ids = $GaPrincipalIds } -Compress
            $GaPrincipals = @((New-GraphPOSTRequest -tenantid $TenantFilter -uri "$Graph/v1.0/directoryObjects/getByIds?`$select=id,userPrincipalName,displayName" -body $Body -ErrorAction Stop).value)
        }
        foreach ($A in @($GaPrincipals | ForEach-Object { [pscustomobject]@{ principal = $_ } })) {
            switch ($A.principal.'@odata.type') {
                '#microsoft.graph.user' { $GaUsers[[string]$A.principal.id] = $A.principal.userPrincipalName }
                '#microsoft.graph.group' {
                    foreach ($M in @(& $Get "$Graph/v1.0/groups/$($A.principal.id)/transitiveMembers/microsoft.graph.user?`$select=id,userPrincipalName")) { $GaUsers[[string]$M.id] = $M.userPrincipalName }
                }
            }
        }
    } catch { $GlobalAdminsKnown = $false; $Errors.Add("Global Administrator role members: $(& $ErrText $_)") }

    # Break-glass registry (Vikunja CIPP-3).
    $BgIds = @{}
    $BreakGlass = @(foreach ($Row in @(Get-CIPPBreakGlassAccounts -TenantFilter $TenantFilter)) {
            $P = & $LoadUser ([string]$Row.RowKey) ([string]$Row.UserPrincipalName)
            if ($GaUsers.Contains($P.Id) -and $GA -notin $P.RoleTemplateIds) { $P.RoleTemplateIds += $GA }
            $BgIds[$P.Id] = $true
            [pscustomobject]$P
        })

    if ($GaUsers.Count -gt $MaxGlobalAdmins) { $Errors.Add("Only the first $MaxGlobalAdmins of $($GaUsers.Count) Global Administrators were evaluated.") }
    $GlobalAdmins = @(foreach ($Id in @($GaUsers.Keys | Select-Object -First $MaxGlobalAdmins)) {
            $P = & $LoadUser $Id $GaUsers[$Id]
            if ($GA -notin $P.RoleTemplateIds) { $P.RoleTemplateIds += $GA }
            $P.IsBreakGlass = $BgIds.ContainsKey($Id)
            [pscustomobject]$P
        })

    # Executing admin: the CIPP user. In a customer tenant that is normally a GDAP service-provider user
    # (CIPP itself calls Graph as the partner's GDAP account, which the same evaluation covers).
    $Executor = $null
    $Actor = try { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Headers.'x-ms-client-principal')) | ConvertFrom-Json).userDetails } catch { $null }
    if ($Actor) {
        $InTenant = try { & $Get "$Graph/v1.0/users/$([System.Uri]::EscapeDataString($Actor))?`$select=id,userPrincipalName,userType" } catch { $null }
        if ($InTenant.id) {
            $P = & $LoadUser ([string]$InTenant.id) $InTenant.userPrincipalName
            if ($GaUsers.Contains($P.Id) -and $GA -notin $P.RoleTemplateIds) { $P.RoleTemplateIds += $GA }
            if ($InTenant.userType -eq 'Guest') { $P.IsExternal = $true; $P.ExternalUserType = 'b2bCollaborationGuest' }
            $Executor = [pscustomobject]$P
        } else {
            $Executor = [pscustomobject]@{ Id = $null; UserPrincipalName = $Actor; Exists = $true; MembershipKnown = $true; GroupIds = @(); RoleTemplateIds = @(); Methods = $null; IsExternal = $true; ExternalUserType = 'serviceProvider'; HomeTenantId = $env:TenantID }
        }
    }

    # Report-only soak evidence: only needed when modifiedDateTime is too recent to prove it on its own.
    $AuditEvents = @(); $AuditKnown = $false; $AuditError = $null
    if ($ExistingPolicy.state -eq $ReportOnly) {
        $Last = try { ([datetimeoffset]($ExistingPolicy.modifiedDateTime ?? $ExistingPolicy.createdDateTime)).UtcDateTime } catch { $null }
        if (-not $Last -or $Last -gt $Now.AddDays(-$RequiredDays)) {
            try {
                $From = $Now.AddDays(-30).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
                $Raw = @(& $Get "$Graph/v1.0/auditLogs/directoryAudits?`$filter=activityDateTime ge $From and targetResources/any(t:t/id eq '$($ExistingPolicy.id)')")
                $AuditEvents = @(foreach ($E in $Raw) {
                        if ($E.activityDisplayName -notmatch 'conditional access policy') { continue }
                        $Prop = @(@($E.targetResources | Where-Object id -EQ $ExistingPolicy.id).modifiedProperties | Where-Object displayName -EQ 'ConditionalAccessPolicy') | Select-Object -First 1
                        $Old = try { if ($Prop.oldValue) { ($Prop.oldValue | ConvertFrom-Json -Depth 30).state } } catch { $null }
                        $New = try { if ($Prop.newValue) { ($Prop.newValue | ConvertFrom-Json -Depth 30).state } } catch { $null }
                        [pscustomobject]@{ ActivityDateTime = $E.activityDateTime; Activity = $E.activityDisplayName; OldState = $Old; NewState = $New; InitiatedBy = $E.initiatedBy.user.userPrincipalName ?? $E.initiatedBy.app.displayName }
                    })
                $AuditKnown = $true
            } catch { $AuditError = & $ErrText $_; $Errors.Add("Directory audit log: $AuditError") }
        }
    }

    # Report-only results: would-be-blocked sign-ins in the soak window.
    $SignIns = [pscustomobject]@{ Collected = $false; Known = $false; Error = $null; WindowDays = $null; Totals = $null; Samples = @(); Partial = $false }
    if (-not $SkipSignIns -and $ExistingPolicy.state -eq $ReportOnly -and $ExistingPolicy.id) {
        $SignIns.Collected = $true
        $SignIns.WindowDays = if ($RequiredDays -le 1) { 1 } elseif ($RequiredDays -le 7) { 7 } else { 30 }
        try {
            $Impact = Get-CIPPCAPolicyImpact -TenantFilter $TenantFilter -PolicyId $ExistingPolicy.id -Days $SignIns.WindowDays
            $SignIns.Known = $true
            $SignIns.Totals = $Impact.totals
            $SignIns.Samples = @($Impact.samples)
            $SignIns.Partial = [bool]$Impact.partial
        } catch { $SignIns.Error = & $ErrText $_; $Errors.Add("Sign-in logs: $($SignIns.Error)") }
    }

    @{
        Policy             = $Policy
        ExistingPolicy     = $ExistingPolicy
        BreakGlassAccounts = $BreakGlass
        GlobalAdmins       = $GlobalAdmins
        GlobalAdminsKnown  = $GlobalAdminsKnown
        Executor           = $Executor
        AuditEvents        = $AuditEvents
        AuditKnown         = $AuditKnown
        AuditError         = $AuditError
        SignIns            = $SignIns
        RequiredDays       = $RequiredDays
        Errors             = @($Errors)
    }
}
