function Get-CIPPRoleAssignmentReport {
    <#
    .SYNOPSIS
        Collects a tenant's directory role assignments (active, PIM-scheduled and PIM-eligible), the role holders'
        sign-in and audit activity and the customer's GDAP relationships, and evaluates them with
        Test-CIPPRoleAssignmentReport.
    .DESCRIPTION
        Read only. Reads, in the customer tenant:
          beta  roleManagement/directory/roleDefinitions
          v1.0  roleManagement/directory/roleAssignments?$expand=principal     (required; failure = Errors)
          v1.0  roleManagement/directory/roleAssignmentSchedules                 (Entra ID P2: permanent vs time-bound)
          v1.0  roleManagement/directory/roleEligibilitySchedules?$expand=principal (Entra ID P2)
          v1.0  groups/{id}/transitiveMembers/microsoft.graph.user               for role-assignable groups
          beta  users/{id}?$select=signInActivity (batched)                      (Entra ID P1; silently omitted
                                                                                  without it, seen live 2026-10-31)
          v1.0  auditLogs/directoryAudits initiated by each standing Global Admin, last ActivityDays days
        and in the partner tenant: the customer's GDAP relationships and, for those carrying Global Administrator,
        their access assignments.
        Licence-dependent reads degrade to "unknown" (AadPremiumLicenseRequired on non-P2 tenants) and are reported
        as Info findings, not Errors. Errors lists reads that should have worked and did not.
        Returns @{ Tenant; Summary; Assignments; Recommendations; Findings; Tasks; Errors }.
        Aspendora fork addition (Vikunja CIPP-15).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantFilter,
        [int]$InactiveDays = 45,
        [int]$ActivityDays = 30,
        [string[]]$AllowedServicePrincipals = @()
    )

    $Errors = [System.Collections.Generic.List[string]]::new()
    $Graph = 'https://graph.microsoft.com'
    $GlobalAdmin = '62e90394-69f5-4237-9190-012177145e10'
    $Now = [datetime]::UtcNow
    $Get = { param($Uri) New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -ErrorAction Stop }
    $Err = { param($E) (Get-CippException -Exception $E).NormalizedError }
    $IsLicenceError = { param($Msg) $Msg -match 'AadPremiumLicenseRequired|P2|Governance|licen[cs]e|premium' }
    $UserSelect = 'id,userPrincipalName,displayName,userType,accountEnabled'

    $Definitions = try { @(& $Get "$Graph/beta/roleManagement/directory/roleDefinitions?`$select=id,displayName,isBuiltIn,isPrivileged,templateId") } catch { $Errors.Add("Role definitions: $(& $Err $_)"); @() }

    # Normalised rows; group principals expand to one row per member user.
    $Rows = [System.Collections.Generic.List[object]]::new()
    $GroupMembers = @{}
    $AddRow = {
        param($Principal, $RoleId, $Kind, $Permanent, $End, $Via)
        $Type = ([string]$Principal.'@odata.type') -replace '^#microsoft\.graph\.', ''
        $Rows.Add([pscustomobject]@{
                PrincipalId            = [string]$Principal.id
                PrincipalType          = $Type
                PrincipalName          = $Principal.displayName
                UserPrincipalName      = $Principal.userPrincipalName
                UserType               = $Principal.userType
                AccountEnabled         = $Principal.accountEnabled
                AppId                  = $Principal.appId
                AppOwnerOrganizationId = $Principal.appOwnerOrganizationId
                RoleDefinitionId       = [string]$RoleId
                Kind                   = $Kind
                Permanent              = $Permanent
                EndDateTime            = $End
                Via                    = $Via
            })
    }
    $AddPrincipal = {
        param($Principal, $RoleId, $Kind, $Permanent, $End)
        if (-not $Principal) { return }
        if ([string]$Principal.'@odata.type' -eq '#microsoft.graph.group') {
            $GroupId = [string]$Principal.id
            if (-not $GroupMembers.ContainsKey($GroupId)) {
                $GroupMembers[$GroupId] = try { @(& $Get "$Graph/v1.0/groups/$GroupId/transitiveMembers/microsoft.graph.user?`$select=$UserSelect" | ForEach-Object { $_ | Add-Member -NotePropertyName '@odata.type' -NotePropertyValue '#microsoft.graph.user' -Force -PassThru }) }
                catch { $Errors.Add("Members of role group $($Principal.displayName): $(& $Err $_)"); @() }
            }
            foreach ($U in $GroupMembers[$GroupId]) { & $AddRow $U $RoleId $Kind $Permanent $End "Group: $($Principal.displayName)" }
        } else {
            & $AddRow $Principal $RoleId $Kind $Permanent $End 'Direct'
        }
    }

    # PIM schedules first, so each active assignment can be marked permanent or time-bound.
    $PimKnown = $true
    $Schedules = @{}
    try {
        foreach ($S in @(& $Get "$Graph/v1.0/roleManagement/directory/roleAssignmentSchedules")) {
            $Schedules["$($S.principalId)|$($S.roleDefinitionId)|$($S.directoryScopeId)".ToLower()] = $S
        }
    } catch {
        $PimKnown = $false
        $Msg = & $Err $_
        if (-not (& $IsLicenceError $Msg)) { $Errors.Add("PIM assignment schedules: $Msg") }
    }

    $AssignmentsRead = $false
    try {
        $Active = @(& $Get "$Graph/v1.0/roleManagement/directory/roleAssignments?`$expand=principal")
        $AssignmentsRead = $true
        foreach ($A in $Active) {
            $Permanent = $null; $End = $null
            if ($PimKnown) {
                $S = $Schedules["$($A.principalId)|$($A.roleDefinitionId)|$($A.directoryScopeId)".ToLower()]
                # No schedule for an active assignment = assigned outside PIM, i.e. standing.
                $Permanent = $true
                if ($S) {
                    $End = $S.scheduleInfo.expiration.endDateTime
                    $Permanent = ($S.assignmentType -ne 'Activated') -and ([string]$S.scheduleInfo.expiration.type -in @('', 'noExpiration'))
                }
            }
            & $AddPrincipal $A.principal $A.roleDefinitionId 'Active' $Permanent $End
        }
    } catch { $Errors.Add("Active role assignments: $(& $Err $_)") }

    if ($PimKnown) {
        try {
            foreach ($E in @(& $Get "$Graph/v1.0/roleManagement/directory/roleEligibilitySchedules?`$expand=principal")) {
                & $AddPrincipal $E.principal $E.roleDefinitionId 'Eligible' $null $E.scheduleInfo.expiration.endDateTime
            }
        } catch {
            $Msg = & $Err $_
            if (& $IsLicenceError $Msg) { $PimKnown = $false } else { $Errors.Add("PIM eligible assignments: $Msg") }
        }
    }

    # Sign-in activity for every user holding a role. The property is silently left out when the tenant lacks
    # Entra ID P1, so "no user came back with it" means unknown, not "never signed in".
    $UserIds = @($Rows | Where-Object PrincipalType -EQ 'user' | ForEach-Object PrincipalId | Select-Object -Unique)
    $SignIns = @{}
    $SignInKnown = $UserIds.Count -eq 0 # nothing to look up is not "unknown"
    if ($UserIds.Count -gt 0) {
        try {
            $Requests = @($UserIds | ForEach-Object { @{ id = $_; method = 'GET'; url = "users/$($_)?`$select=id,createdDateTime,signInActivity" } })
            $Responses = @(New-GraphBulkRequest -tenantid $TenantFilter -Requests $Requests)
            foreach ($R in $Responses) {
                if ([int]$R.status -ne 200 -or -not $R.body) { continue }
                if ($R.body.PSObject.Properties.Name -notcontains 'signInActivity') { continue }
                $SignInKnown = $true
                $SA = $R.body.signInActivity
                $Last = $SA.lastSuccessfulSignInDateTime
                if (-not $Last) {
                    # lastSuccessfulSignInDateTime only exists since late 2023; fall back to the other two.
                    $Last = @($SA.lastSignInDateTime, $SA.lastNonInteractiveSignInDateTime | Where-Object { $_ } | ForEach-Object { [datetime]$_ } | Sort-Object -Descending | Select-Object -First 1)[0]
                }
                $Created = if ($R.body.createdDateTime) { ([datetime]$R.body.createdDateTime).ToUniversalTime() } else { $null }
                # A brand-new account that has not signed in yet is not "inactive": leave it unknown.
                if (-not $Last -and $Created -and $Created -gt $Now.AddDays(-$InactiveDays)) { continue }
                $SignIns[[string]$R.id] = if ($Last) { [datetime]$Last } else { $null }
            }
        } catch { $Errors.Add("Sign-in activity: $(& $Err $_)") }
    }

    $BreakGlassIds = try { @(Get-CIPPBreakGlassAccounts -TenantFilter $TenantFilter | ForEach-Object { [string]$_.RowKey }) } catch { $Errors.Add("Break-glass registry: $(& $Err $_)"); @() }

    # Recent Entra directory changes by each standing Global Admin, for the least-privilege suggestion.
    $Activity = @{}
    $Cutoff = $Now.AddDays(-$ActivityDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $GaIds = @($Rows | Where-Object { $_.PrincipalType -eq 'user' -and $_.Kind -eq 'Active' -and $_.RoleDefinitionId -eq $GlobalAdmin -and $_.Permanent -ne $false -and $_.PrincipalId -notin $BreakGlassIds } | ForEach-Object PrincipalId | Select-Object -Unique)
    foreach ($Id in $GaIds) {
        try {
            $Activity[$Id] = @(New-GraphGetRequest -uri "$Graph/v1.0/auditLogs/directoryAudits?`$filter=initiatedBy/user/id eq '$Id' and activityDateTime ge $Cutoff&`$top=500" -tenantid $TenantFilter -noPagination $true -ErrorAction Stop |
                    Where-Object { $_.id } | Select-Object activityDisplayName, loggedByService, category)
        } catch { } # unknown: the finding says so
    }

    # GDAP relationships with this customer, read from the partner tenant.
    $Tenant = Get-Tenants -TenantFilter $TenantFilter | Select-Object -First 1
    $GdapApplicable = [bool]($Tenant.customerId) -and $Tenant.customerId -ne $env:TenantID -and $Tenant.delegatedPrivilegeStatus -ne 'directTenant'
    $GdapKnown = $true
    $Gdap = [System.Collections.Generic.List[object]]::new()
    if ($GdapApplicable) {
        try {
            $Rels = @(New-GraphGetRequest -uri "$Graph/beta/tenantRelationships/delegatedAdminRelationships?`$filter=customer/tenantId eq '$($Tenant.customerId)'" -tenantid $env:TenantID -NoAuthCheck $true -ErrorAction Stop)
            foreach ($Rel in $Rels) {
                $Roles = @($Rel.accessDetails.unifiedRoles.roleDefinitionId)
                $Assignments = @()
                if ($Rel.status -eq 'active' -and $GlobalAdmin -in $Roles) {
                    try {
                        $Assignments = @(New-GraphGetRequest -uri "$Graph/beta/tenantRelationships/delegatedAdminRelationships/$($Rel.id)/accessAssignments" -tenantid $env:TenantID -NoAuthCheck $true -ErrorAction Stop | ForEach-Object {
                                $GroupId = [string]$_.accessContainer.accessContainerId
                                $GroupName = try { (New-GraphGetRequest -uri "$Graph/v1.0/groups/$($GroupId)?`$select=displayName" -tenantid $env:TenantID -AsApp $true -NoAuthCheck $true -ErrorAction Stop).displayName } catch { $GroupId }
                                [pscustomobject]@{ Id = $_.id; Group = $GroupName; Roles = @($_.accessDetails.unifiedRoles.roleDefinitionId); Status = $_.status }
                            })
                    } catch { $Errors.Add("GDAP access assignments for $($Rel.displayName): $(& $Err $_)") }
                }
                $Gdap.Add([pscustomobject]@{ Id = $Rel.id; DisplayName = $Rel.displayName; Status = $Rel.status; EndDateTime = $Rel.endDateTime; Roles = $Roles; Assignments = $Assignments })
            }
        } catch {
            $GdapKnown = $false
        }
    }

    $LeastPrivilege = try { Get-CIPPLeastPrivilegeRoles } catch { $Errors.Add("Least-privilege lookup: $($_.Exception.Message)"); $null }

    if (-not $AssignmentsRead) {
        return [pscustomobject]@{ Tenant = $TenantFilter; Summary = $null; Assignments = @(); Recommendations = @(); Findings = @(); Tasks = @($LeastPrivilege.tasks); Errors = @($Errors) }
    }

    $Result = Test-CIPPRoleAssignmentReport -RoleDefinitions $Definitions -Assignments @($Rows) -PimKnown $PimKnown -SignIns $SignIns -SignInKnown $SignInKnown `
        -AdminActivity $Activity -ActivityDays $ActivityDays -BreakGlassIds $BreakGlassIds -LeastPrivilege $LeastPrivilege -GdapRelationships @($Gdap) -GdapKnown $GdapKnown `
        -GdapApplicable $GdapApplicable -AllowedServicePrincipals $AllowedServicePrincipals -InactiveDays $InactiveDays -Now $Now

    [pscustomobject]@{
        Tenant          = $TenantFilter
        Summary         = $Result.Summary
        Assignments     = $Result.Assignments
        Recommendations = $Result.Recommendations
        Findings        = $Result.Findings
        Tasks           = @($LeastPrivilege.tasks | ForEach-Object { [pscustomobject]@{ Task = $_.task; Role = $_.role; Notes = $_.notes } })
        Errors          = @($Errors)
    }
}
