function Get-CIPPVendorAccessReport {
    <#
    .SYNOPSIS
        Lists every outside party with standing access to one tenant: foreign apps, foreign role holders (other
        partners' GDAP/DAP groups), guests with directory roles and service-provider partners.
    .DESCRIPTION
        Read only. Returns @{ Tenant; TenantId; GeneratedAt; Items; Errors; SignInActivityAvailable }. Each item has
        Kind, Key, Organisation, OrganisationId, OrganisationType, Vendor, Name, Access, Risk, RiskReasons,
        LastSignInDateTime, DaysSinceLastSignIn, SignInActivity, Stale and Details.

        Kinds:
          App                  a service principal owned by another organisation (not this tenant, not Microsoft, not a
                               managed identity). The risk rating comes from Get-CIPPAppPermissionExposure (CIPP's
                               risky-permissions catalogue). An app it does not list holds no catalogued permission and is
                               rated Low, but its permissions are still listed.
          ForeignRoleHolder    a group or user from another organisation holding directory roles, read from
                               roleManagement/directory/roleAssignments (beta principalOrganizationId). This is how a
                               partner's GDAP or DAP access appears in the customer tenant ("AdminAgents @( PAX8 US …)").
                               The CIPP partner tenant's own GDAP groups are summarised as one row.
          GuestRoleHolder      a guest (userType Guest or #EXT#) holding directory roles: the CIPP-15 rule.
          ServiceProvider      a cross-tenant access partner configured with isServiceProvider = true.

        Sign-in: apps from the ServicePrincipalSignInActivities cache and guests from the Users cache, both Entra ID P1
        data. Without it SignInActivity is 'Unknown' and Stale is $null, never "never". Stale is $true when the last
        sign-in is StaleDays (default 45) or more days ago, or when sign-in data exists and none is recorded.
        Apps and permissions come from the reporting database. Role assignments and cross-tenant partners are read
        live: the RoleAssignments cache has no principalOrganizationId and cannot resolve foreign groups.
        Aspendora fork addition (Vendor Access report).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantFilter,
        [int]$StaleDays = 45,
        # Read apps and permissions live from Graph instead of the reporting database.
        [switch]$Live
    )

    $Errors = [System.Collections.Generic.List[string]]::new()
    $Items = [System.Collections.Generic.List[object]]::new()
    $Now = [datetime]::UtcNow
    $PartnerTenantId = [string]$env:TenantID
    $VendorTenants = Get-CIPPVendorTenantMap
    $Err = { param($E) try { (Get-CippException -Exception $E).NormalizedError } catch { [string]$E.Exception.Message } }
    $Tenant = Get-Tenants -TenantFilter $TenantFilter | Select-Object -First 1
    $TenantId = [string]$Tenant.customerId
    $ManagedTenants = @{}
    foreach ($T in @(Get-Tenants -IncludeErrors)) { if ($T.customerId) { $ManagedTenants[[string]$T.customerId] = $T } }

    $ToUtc = {
        param($Value)
        if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
        $Parsed = [datetimeoffset]::MinValue
        if ($Value -and [datetimeoffset]::TryParse([string]$Value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$Parsed)) { return $Parsed.UtcDateTime }
        return $null
    }
    # One place decides what stale means, so the page, the email and the tests agree.
    $SignInState = {
        param($Known, $Last)
        if (-not $Known) { return @{ Activity = 'Unknown'; Days = $null; Stale = $null; Last = $null } }
        if (-not $Last) { return @{ Activity = 'No sign-in recorded'; Days = $null; Stale = $true; Last = $null } }
        $Days = [int][Math]::Max(0, [Math]::Floor(($Now - $Last).TotalDays))
        $Activity = if ($Days -lt $StaleDays) { 'Active' } else { "Stale $($StaleDays)+ days" }
        return @{ Activity = $Activity; Days = $Days; Stale = ($Days -ge $StaleDays); Last = $Last }
    }
    # Who an organisation is, from Aspendora's point of view.
    $OrgType = {
        param($OrgId)
        if (-not $OrgId) { return 'Unknown' }
        if ($PartnerTenantId -and $OrgId -eq $PartnerTenantId) { return 'Partner tenant' }
        if ($TenantId -and $OrgId -eq $TenantId) { return 'This tenant' }
        $V = $null
        if ($VendorTenants.TryGetValue($OrgId, [ref]$V)) {
            if ($V.VendorType -eq 'Microsoft') { return 'Microsoft' }
            if ($V.VendorType -eq 'MSP') { return 'MSP vendor' }
            return 'Known vendor'
        }
        if ($ManagedTenants.ContainsKey($OrgId)) { return 'Managed tenant' }
        return 'Third party'
    }
    $OrgIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    # ---------- (a) foreign apps ----------
    $Exposure = @()
    try {
        $Exposure = @(Get-CIPPAppPermissionExposure -TenantFilter $TenantFilter -Live:$Live)
    } catch [System.Management.Automation.ItemNotFoundException] {
        try {
            $Exposure = @(Get-CIPPAppPermissionExposure -TenantFilter $TenantFilter -Live)
            $Live = [switch]::new($true)
            $Errors.Add('The reporting database has no app data for this tenant yet; apps were read live.')
        } catch { $Errors.Add("App permissions: $(& $Err $_)") }
    } catch { $Errors.Add("App permissions: $(& $Err $_)") }
    $ExposureById = @{}
    foreach ($Row in $Exposure) { if ($Row.ServicePrincipalId) { $ExposureById[[string]$Row.ServicePrincipalId] = $Row } }

    $SpFields = @('id', 'appId', 'displayName', 'appOwnerOrganizationId', 'accountEnabled', 'publisherName', 'verifiedPublisher', 'servicePrincipalType', 'createdDateTime', 'appRoles')
    $Sps = @(); $Assignments = @(); $Grants = @(); $Activities = $null
    try {
        if ($Live) {
            $Sps = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/servicePrincipals?`$select=$($SpFields -join ',')&`$top=999" -tenantid $TenantFilter -ErrorAction Stop)
            $Grants = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999' -tenantid $TenantFilter -ErrorAction Stop)
        } else {
            $Sps = @(New-CIPPDbRequest -TenantFilter $TenantFilter -Type 'ServicePrincipals' -Fields $SpFields)
            $Assignments = @(New-CIPPDbRequest -TenantFilter $TenantFilter -Type 'AppRoleAssignments' -Fields 'principalId', 'resourceId', 'resourceDisplayName', 'appRoleId', 'createdDateTime')
            $Grants = @(New-CIPPDbRequest -TenantFilter $TenantFilter -Type 'OAuth2PermissionGrants' -Fields 'clientId', 'resourceId', 'consentType', 'scope')
        }
    } catch { $Errors.Add("Service principals: $(& $Err $_)") }
    try {
        $ActivityRows = @(New-CIPPDbRequest -TenantFilter $TenantFilter -Type 'ServicePrincipalSignInActivities' -Fields 'appId', 'lastSignInActivity')
        # The count row exists once the cache has been collected, even when no app has signed in.
        $ActivityCount = @(Get-CIPPDbItem -TenantFilter $TenantFilter -Type 'ServicePrincipalSignInActivities' -ErrorAction SilentlyContinue | Where-Object RowKey -EQ 'ServicePrincipalSignInActivities-Count')
        if ($ActivityRows.Count -gt 0 -or $ActivityCount.Count -gt 0) {
            $Activities = @{}
            foreach ($A in $ActivityRows) { if ($A.appId) { $Activities[[string]$A.appId] = & $ToUtc $A.lastSignInActivity.lastSignInDateTime } }
        }
    } catch { $Activities = $null }

    $SpById = @{}
    foreach ($Sp in $Sps) { if ($Sp.id) { $SpById[[string]$Sp.id] = $Sp } }
    $RoleNames = @{}
    foreach ($Sp in $Sps) { foreach ($R in @($Sp.appRoles)) { if ($R.id) { $RoleNames["$($Sp.id)|$($R.id)"] = [string]$R.value } } }
    $PermsBySp = @{}
    $AddPerm = {
        param($SpId, $Text)
        if (-not $PermsBySp.ContainsKey($SpId)) { $PermsBySp[$SpId] = [System.Collections.Generic.List[string]]::new() }
        if (-not $PermsBySp[$SpId].Contains($Text)) { $PermsBySp[$SpId].Add($Text) }
    }
    foreach ($A in $Assignments) {
        $Res = $SpById[[string]$A.resourceId]
        $Name = $RoleNames["$($A.resourceId)|$($A.appRoleId)"]
        if (-not $Name) { $Name = if ([string]$A.appRoleId -eq '00000000-0000-0000-0000-000000000000') { 'default access' } else { [string]$A.appRoleId } }
        & $AddPerm ([string]$A.principalId) ('{0}: {1} (application)' -f $(if ($Res.displayName) { $Res.displayName } else { $A.resourceDisplayName }), $Name)
    }
    foreach ($G in $Grants) {
        $Res = $SpById[[string]$G.resourceId]
        $Who = if ($G.consentType -eq 'AllPrincipals') { 'all users' } else { 'one user' }
        foreach ($Scope in ([string]$G.scope).Split([char[]]' ', [System.StringSplitOptions]::RemoveEmptyEntries)) {
            & $AddPerm ([string]$G.clientId) ('{0}: {1} (delegated, {2})' -f $Res.displayName, $Scope, $Who)
        }
    }

    foreach ($Sp in $Sps) {
        $Owner = [string]$Sp.appOwnerOrganizationId
        $Type = & $OrgType $Owner
        if ($Sp.servicePrincipalType -eq 'ManagedIdentity' -or $Type -in @('This tenant', 'Microsoft')) { continue }
        $Id = [string]$Sp.id
        $Exp = $ExposureById[$Id]
        $Perms = if ($PermsBySp.ContainsKey($Id)) { $PermsBySp[$Id] } else { @() }
        # No owner organisation and nothing granted: Microsoft's legacy first-party apps (O365 LinkedIn Connection,
        # Azure Media Service, YammerOnOls), seen in every tenant on 2026-11-09. Noise, not access.
        if (-not $Owner -and @($Perms).Count -eq 0 -and -not $Exp) { continue }
        if ($Exp -and $Exp.Permissions) { $AccessText = [string]$Exp.Permissions } else { $AccessText = (@($Perms) -join '; ') }
        $Last = if ($null -ne $Activities) { $Activities[[string]$Sp.appId] } else { $null }
        $SignIn = & $SignInState ($null -ne $Activities) $Last
        $Vendor = $null
        if ($Owner) { [void]$VendorTenants.TryGetValue($Owner, [ref]$Vendor) }
        if ($Owner) { [void]$OrgIds.Add($Owner) }
        $Reasons = [System.Collections.Generic.List[string]]::new()
        if ($Exp) { foreach ($R in @($Exp.RiskReasons)) { $Reasons.Add([string]$R) } } else { $Reasons.Add('Holds no permission from the risky-permissions catalogue') }
        $Risk = if ($Exp.Risk) { [string]$Exp.Risk } else { 'Low' }
        if ($Sp.accountEnabled -eq $false) { $Reasons.Add('Disabled in this tenant') }
        # Unexpired sign-in credentials added in the last 30 days (the audit window the exposure report reads).
        $NewCreds = @($Exp.CredentialDetails | Where-Object { -not $_.Expired -and $_.Purpose -eq 'Sign-in' -and $_.AddedDateTime -and ($Now - (& $ToUtc $_.AddedDateTime)).TotalDays -le 30 })
        $Items.Add([pscustomobject]@{
                Kind                = 'App'
                Key                 = "App|$($Sp.appId)"
                Name                = [string]$Sp.displayName
                ObjectId            = $Id
                AppId               = [string]$Sp.appId
                Organisation        = $null
                OrganisationId      = $Owner
                OrganisationType    = $Type
                Vendor              = $Vendor.Name
                VendorType          = $Vendor.VendorType
                Publisher           = if ($Sp.verifiedPublisher.displayName) { [string]$Sp.verifiedPublisher.displayName } else { [string]$Sp.publisherName }
                Enabled             = $Sp.accountEnabled
                Access              = if ($AccessText) { $AccessText } else { 'Sign-in only (no API permissions granted)' }
                PermissionCount     = [Math]::Max([int]$Exp.PermissionCount, @($Perms).Count)
                HasPermissions      = ([Math]::Max([int]$Exp.PermissionCount, @($Perms).Count) -gt 0)
                Risk                = $Risk
                RiskReasons         = @($Reasons)
                NewCredentials      = $NewCreds.Count
                ConsentedDateTime   = & $ToUtc $Sp.createdDateTime
                LastSignInDateTime  = $SignIn.Last
                DaysSinceLastSignIn = $SignIn.Days
                SignInActivity      = $SignIn.Activity
                Stale               = $SignIn.Stale
            })
    }

    # ---------- (b) and (c) role holders ----------
    try {
        $Definitions = @{}
        foreach ($D in @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?$select=id,displayName,isPrivileged,templateId' -tenantid $TenantFilter -ErrorAction Stop)) {
            $Definitions[[string]$D.id] = $D
            if ($D.templateId) { $Definitions[[string]$D.templateId] = $D }
        }
        $RoleRows = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments?$select=id,principalId,principalOrganizationId,roleDefinitionId,directoryScopeId&$top=999' -tenantid $TenantFilter -ErrorAction Stop)
        $ByPrincipal = @{}
        foreach ($R in $RoleRows) {
            $P = [string]$R.principalId
            if (-not $ByPrincipal.ContainsKey($P)) { $ByPrincipal[$P] = [System.Collections.Generic.List[object]]::new() }
            $ByPrincipal[$P].Add($R)
        }
        $Foreign = @($ByPrincipal.Keys | Where-Object {
                $Org = [string]$ByPrincipal[$_][0].principalOrganizationId
                $Org -and $TenantId -and $Org -ne $TenantId
            })
        $Local = @($ByPrincipal.Keys | Where-Object { $_ -notin $Foreign })
        $RoleList = {
            param($Rows)
            $Names = foreach ($R in $Rows) {
                $D = $Definitions[[string]$R.roleDefinitionId]
                $N = if ($D.displayName) { [string]$D.displayName } else { [string]$R.roleDefinitionId }
                if ($R.directoryScopeId -and $R.directoryScopeId -ne '/') { "$N (scoped)" } else { $N }
            }
            @($Names | Sort-Object -Unique)
        }
        $IsPrivileged = { param($Rows) @($Rows | Where-Object { $Definitions[[string]$_.roleDefinitionId].isPrivileged -eq $true }).Count -gt 0 }
        $IsGlobalAdmin = { param($Rows) @($Rows | Where-Object { $Definitions[[string]$_.roleDefinitionId].templateId -eq '62e90394-69f5-4237-9190-012177145e10' }).Count -gt 0 }

        # The CIPP partner tenant's own GDAP groups: one summary row, not one per group.
        $PartnerPrincipals = @($Foreign | Where-Object { $PartnerTenantId -and [string]$ByPrincipal[$_][0].principalOrganizationId -eq $PartnerTenantId })
        if ($PartnerPrincipals.Count -gt 0) {
            [void]$OrgIds.Add($PartnerTenantId)
            $AllRows = @($PartnerPrincipals | ForEach-Object { $ByPrincipal[$_] })
            $Roles = & $RoleList $AllRows
            $Items.Add([pscustomobject]@{
                    Kind                = 'ForeignRoleHolder'
                    Key                 = "Role|$PartnerTenantId|partner"
                    Name                = "CIPP partner tenant GDAP ($($PartnerPrincipals.Count) groups)"
                    ObjectId            = $null
                    AppId               = $null
                    Organisation        = $null
                    OrganisationId      = $PartnerTenantId
                    OrganisationType    = 'Partner tenant'
                    Vendor              = $null
                    VendorType          = $null
                    Publisher           = $null
                    Enabled             = $true
                    Access              = ($Roles -join '; ')
                    PermissionCount     = $Roles.Count
                    HasPermissions      = $true
                    Risk                = 'Low'
                    RiskReasons         = @('Aspendora''s own GDAP access through the CIPP partner tenant')
                    NewCredentials      = 0
                    ConsentedDateTime   = $null
                    LastSignInDateTime  = $null
                    DaysSinceLastSignIn = $null
                    SignInActivity      = 'Not applicable'
                    Stale               = $null
                })
        }
        # Other organisations: resolve the principal's name with $expand. getByIds cannot read foreign objects and a
        # principalId filter returns "does not exist" for them; a roleDefinitionId filter with $expand works (seen live
        # 2026-11-08), so read each role the foreign principals hold once.
        $Others = @($Foreign | Where-Object { $_ -notin $PartnerPrincipals })
        $Resolved = @{}
        if ($Others.Count -gt 0) {
            $OtherSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$Others, [System.StringComparer]::OrdinalIgnoreCase)
            $RoleIds = @($Others | ForEach-Object { $ByPrincipal[$_] | ForEach-Object { [string]$_.roleDefinitionId } } | Sort-Object -Unique)
            $Requests = @($RoleIds | ForEach-Object { @{ id = $_; method = 'GET'; url = "roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$_'&`$expand=principal" } })
            try {
                foreach ($Resp in @(New-GraphBulkRequest -tenantid $TenantFilter -Requests $Requests -Version 'beta')) {
                    if ([int]$Resp.status -ne 200) { continue }
                    foreach ($A in @($Resp.body.value)) {
                        if ($A.principal -and $OtherSet.Contains([string]$A.principalId)) { $Resolved[[string]$A.principalId] = $A.principal }
                    }
                }
            } catch { $Errors.Add("Foreign principal names: $(& $Err $_)") }
        }
        foreach ($P in $Others) {
            $Rows = $ByPrincipal[$P]
            $Org = [string]$Rows[0].principalOrganizationId
            [void]$OrgIds.Add($Org)
            $Principal = $Resolved[$P]
            $PType = ([string]$Principal.'@odata.type') -replace '^#microsoft\.graph\.', ''
            $Roles = & $RoleList $Rows
            $GA = & $IsGlobalAdmin $Rows
            $Priv = & $IsPrivileged $Rows
            $Reasons = [System.Collections.Generic.List[string]]::new()
            $Reasons.Add('A group or account from another organisation holds directory roles here: a partner''s GDAP/DAP access or another outside admin')
            if ($GA) { $Reasons.Add('Includes Global Administrator') } elseif ($Priv) { $Reasons.Add('Includes privileged roles') }
            $Items.Add([pscustomobject]@{
                    Kind                = 'ForeignRoleHolder'
                    Key                 = "Role|$Org|$P"
                    Name                = if ($Principal.displayName) { [string]$Principal.displayName } else { "Unresolved principal $P" }
                    ObjectId            = $P
                    AppId               = $null
                    Organisation        = $null
                    OrganisationId      = $Org
                    OrganisationType    = & $OrgType $Org
                    Vendor              = $null
                    VendorType          = $null
                    Publisher           = $null
                    Enabled             = $true
                    PrincipalType       = $PType
                    Access              = ($Roles -join '; ')
                    PermissionCount     = $Roles.Count
                    HasPermissions      = $true
                    Risk                = if ($GA) { 'Critical' } elseif ($Priv) { 'High' } else { 'Medium' }
                    RiskReasons         = @($Reasons)
                    NewCredentials      = 0
                    ConsentedDateTime   = $null
                    LastSignInDateTime  = $null
                    DaysSinceLastSignIn = $null
                    SignInActivity      = 'Not applicable'
                    Stale               = $null
                })
        }

        # Guests: CIPP-15's rule (userType Guest or #EXT# in the UPN), applied to local principals.
        if ($Local.Count -gt 0) {
            $Users = @{}
            for ($i = 0; $i -lt $Local.Count; $i += 1000) {
                $Chunk = @($Local[$i..([Math]::Min($i + 999, $Local.Count - 1))])
                $Body = @{ ids = $Chunk; types = @('user') } | ConvertTo-Json -Compress
                foreach ($U in @(New-GraphPOSTRequest -tenantid $TenantFilter -uri 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds?$select=id,displayName,userPrincipalName,userType,mail,accountEnabled' -body $Body).value) {
                    $Users[[string]$U.id] = $U
                }
            }
            $GuestIds = @($Users.Keys | Where-Object { $Users[$_].userType -eq 'Guest' -or [string]$Users[$_].userPrincipalName -match '#EXT#' })
            $SignIns = $null
            if ($GuestIds.Count -gt 0) {
                try {
                    $Cached = @(New-CIPPDbRequest -TenantFilter $TenantFilter -Type 'Users' -Fields 'id', 'signInActivity')
                    if (@($Cached | Where-Object { $null -ne $_.signInActivity }).Count -gt 0) {
                        $SignIns = @{}
                        foreach ($U in $Cached) {
                            $L = @((& $ToUtc $U.signInActivity.lastSignInDateTime), (& $ToUtc $U.signInActivity.lastNonInteractiveSignInDateTime)) | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1
                            $SignIns[[string]$U.id] = $L
                        }
                    }
                } catch { $SignIns = $null }
            }
            foreach ($G in $GuestIds) {
                $U = $Users[$G]
                $Rows = $ByPrincipal[$G]
                $Roles = & $RoleList $Rows
                $Priv = & $IsPrivileged $Rows
                $Domain = if ($U.mail -match '@(.+)$') { $Matches[1] } elseif ($U.userPrincipalName -match '_([^_#]+)#EXT#') { $Matches[1] } else { $null }
                $SignIn = & $SignInState ($null -ne $SignIns) $(if ($null -ne $SignIns) { $SignIns[$G] } else { $null })
                $Items.Add([pscustomobject]@{
                        Kind                = 'GuestRoleHolder'
                        Key                 = "Guest|$G"
                        Name                = "$($U.displayName) ($($U.mail))"
                        ObjectId            = $G
                        AppId               = $null
                        Organisation        = $Domain
                        OrganisationId      = $null
                        OrganisationType    = 'Guest'
                        Vendor              = $null
                        VendorType          = $null
                        Publisher           = $null
                        Enabled             = $U.accountEnabled
                        Access              = ($Roles -join '; ')
                        PermissionCount     = $Roles.Count
                        HasPermissions      = $true
                        Risk                = if ($Priv) { 'High' } else { 'Medium' }
                        RiskReasons         = @("A guest's password, MFA and lifecycle are controlled by its home tenant, not this one$(if ($Priv) { '; holds privileged roles' })")
                        NewCredentials      = 0
                        ConsentedDateTime   = $null
                        LastSignInDateTime  = $SignIn.Last
                        DaysSinceLastSignIn = $SignIn.Days
                        SignInActivity      = $SignIn.Activity
                        Stale               = $SignIn.Stale
                    })
            }
        }
    } catch { $Errors.Add("Directory roles: $(& $Err $_)") }

    # ---------- (d) service-provider partners ----------
    try {
        foreach ($Partner in @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy/partners' -tenantid $TenantFilter -ErrorAction Stop)) {
            if ($Partner.isServiceProvider -ne $true) { continue }
            $Org = [string]$Partner.tenantId
            [void]$OrgIds.Add($Org)
            $Type = & $OrgType $Org
            $Items.Add([pscustomobject]@{
                    Kind                = 'ServiceProvider'
                    Key                 = "Provider|$Org"
                    Name                = 'Cross-tenant service provider'
                    ObjectId            = $null
                    AppId               = $null
                    Organisation        = $null
                    OrganisationId      = $Org
                    OrganisationType    = $Type
                    Vendor              = $null
                    VendorType          = $null
                    Publisher           = $null
                    Enabled             = $true
                    Access              = 'Cross-tenant access partner marked as a service provider (set when a partner relationship is accepted)'
                    PermissionCount     = 0
                    HasPermissions      = $false
                    Risk                = if ($Type -eq 'Partner tenant') { 'Low' } else { 'Medium' }
                    RiskReasons         = @($(if ($Type -eq 'Partner tenant') { 'Aspendora''s CIPP partner tenant' } else { 'Another organisation is configured as a service provider for this tenant' }))
                    NewCredentials      = 0
                    ConsentedDateTime   = $null
                    LastSignInDateTime  = $null
                    DaysSinceLastSignIn = $null
                    SignInActivity      = 'Not applicable'
                    Stale               = $null
                })
        }
    } catch { $Errors.Add("Cross-tenant partners: $(& $Err $_)") }

    # Organisation names, from the vendor list, the managed-tenant list or Entra's tenant lookup.
    $Names = Resolve-CIPPVendorAccessOrganisation -TenantIds @($OrgIds)
    foreach ($I in $Items) {
        if ($I.Organisation -or -not $I.OrganisationId) { continue }
        $V = $null
        $I.Organisation = if ($VendorTenants.TryGetValue([string]$I.OrganisationId, [ref]$V)) { if ($V.Company) { $V.Company } else { $V.Name } }
        elseif ($ManagedTenants.ContainsKey([string]$I.OrganisationId)) { [string]$ManagedTenants[[string]$I.OrganisationId].displayName }
        elseif ($Names[[string]$I.OrganisationId]) { [string]$Names[[string]$I.OrganisationId] }
        else { [string]$I.OrganisationId }
    }

    $Rank = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }
    [pscustomobject]@{
        Tenant                  = if ($Tenant.defaultDomainName) { [string]$Tenant.defaultDomainName } else { $TenantFilter }
        TenantName              = [string]$Tenant.displayName
        TenantId                = $TenantId
        GeneratedAt             = $Now.ToString('o')
        Source                  = if ($Live) { 'Live' } else { 'Reporting database' }
        SignInActivityAvailable = $null -ne $Activities
        Items                   = @($Items | Sort-Object @{ Expression = { $Rank[[string]$_.Risk] }; Descending = $true }, Kind, Name)
        Errors                  = @($Errors)
    }
}
