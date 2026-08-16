function Get-CIPPIdentityConfigReportData {
    <#
    .SYNOPSIS
        Gather the Identity Configuration Document model for a single tenant.
    .DESCRIPTION
        Phase 3 of the tenant documentation set: how identity and access are actually
        configured for a client - Conditional Access, named locations, who holds
        administrative roles, how people authenticate, and what guests are allowed to do.

        Same contract as Get-CIPPIntuneConfigReportData: sections carry a stable Key for
        the IT Glue trait mapping, every section is gathered defensively, and a section
        that could not be read is recorded as a collection note rather than rendered as an
        empty tenant.
    .PARAMETER TenantFilter
        Tenant default domain name.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter
    )

    $GraphBeta = 'https://graph.microsoft.com/beta'
    $Findings = [System.Collections.Generic.List[object]]::new()
    $Sections = [System.Collections.Generic.List[object]]::new()
    $Notes = [System.Collections.Generic.List[object]]::new()

    function Add-Finding($Title, $Status, $Detail) {
        $Findings.Add(@{ Title = $Title; Status = $Status; Detail = $Detail })
    }
    function Add-Section($Key, $Title, $Status, $Description, $Columns, $Rows, $Empty) {
        $Sections.Add(@{ Key = $Key; Title = $Title; Status = $Status; Description = $Description; Columns = $Columns; Rows = $Rows; Empty = $Empty })
    }
    function New-RowList { , [System.Collections.Generic.List[object]]::new() }
    function Invoke-Section($Key, $Name, [scriptblock]$Builder) {
        try { & $Builder } catch {
            $Reason = $_.Exception.Message
            $Notes.Add(@{ Section = $Name; Detail = $Reason })
            $r = New-RowList; $r.Add(@($Reason))
            Add-Section $Key $Name 'warn' 'This section could not be retrieved - the data below is incomplete.' @('Error') $r 'Data unavailable.'
        }
    }

    # ---- tenant identity -----------------------------------------------------------
    $Org = $null
    try { $Org = New-GraphGetRequest -uri "$GraphBeta/organization" -tenantid $TenantFilter | Select-Object -First 1 } catch {}
    $TenantName = if ($Org.displayName) { $Org.displayName } else { $TenantFilter }
    $DefaultDomain = ($Org.verifiedDomains | Where-Object { $_.isDefault }).name
    if (-not $DefaultDomain) { $DefaultDomain = $TenantFilter }

    # Section builders run in a child scope, so anything the executive findings need back
    # out of them lives in this hashtable. A plain variable assigned inside a section is
    # silently discarded - the findings would then report zero policies on a tenant that
    # has twenty.
    $State = @{ Count = 0; CAPolicies = @(); GlobalAdmins = 0 }

    # ---- Conditional Access --------------------------------------------------------
    Invoke-Section 'ConditionalAccess' 'Conditional Access Policies' {
        $CAPolicies = @(Get-CIPPConditionalAccessReport -TenantFilter $TenantFilter)
        $State.CAPolicies = $CAPolicies
        $r = New-RowList
        foreach ($p in $CAPolicies) {
            $Targets = @(
                if ($p.includeUsers) { "Users: $($p.includeUsers)" }
                if ($p.includeGroups) { "Groups: $($p.includeGroups)" }
                if ($p.includeRoles) { "Roles: $($p.includeRoles)" }
            ) -join ' | '
            $Excludes = @(
                if ($p.excludeUsers) { "Users: $($p.excludeUsers)" }
                if ($p.excludeGroups) { "Groups: $($p.excludeGroups)" }
                if ($p.excludeRoles) { "Roles: $($p.excludeRoles)" }
            ) -join ' | '
            $Controls = @(
                if ($p.builtInControls) { $p.builtInControls }
                if ($p.authStrength) { "Auth strength: $($p.authStrength)" }
                if ($p.sessionControls) { "Session: $($p.sessionControls)" }
            ) -join ' | '
            $Conditions = @(
                if ($p.includeApplications) { "Apps: $($p.includeApplications)" }
                if ($p.includeLocations) { "Locations: $($p.includeLocations)" }
                if ($p.userRiskLevels) { "User risk: $($p.userRiskLevels)" }
                if ($p.signInRiskLevels) { "Sign-in risk: $($p.signInRiskLevels)" }
            ) -join ' | '
            $r.Add(@($p.displayName, $p.state, $Targets, $Excludes, $Conditions, $Controls))
        }
        $State.Count += $CAPolicies.Count
        $Enabled = @($CAPolicies | Where-Object { $_.state -eq 'enabled' }).Count
        Add-Section 'ConditionalAccess' 'Conditional Access Policies' 'info' `
            "$($CAPolicies.Count) policies, $Enabled enabled." `
            @('Policy', 'State', 'Applies To', 'Excludes', 'Conditions', 'Controls') $r `
            'No Conditional Access policies exist in this tenant.'
    }

    # ---- Named Locations -----------------------------------------------------------
    Invoke-Section 'NamedLocations' 'Named Locations' {
        $Locations = @(New-GraphGetRequest -uri "$GraphBeta/identity/conditionalAccess/namedLocations" -tenantid $TenantFilter)
        $r = New-RowList
        foreach ($l in $Locations) {
            $Kind = if ($l.'@odata.type' -match 'ipNamedLocation') { 'IP ranges' }
            elseif ($l.'@odata.type' -match 'countryNamedLocation') { 'Countries' }
            else { ($l.'@odata.type' -replace '#microsoft\.graph\.', '') }
            $Detail = if ($l.ipRanges) {
                (@($l.ipRanges | ForEach-Object { $_.cidrAddress }) | Where-Object { $_ }) -join ', '
            } elseif ($l.countriesAndRegions) {
                (@($l.countriesAndRegions) -join ', ')
            } else { '' }
            $Trusted = if ($null -ne $l.isTrusted) { "$($l.isTrusted)" } else { '' }
            $r.Add(@([string]$l.displayName, $Kind, $Detail, $Trusted))
        }
        $State.Count += $Locations.Count
        Add-Section 'NamedLocations' 'Named Locations' 'info' `
            "$($Locations.Count) named locations." `
            @('Location', 'Type', 'Definition', 'Trusted') $r `
            'No named locations are defined.'
    }

    # ---- Administrative Roles ------------------------------------------------------
    # Who can do what to this tenant. The single most useful identity fact to have written
    # down, and the one that drifts silently as people come and go.
    Invoke-Section 'AdminRoles' 'Administrative Roles' {
        $Roles = @(New-GraphGetRequest -uri "$GraphBeta/directoryRoles?`$expand=members" -tenantid $TenantFilter)
        $r = New-RowList
        foreach ($Role in ($Roles | Where-Object { @($_.members).Count -gt 0 } | Sort-Object displayName)) {
            foreach ($m in @($Role.members)) {
                $Who = if ($m.userPrincipalName) { $m.userPrincipalName } elseif ($m.displayName) { $m.displayName } else { $m.id }
                $Kind = ($m.'@odata.type' -replace '#microsoft\.graph\.', '')
                $r.Add(@([string]$Role.displayName, $Who, $Kind, [string]$m.accountEnabled))
            }
            if ($Role.displayName -match 'Global Administrator|Company Administrator') {
                $State.GlobalAdmins = @($Role.members).Count
            }
        }
        $State.Count += $r.Count
        $Status = if ($State.GlobalAdmins -gt 4) { 'warn' } else { 'info' }
        Add-Section 'AdminRoles' 'Administrative Roles' $Status `
            "$($r.Count) role assignments across roles that have members. $($State.GlobalAdmins) Global Administrator(s)." `
            @('Role', 'Member', 'Type', 'Enabled') $r `
            'No directory roles have members, which is unexpected - every tenant has at least one Global Administrator.'
    }

    # ---- Authentication Methods ----------------------------------------------------
    Invoke-Section 'AuthenticationMethods' 'Authentication Methods' {
        $r = New-RowList
        try {
            $Policy = New-GraphGetRequest -uri "$GraphBeta/policies/authenticationMethodsPolicy" -tenantid $TenantFilter
            foreach ($Config in @($Policy.authenticationMethodConfigurations)) {
                # -creplace, NOT -replace: PowerShell's -replace is case-INSENSITIVE by
                # default, so [A-Z] also matches lowercase and every letter pair gets split
                # ("microsoftAuthenticator" -> "m ic ro so ft Au th en ti ca to r").
                $Method = ($Config.id -creplace '([a-z0-9])([A-Z])', '$1 $2')
                if ($Method) { $Method = $Method.Substring(0, 1).ToUpper() + $Method.Substring(1) }
                $Targets = (@($Config.includeTargets | ForEach-Object { $_.targetType }) | Where-Object { $_ }) -join ', '
                $r.Add(@('Method', $Method, [string]$Config.state, $Targets))
            }
        } catch {
            $Notes.Add(@{ Section = 'Authentication Methods'; Detail = "Authentication methods policy unavailable: $($_.Exception.Message)" })
        }
        try {
            $SecurityDefaults = New-GraphGetRequest -uri "$GraphBeta/policies/identitySecurityDefaultsEnforcementPolicy" -tenantid $TenantFilter
            $r.Add(@('Tenant', 'Security Defaults', $(if ($SecurityDefaults.isEnabled) { 'enabled' } else { 'disabled' }), ''))
        } catch {
            $Notes.Add(@{ Section = 'Authentication Methods'; Detail = "Security defaults state unavailable: $($_.Exception.Message)" })
        }
        $State.Count += $r.Count
        Add-Section 'AuthenticationMethods' 'Authentication Methods' 'info' `
            "$($r.Count) authentication method configurations." `
            @('Scope', 'Setting', 'State', 'Targets') $r `
            'No authentication method policy could be read.'
    }

    # ---- Guest and External Access -------------------------------------------------
    Invoke-Section 'GuestAccess' 'Guest and External Access' {
        $r = New-RowList
        $Auth = New-GraphGetRequest -uri "$GraphBeta/policies/authorizationPolicy" -tenantid $TenantFilter | Select-Object -First 1
        if ($Auth) {
            $r.Add(@('Guest invitations allowed from', [string]$Auth.allowInvitesFrom))
            $r.Add(@('Users can create apps', "$($Auth.defaultUserRolePermissions.allowedToCreateApps)"))
            $r.Add(@('Users can create security groups', "$($Auth.defaultUserRolePermissions.allowedToCreateSecurityGroups)"))
            $r.Add(@('Users can read other users', "$($Auth.defaultUserRolePermissions.allowedToReadOtherUsers)"))
            $r.Add(@('Self-service password reset enabled', "$($Auth.allowedToUseSSPR)"))
            $r.Add(@('Guest user role', [string]$Auth.guestUserRoleId))
        }
        $GuestCount = 0
        try {
            $Guests = @(New-GraphGetRequest -uri "$GraphBeta/users?`$filter=userType eq 'Guest'&`$select=id&`$top=999" -tenantid $TenantFilter)
            $GuestCount = $Guests.Count
            $r.Add(@('Guest accounts in directory', "$GuestCount"))
        } catch {
            $Notes.Add(@{ Section = 'Guest and External Access'; Detail = "Guest account count unavailable: $($_.Exception.Message)" })
        }
        $State.Count += $r.Count
        Add-Section 'GuestAccess' 'Guest and External Access' 'info' `
            'Directory-wide defaults governing guests and what ordinary users may do.' `
            @('Setting', 'Value') $r `
            'Authorization policy could not be read.'
    }

    # ---- executive findings --------------------------------------------------------
    $CAPolicies = @($State.CAPolicies)
    $GlobalAdmins = $State.GlobalAdmins
    $EnabledCA = @($CAPolicies | Where-Object { $_.state -eq 'enabled' }).Count
    $ReportOnly = @($CAPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' }).Count
    if ($CAPolicies.Count -eq 0) {
        Add-Finding 'Conditional Access' 'fail' 'No Conditional Access policies exist. Access is governed only by security defaults, if those are on.'
    } elseif ($EnabledCA -eq 0) {
        Add-Finding 'Conditional Access' 'fail' "$($CAPolicies.Count) policies exist but none are enabled - $ReportOnly are report-only, so nothing is being enforced."
    } else {
        Add-Finding 'Conditional Access' 'pass' "$EnabledCA of $($CAPolicies.Count) policies are enabled and enforcing."
    }

    if ($GlobalAdmins -gt 4) {
        Add-Finding 'Global Administrators' 'warn' "$GlobalAdmins accounts hold Global Administrator. Microsoft recommends fewer than five."
    } elseif ($GlobalAdmins -gt 0) {
        Add-Finding 'Global Administrators' 'pass' "$GlobalAdmins account(s) hold Global Administrator."
    }

    Add-Finding 'Objects documented' 'info' "$($State.Count) identity and access objects captured for $TenantName."

    if ($Notes.Count -gt 0) {
        Add-Finding 'Collection warnings' 'warn' "$($Notes.Count) section(s) could not be read in full. See collection notes."
    }

    return @{
        Title           = 'Identity Configuration Document'
        TenantName      = $TenantName
        TenantDomain    = $DefaultDomain
        GeneratedDate   = (Get-Date).ToString('dd MMMM yyyy')
        Findings        = $Findings
        Sections        = $Sections
        CollectionNotes = $Notes
        ObjectCount     = $State.Count
    }
}
