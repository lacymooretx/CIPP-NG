function Get-CIPPConditionalAccessReport {
    <#
    .SYNOPSIS
        Conditional Access policies for a tenant, with every GUID resolved to a name.
    .DESCRIPTION
        Returns CA policies in documentation form: users, groups, roles, applications and
        named locations rendered as names rather than object IDs, which is the whole
        difference between a readable policy document and a page of GUIDs.

        Why this exists rather than a call into the existing list endpoint: the same
        transform lives inline inside both `Invoke-ListConditionalAccessPolicies` and
        `Push-ListConditionalAccessPoliciesAllTenants`, as nested functions in each. Neither
        is callable from here. Refactoring those two upstream files into a shared helper is
        the tidier fix, but it widens the merge surface on files we do not own ahead of the
        CRAFT migration, so this adapted copy sits in our own Reports directory instead.

        If upstream ever extracts a shared helper, delete this and call theirs.
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

    $Requests = @(
        @{ id = 'policies'; url = 'identity/conditionalAccess/policies'; method = 'GET' }
        @{ id = 'namedLocations'; url = 'identity/conditionalAccess/namedLocations'; method = 'GET' }
        @{ id = 'applications'; url = 'applications?$top=999&$select=appId,displayName'; method = 'GET' }
        @{ id = 'roleDefinitions'; url = 'roleManagement/directory/roleDefinitions?$select=id,displayName'; method = 'GET' }
        @{ id = 'groups'; url = 'groups?$top=999&$select=id,displayName'; method = 'GET' }
        @{ id = 'users'; url = 'users?$top=999&$select=id,userPrincipalName'; method = 'GET' }
        @{ id = 'servicePrincipals'; url = 'servicePrincipals?$top=999&$select=appId,displayName'; method = 'GET' }
    )

    $BulkResults = New-GraphBulkRequest -Requests @($Requests) -tenantid $TenantFilter -asapp $true

    $Policies = ($BulkResults | Where-Object { $_.id -eq 'policies' }).body.value
    $Locations = ($BulkResults | Where-Object { $_.id -eq 'namedLocations' }).body.value
    $Applications = ($BulkResults | Where-Object { $_.id -eq 'applications' }).body.value
    $RoleDefinitions = ($BulkResults | Where-Object { $_.id -eq 'roleDefinitions' }).body.value
    $Groups = ($BulkResults | Where-Object { $_.id -eq 'groups' }).body.value
    $Users = ($BulkResults | Where-Object { $_.id -eq 'users' }).body.value
    $ServicePrincipals = ($BulkResults | Where-Object { $_.id -eq 'servicePrincipals' }).body.value

    # Resolve an id to a name, leaving well-known literals ('All', 'None', 'GuestsOrExternalUsers')
    # and unresolvable ids alone - an unresolved GUID is still truer than a blank cell.
    function Resolve-Name($Id, $Collection, [string]$KeyProperty, [string]$NameProperty) {
        if ([string]::IsNullOrWhiteSpace($Id)) { return $null }
        if ($Id -notmatch '^[0-9a-fA-F]{8}-') { return $Id }
        $Match = $Collection | Where-Object { $_.$KeyProperty -eq $Id } | Select-Object -First 1
        if ($Match -and $Match.$NameProperty) { return [string]$Match.$NameProperty }
        return $Id
    }
    function Resolve-Many($Ids, $Collection, [string]$KeyProperty, [string]$NameProperty) {
        $Out = foreach ($Id in @($Ids)) { Resolve-Name $Id $Collection $KeyProperty $NameProperty }
        return (@($Out | Where-Object { $_ }) -join ', ')
    }

    foreach ($Policy in $Policies) {
        $Conditions = $Policy.conditions
        [PSCustomObject]@{
            displayName         = [string]$Policy.displayName
            state               = [string]$Policy.state
            modifiedDateTime    = if ($Policy.modifiedDateTime) { $Policy.modifiedDateTime } elseif ($Policy.createdDateTime) { $Policy.createdDateTime } else { '' }
            includeUsers        = Resolve-Many $Conditions.users.includeUsers $Users 'id' 'userPrincipalName'
            excludeUsers        = Resolve-Many $Conditions.users.excludeUsers $Users 'id' 'userPrincipalName'
            includeGroups       = Resolve-Many $Conditions.users.includeGroups $Groups 'id' 'displayName'
            excludeGroups       = Resolve-Many $Conditions.users.excludeGroups $Groups 'id' 'displayName'
            includeRoles        = Resolve-Many $Conditions.users.includeRoles $RoleDefinitions 'id' 'displayName'
            excludeRoles        = Resolve-Many $Conditions.users.excludeRoles $RoleDefinitions 'id' 'displayName'
            includeApplications = Resolve-Many $Conditions.applications.includeApplications (@($Applications) + @($ServicePrincipals)) 'appId' 'displayName'
            excludeApplications = Resolve-Many $Conditions.applications.excludeApplications (@($Applications) + @($ServicePrincipals)) 'appId' 'displayName'
            includeLocations    = Resolve-Many $Conditions.locations.includeLocations $Locations 'id' 'displayName'
            excludeLocations    = Resolve-Many $Conditions.locations.excludeLocations $Locations 'id' 'displayName'
            includePlatforms    = (@($Conditions.platforms.includePlatforms) -join ', ')
            clientAppTypes      = (@($Conditions.clientAppTypes) -join ', ')
            userRiskLevels      = (@($Conditions.userRiskLevels) -join ', ')
            signInRiskLevels    = (@($Conditions.signInRiskLevels) -join ', ')
            grantOperator       = [string]$Policy.grantControls.operator
            builtInControls     = (@($Policy.grantControls.builtInControls) -join ', ')
            authStrength        = [string]$Policy.grantControls.authenticationStrength.displayName
            sessionControls     = (@(
                    if ($Policy.sessionControls.applicationEnforcedRestrictions.isEnabled) { 'App enforced restrictions' }
                    if ($Policy.sessionControls.cloudAppSecurity.isEnabled) { 'Cloud app security' }
                    if ($Policy.sessionControls.signInFrequency.isEnabled) { 'Sign-in frequency' }
                    if ($Policy.sessionControls.persistentBrowser.isEnabled) { 'Persistent browser' }
                ) -join ', ')
        }
    }
}
