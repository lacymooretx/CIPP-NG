function Get-CippAzureTestContext {
    <#
    .SYNOPSIS
        Everything the AZ_ tests read for one tenant, loaded from the Azure cache types and indexed
    .DESCRIPTION
        Returns $null when the tenant has no readable Azure subscription (never onboarded, or the
        Reader grant was removed). The AZ_ tests emit nothing in that case, so the Azure tab only
        shows tenants that actually have Azure data.
        Each type is read through Get-CIPPTestData, which caches per tenant for the whole test run,
        so building the context once per test costs only the indexing below.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Tenant)

    $Subscriptions = @(Get-CIPPTestData -TenantFilter $Tenant -Type 'AzureSubscriptions' | Where-Object { $_.state -eq 'Enabled' })
    if ($Subscriptions.Count -eq 0) { return $null }

    $SubName = @{}
    foreach ($S in $Subscriptions) { $SubName[[string]$S.subscriptionId] = $S.displayName }

    $Resources = @(Get-CIPPTestData -TenantFilter $Tenant -Type 'AzureResources')
    $ByType = @{}
    foreach ($R in $Resources) {
        $T = ([string]$R.type).ToLower()
        if (-not $ByType.ContainsKey($T)) { $ByType[$T] = [System.Collections.Generic.List[object]]::new() }
        $ByType[$T].Add($R)
    }

    $Index = {
        param($Items, $Key)
        $H = @{}
        foreach ($I in @($Items)) { if ($I.$Key) { $H[([string]$I.$Key).ToLower()] = $I } }
        $H
    }

    [pscustomobject]@{
        Tenant           = $Tenant
        Subscriptions    = $Subscriptions
        SubName          = $SubName
        Resources        = $Resources
        ByType           = $ByType
        RoleAssignments  = @(Get-CIPPTestData -TenantFilter $Tenant -Type 'AzureRoleAssignments')
        CustomRoles      = @(Get-CIPPTestData -TenantFilter $Tenant -Type 'AzureRoleDefinitions')
        Defender         = & $Index (Get-CIPPTestData -TenantFilter $Tenant -Type 'AzureDefender') 'subscriptionId'
        SecurityPosture  = @(Get-CIPPTestData -TenantFilter $Tenant -Type 'AzureSecurityPosture')
        ActivityLog      = & $Index (Get-CIPPTestData -TenantFilter $Tenant -Type 'AzureActivityLogSettings') 'subscriptionId'
        Policy           = @(Get-CIPPTestData -TenantFilter $Tenant -Type 'AzurePolicy')
        BackupItems      = @(Get-CIPPTestData -TenantFilter $Tenant -Type 'AzureBackupItems')
        Config           = & $Index (Get-CIPPTestData -TenantFilter $Tenant -Type 'AzureResourceConfig') 'id'
    }
}
