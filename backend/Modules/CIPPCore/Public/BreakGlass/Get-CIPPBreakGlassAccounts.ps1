function Get-CIPPBreakGlassAccounts {
    <#
    .SYNOPSIS
        Break-glass (emergency access) accounts registered for a tenant, or for every tenant.
    .DESCRIPTION
        Rows live in table BreakGlassAccounts: PartitionKey = tenant id (customerId), RowKey = user object id,
        plus UserPrincipalName, DisplayName, Note, AddedBy, AddedUtc. Managed through ExecBreakGlassAccounts.
        Aspendora fork addition (Vikunja CIPP-3).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        # Tenant default domain or id. Omit for every tenant.
        [string]$TenantFilter
    )
    $Table = Get-CIPPTable -tablename 'BreakGlassAccounts'
    if (-not $TenantFilter) { return @(Get-CIPPAzDataTableEntity @Table) }
    $TenantId = if ($TenantFilter -match '^[0-9a-fA-F-]{36}$') { $TenantFilter } else { (Get-Tenants -TenantFilter $TenantFilter).customerId }
    if (-not $TenantId) { return @() }
    return @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$($TenantId.ToLower())'")
}
