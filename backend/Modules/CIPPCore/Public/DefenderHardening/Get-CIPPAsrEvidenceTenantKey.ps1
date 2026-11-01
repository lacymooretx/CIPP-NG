function Get-CIPPAsrEvidenceTenantKey {
    <#
    .SYNOPSIS
        The AsrEvidence PartitionKey for a tenant: its default domain, lower case.
    .DESCRIPTION
        Callers may name a tenant by default domain, another domain or customer id. The evidence writer and reader
        both normalise through Get-Tenants so rows always land on, and are read from, the same key. Falls back to
        the value given (lower case) when the tenant is not in CIPP's list. Aspendora fork addition (Vikunja CIPP-26).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TenantFilter)
    $Tenant = $null
    try { $Tenant = Get-Tenants -TenantFilter $TenantFilter | Select-Object -First 1 } catch {}
    ([string]($Tenant.defaultDomainName ?? $TenantFilter)).ToLowerInvariant()
}
