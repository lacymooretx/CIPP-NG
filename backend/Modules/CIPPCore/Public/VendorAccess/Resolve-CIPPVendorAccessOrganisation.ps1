function Resolve-CIPPVendorAccessOrganisation {
    <#
    .SYNOPSIS
        Returns tenant ID -> organisation display name for the given Entra tenant IDs.
    .DESCRIPTION
        Uses Graph tenantRelationships/findTenantInformationByTenantId from the partner tenant and remembers the answer
        for 30 days in the CippVendorAccessOrgs table, so a weekly all-tenants run costs a handful of lookups.
        A failed lookup returns no name; callers fall back to the tenant ID. Aspendora fork addition (Vendor Access).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([string[]]$TenantIds = @())

    $Result = @{}
    $Ids = @($TenantIds | Where-Object { $_ -match '^[0-9a-fA-F-]{36}$' } | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
    if ($Ids.Count -eq 0) { return $Result }
    $Table = Get-CIPPTable -TableName 'CippVendorAccessOrgs'
    $Cached = @{}
    try { foreach ($Row in @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Org'")) { $Cached[[string]$Row.RowKey] = $Row } } catch {}
    $Cutoff = [datetime]::UtcNow.AddDays(-30)
    foreach ($Id in $Ids) {
        $Row = $Cached[$Id]
        if ($Row -and $Row.Name -and $Row.Timestamp -and ([datetimeoffset]$Row.Timestamp).UtcDateTime -gt $Cutoff) {
            $Result[$Id] = [string]$Row.Name
            continue
        }
        try {
            $Info = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/tenantRelationships/findTenantInformationByTenantId(tenantId='$Id')" -tenantid $env:TenantID -NoAuthCheck $true -ErrorAction Stop
            if ($Info.displayName) {
                $Name = if ($Info.defaultDomainName) { "$($Info.displayName) ($($Info.defaultDomainName))" } else { [string]$Info.displayName }
                $Result[$Id] = $Name
                Add-CIPPAzDataTableEntity @Table -Entity @{ PartitionKey = 'Org'; RowKey = $Id; Name = $Name; Domain = [string]$Info.defaultDomainName } -Force | Out-Null
            }
        } catch {
            if ($Row.Name) { $Result[$Id] = [string]$Row.Name }
        }
    }
    return $Result
}
