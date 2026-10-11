function Get-HuduCompanyId {
    <#
    .SYNOPSIS
    Resolves a CIPP tenant to its mapped Hudu company id.

    .DESCRIPTION
    Uses the Hudu extension's tenant mapping table (Settings -> Integrations -> Hudu ->
    Mappings). Returns $null when the tenant has not been mapped; callers surface that
    rather than swallow it, because an unmapped tenant means documentation silently
    stops being written.

    Aspendora fork addition (IT Glue -> Hudu migration, 2026-10).

    .PARAMETER TenantFilter
    Tenant default domain name or customer id.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantFilter
    )

    try {
        $Tenant = Get-Tenants -TenantFilter $TenantFilter | Select-Object -First 1
        $CustomerId = if ($Tenant.customerId) { $Tenant.customerId } else { $TenantFilter }

        $Mapping = Get-ExtensionMapping -Extension 'Hudu' | Where-Object { $_.RowKey -eq $CustomerId } | Select-Object -First 1
        if (-not $Mapping -or [string]::IsNullOrWhiteSpace($Mapping.IntegrationId)) {
            return $null
        }

        return [PSCustomObject]@{
            CompanyId   = $Mapping.IntegrationId
            CompanyName = $Mapping.IntegrationName
        }
    } catch {
        Write-LogMessage -API 'Hudu' -message "Failed to resolve the Hudu company for $($TenantFilter): $($_.Exception.Message)" -Sev 'Error' -tenant $TenantFilter
        return $null
    }
}
