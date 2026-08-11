function Get-ITGlueOrganizationId {
    <#
    .SYNOPSIS
    Resolves a CIPP tenant to its mapped IT Glue organization id.

    .DESCRIPTION
    Uses the IT Glue extension's existing tenant mapping table (Settings -> Integrations ->
    IT Glue -> Mappings). Returns $null when the tenant has not been mapped, which callers
    are expected to surface rather than swallow -- an unmapped tenant means documentation
    silently stops being written.

    Aspendora fork addition.

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

        $Mapping = Get-ExtensionMapping -Extension 'ITGlue' | Where-Object { $_.RowKey -eq $CustomerId } | Select-Object -First 1
        if (-not $Mapping -or [string]::IsNullOrWhiteSpace($Mapping.IntegrationId)) {
            return $null
        }

        return [PSCustomObject]@{
            OrganizationId   = $Mapping.IntegrationId
            OrganizationName = $Mapping.IntegrationName
        }
    } catch {
        Write-LogMessage -API 'ITGlue' -message "Failed to resolve the IT Glue organization for $($TenantFilter): $($_.Exception.Message)" -Sev 'Error' -tenant $TenantFilter
        return $null
    }
}
