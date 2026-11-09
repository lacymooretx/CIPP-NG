function Invoke-ListVendorAccess {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.Application.Read
    .SYNOPSIS
        Vendor Access report: every outside party with standing access, per tenant or across all tenants
    .DESCRIPTION
        Lists foreign apps (with permissions, risk, new credentials and last sign-in), groups and accounts from other
        organisations holding directory roles (other partners' GDAP/DAP), guests holding directory roles and
        cross-tenant service-provider partners. Returns { GeneratedAt, Summary, Tenants, Items }. Reads the saved
        snapshot (rebuilt weekly, and whenever Refresh is set); a tenant with no snapshot yet is built on the spot.
        Items include those removed in the last 7 days (Removed = true). Aspendora fork addition (Vendor Access).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    # One tenant, or AllTenants (the default).
    $TenantFilter = if ($Request.Query.tenantFilter) { [string]$Request.Query.tenantFilter } else { 'AllTenants' }
    # Rebuild the snapshot before returning it. Across all tenants this takes a minute or two.
    $Refresh = $Request.Query.Refresh -eq $true

    try {
        $Body = if ($Refresh) {
            Update-CIPPVendorAccessSnapshot -TenantFilter $TenantFilter
        } else {
            $Snapshot = Get-CIPPVendorAccessSnapshot -TenantFilter $TenantFilter
            if (@($Snapshot.Tenants).Count -eq 0) { Update-CIPPVendorAccessSnapshot -TenantFilter $TenantFilter } else { $Snapshot }
        }
        $StatusCode = [System.Net.HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Failed to build the vendor access report: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [System.Net.HttpStatusCode]::InternalServerError
        $Body = @{ Results = "Failed to build the vendor access report: $($ErrorMessage.NormalizedError)" }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Body
        })
}
