function Invoke-ListEntraRecoveryCoverage {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.Administration.Read
    .SYNOPSIS
        Entra recovery coverage per tenant: Entra Backup and Recovery snapshots, CIPP scheduled backup coverage and gaps
    .DESCRIPTION
        Read only. Per tenant: Entra ID licence (Entra Backup and Recovery needs P1 or P2; Business Premium includes P1),
        native snapshot status from v1.0 directory/recovery/snapshots (count, latest, window; needs EntraBackup.Read.All),
        whether a scheduled CIPP backup task covers the tenant, the last CIPP backup and its age, the components it
        includes, and gaps (no backup, disabled task, older than maxBackupAgeDays, Conditional Access or users/groups
        not included). Also counts soft-deleted Conditional Access policies and named locations, which are restorable
        for 30 days but are not listed by Deleted Items. Accepts AllTenants (one Graph batch per tenant).
        Aspendora fork addition (Vikunja CIPP-17).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    # The tenant to report on, or AllTenants for every managed tenant.
    $TenantFilter = $Request.Query.tenantFilter
    # Days after which the last CIPP backup counts as stale. Defaults to 2 (backups run daily).
    $MaxBackupAgeDays = if ($Request.Query.maxBackupAgeDays -as [int]) { [int]$Request.Query.maxBackupAgeDays } else { 2 }
    # true skips the live Graph reads (snapshots, soft-deleted CA objects) and returns licence and CIPP coverage only.
    $SkipLive = $Request.Query.skipLive -eq 'true' -or $Request.Query.skipLive -eq $true

    if (-not $TenantFilter) {
        return ([HttpResponseContext]@{
                StatusCode = [System.Net.HttpStatusCode]::BadRequest
                Body       = @{ Results = 'tenantFilter is required (a tenant or AllTenants).' }
            })
    }

    try {
        # Tenant access (including whether AllTenants is allowed) is enforced by the router for this role.
        $Body = Get-CIPPEntraRecoveryCoverage -TenantFilter $TenantFilter -MaxBackupAgeDays $MaxBackupAgeDays -SkipLive:$SkipLive
        $StatusCode = [System.Net.HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Failed to build the Entra recovery coverage report: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [System.Net.HttpStatusCode]::InternalServerError
        $Body = @{ Results = "Failed to build the Entra recovery coverage report: $($ErrorMessage.NormalizedError)" }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Body
        })
}
