function Invoke-ListPostureChange {
    <#
    .SYNOPSIS
        Month-over-month security posture change for a tenant (CIPPTests results and Secure Score).
    .DESCRIPTION
        Compares the tenant's current posture (the stored CIPPTests results and the cached Microsoft Secure Score)
        with the stored posture snapshot from at least minDays (default 25) earlier, falling back to the oldest
        earlier snapshot. Returns Fixed, NewIssues, StillOpen, OpenNow (bucketed DoToday / ThisMonth / LongTerm by
        risk), NoLongerAssessed, AddedTests, RemovedTests, RenamedTests, SecureScore deltas and Counts. HasPrevious
        is false when no earlier snapshot exists yet.

        Read only: this endpoint never stores a snapshot. Snapshots are taken when the Security Posture Change
        report (ReportType PostureChange) runs and by the PostureSnapshot scripted alert (every 30 days).
        Aspendora fork addition (Vikunja CIPP-16).
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.Reports.Read
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $TriggerMetadata.FunctionName
    Write-LogMessage -headers $Request.Headers -API $APIName -message 'Accessed posture change' -Sev 'Debug'

    # Tenant default domain or customerId. A single tenant is required; snapshots are stored per tenant.
    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter
    # Minimum age in days of the preferred baseline snapshot (default 25).
    $MinDays = $Request.Query.minDays ?? $Request.Body.minDays

    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = ConvertTo-Json -InputObject @{ Results = 'Select a single tenant. Posture snapshots are stored per tenant.' }
            })
    }

    $Days = 25
    $Parsed = 0
    if ($null -ne $MinDays -and [int]::TryParse([string]$MinDays, [ref]$Parsed) -and $Parsed -ge 1) { $Days = $Parsed }

    try {
        $Diff = Get-CIPPPostureChange -TenantFilter $TenantFilter -MinDays $Days
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = ConvertTo-Json -Depth 8 -InputObject $Diff
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API $APIName -tenant $TenantFilter -message "Failed to build posture change: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = ConvertTo-Json -InputObject @{ Results = "Failed to build posture change: $($ErrorMessage.NormalizedError)" }
            })
    }
}
