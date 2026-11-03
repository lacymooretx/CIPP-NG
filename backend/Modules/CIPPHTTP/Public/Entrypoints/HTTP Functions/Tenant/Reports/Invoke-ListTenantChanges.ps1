function Invoke-ListTenantChanges {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.Reports.Read
    .SYNOPSIS
        What changed in one tenant: new, reopened and resolved alerts, new and fixed tests, Secure Score moves and Message Center deadlines
    .DESCRIPTION
        Read only. Assembles the change record from data CIPP already holds: the AlertLifecycle table, the stored test
        results and posture snapshots, and the cached Secure Score and Message Center posts. Nothing is stored and no
        tenant is called. Each source reports its own Status, and one that failed is CouldNotRead with null counts,
        never zero. Body: Verdict (Changes, Quiet, Incomplete, Unreadable), Summary, Sources, Changes and
        OlderTestChanges (differences from a posture snapshot too old to date within the window). Returns 200 when every
        source was read, 207 when some failed and 500 when all failed, each with the same body. Aspendora fork addition
        (Vikunja CIPP-58).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    # The tenant to report on. A single tenant is required.
    $TenantFilter = $Request.Query.tenantFilter
    # Days back to look. Defaults to 1, at most 30.
    $Days = $Request.Query.days -as [int]
    if (-not $Days -or $Days -lt 1) { $Days = 1 }
    if ($Days -gt 30) { $Days = 30 }

    if ([string]::IsNullOrWhiteSpace($TenantFilter) -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'Select a single tenant. The change record is per tenant.' }
            })
    }

    try {
        $Body = Get-CIPPTenantChanges -TenantFilter $TenantFilter -Days $Days
        $StatusCode = Get-CippBulkStatusCode -Total $Body.Summary.SourcesTotal -Failed $Body.Summary.SourcesFailed
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Failed to build the change record: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = Get-CippErrorStatusCode -ErrorRecord $_
        $Body = @{ Results = "Failed to build the change record: $($ErrorMessage.NormalizedError)" }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Body
        })
}
