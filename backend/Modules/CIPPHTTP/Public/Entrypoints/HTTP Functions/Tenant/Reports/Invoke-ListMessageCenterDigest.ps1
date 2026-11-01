function Invoke-ListMessageCenterDigest {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.Administration.Read
    .SYNOPSIS
        Deduplicated Message Center digest with each post classified (action required, retirement, security, opt-in, default change) and its deadline
    .DESCRIPTION
        Read only. Reads Microsoft 365 Message Center posts from the CIPP reporting database (cache type
        MessageCenterMessages; a single tenant with nothing cached is read live from Graph), returns each post once
        with the tenants it was posted to, and classifies it: Action required / deadline (Microsoft set an act-by date,
        severity high, Breaking change), Retirement, Security / compliance, New feature off by default / opt-in,
        On by default (admin opt-out) or Informational. Each item carries the deadline as a US Central date, days
        left, whether it is due within deadlineDays, why it is in the digest (New, Updated, Deadline approaching) and
        the admin center link. Body: Items, Summary (counts per category, tenants covered, tenants with no cached
        posts, cache age) and Errors. The MessageCenterDigest alert uses the same rules. Aspendora fork addition
        (Vikunja CIPP-37).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    # The tenant to digest, or AllTenants for every managed tenant (deduplicated, read from the cache).
    $TenantFilter = $Request.Query.tenantFilter
    # Days back to look for new or updated posts. Defaults to 7.
    $Days = if ($Request.Query.days -as [int]) { [int]$Request.Query.days } else { 7 }
    # Posts whose deadline is this many days away or fewer are flagged Due soon and included even if not updated recently. Defaults to 30.
    $DeadlineDays = if ($Request.Query.deadlineDays -as [int]) { [int]$Request.Query.deadlineDays } else { 30 }
    # true to include Informational posts. By default only classified posts are returned.
    $IncludeInformational = ConvertTo-CIPPBoolean $Request.Query.includeInformational

    if ([string]::IsNullOrWhiteSpace($TenantFilter)) {
        return ([HttpResponseContext]@{
                StatusCode = [System.Net.HttpStatusCode]::BadRequest
                Body       = @{ Results = 'tenantFilter is required (a tenant or AllTenants).' }
            })
    }

    try {
        $Body = Get-CIPPMessageCenterDigest -TenantFilter $TenantFilter -Days $Days -DeadlineDays $DeadlineDays -IncludeInformational:$IncludeInformational
        $StatusCode = [System.Net.HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Failed to build the Message Center digest: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [System.Net.HttpStatusCode]::InternalServerError
        $Body = @{ Results = "Failed to build the Message Center digest: $($ErrorMessage.NormalizedError)" }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Body
        })
}
