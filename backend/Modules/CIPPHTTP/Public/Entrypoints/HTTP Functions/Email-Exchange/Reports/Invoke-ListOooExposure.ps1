function Invoke-ListOooExposure {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Exchange.Mailbox.Read
    .SYNOPSIS
        Out-of-office exposure: mailboxes with a live external auto-reply and what the message gives away
    .DESCRIPTION
        Read only. Lists the user and shared mailboxes in one tenant whose automatic reply is Enabled, or Scheduled and
        inside its window, with ExternalAudience All or Known. The external message is reduced to text and flagged for
        colleague (accepted-domain) and external email addresses, phone numbers, travel terms, return dates, job titles
        and finance cues (invoices, payments, wires, payroll). Severity: High = audience All and the message names a
        colleague address, a phone number or a finance cue; Medium = audience All otherwise; Low = audience Known.
        Each row carries the schedule as UTC, Unix seconds and US Central text, a redacted snippet (addresses and phone
        numbers masked) and the full message text. A tenant without Exchange Online returns Status NoExchange.
        Settings are read with two EXO bulk requests (state for every mailbox, then messages for live ones only).
        Single tenant only. Aspendora fork addition (Vikunja CIPP-40).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    # The tenant to check. AllTenants is not supported.
    $TenantFilter = $Request.Query.tenantFilter
    # true to also list scheduled replies that start within the next upcomingDays. Defaults to false.
    $IncludeUpcoming = [string]$Request.Query.includeUpcoming -in @('true', '1', 'yes')
    # Days ahead to look for upcoming scheduled replies when includeUpcoming is true (1-90). Defaults to 14.
    $UpcomingDays = if (($Request.Query.upcomingDays -as [int]) -ge 1 -and ($Request.Query.upcomingDays -as [int]) -le 90) { [int]$Request.Query.upcomingDays } else { 14 }

    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{
                StatusCode = [System.Net.HttpStatusCode]::BadRequest
                Body       = @{ Results = 'Select a single tenant: auto-reply settings are read live per tenant.' }
            })
    }

    try {
        $Body = Get-CIPPOooExposure -TenantFilter $TenantFilter -IncludeUpcoming:$IncludeUpcoming -UpcomingDays $UpcomingDays
        $StatusCode = [System.Net.HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Failed to check out-of-office exposure: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [System.Net.HttpStatusCode]::InternalServerError
        $Body = @{ Results = "Failed to check out-of-office exposure: $($ErrorMessage.NormalizedError)" }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Body
        })
}
