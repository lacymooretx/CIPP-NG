function Invoke-ListMailTriage {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Exchange.Mailbox.Read
    .SYNOPSIS
        Guided "mail not received / delayed" triage for one recipient, returned as an evidence bundle
    .DESCRIPTION
        Inputs: tenantFilter, Recipient (UPN or address), optional Sender, optional Hours (default 48, max 240).
        Runs, in order: Exchange Online service health, message trace, quarantine, mail flow rules that name the
        sender/recipient/domain, inbox rules including hidden ones, sender/delivery restrictions and forwarding,
        mailbox quota and archive, Tenant Allow/Block List and the user's Blocked Senders, and account sign-in state.
        Each step returns Status (OK / Problem / Unknown), a plain-English Summary, Findings and Evidence; the bundle
        has an Overall status and Summary. Times are US Central (America/Chicago) with the zone stated and UTC
        alongside. Read-only. Post the result to a ConnectWise ticket with ExecMailTriageNote.
        Aspendora fork addition (Vikunja CIPP-38).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = [string]($Request.Body.tenantFilter ?? $Request.Query.tenantFilter)
    $Recipient = [string]($Request.Body.Recipient.value ?? $Request.Body.Recipient ?? $Request.Query.Recipient)
    $Sender = [string]($Request.Body.Sender ?? $Request.Query.Sender)
    $HoursIn = $Request.Body.Hours ?? $Request.Query.Hours
    $Hours = if ($HoursIn) { [math]::Min(240, [math]::Max(1, [int]$HoursIn)) } else { 48 }

    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants' -or -not $Recipient) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Pick a single tenant and give the recipient address.' } })
    }
    try {
        $Bundle = Get-CIPPMailTriage -TenantFilter $TenantFilter -Recipient $Recipient -Sender $Sender -Hours $Hours
        Write-LogMessage -headers $Request.Headers -API 'MailTriage' -tenant $TenantFilter -message "Mail triage for $($Bundle.Recipient)$(if ($Sender) { " from $Sender" }): $($Bundle.Overall)" -Sev 'Info'
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Bundle })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'MailTriage' -tenant $TenantFilter -message "Mail triage failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $($ErrorMessage.NormalizedError)" } })
    }
}
