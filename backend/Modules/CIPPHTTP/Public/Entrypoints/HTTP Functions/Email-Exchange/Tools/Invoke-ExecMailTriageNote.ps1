function Invoke-ExecMailTriageNote {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Exchange.Mailbox.ReadWrite
    .SYNOPSIS
        Posts a mail triage evidence bundle as an internal note on an existing ConnectWise Manage ticket
    .DESCRIPTION
        Body: tenantFilter, TicketId (the ConnectWise ticket number), and Bundle (the ListMailTriage result). Without a
        Bundle, the triage is run again from Recipient / Sender / Hours. The note is Markdown, posted to the Internal
        Analysis tab with processNotifications off (no ConnectWise email). Refuses when the ticket belongs to a
        different company than the tenant's ConnectWise mapping, unless Force=true. Preview=true returns the note text
        without posting. Changes nothing in the tenant. Aspendora fork addition (Vikunja CIPP-38).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = [string]($Request.Body.tenantFilter ?? $Request.Query.tenantFilter)
    $TicketIn = "$($Request.Body.TicketId)".Trim().TrimStart('#')
    $Preview = ConvertTo-CIPPBoolean -Value ($Request.Body.Preview ?? $false)
    $Force = ConvertTo-CIPPBoolean -Value ($Request.Body.Force ?? $false)
    $TicketId = 0
    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Pick a single tenant.' } })
    }
    if (-not $Preview -and -not ([int]::TryParse($TicketIn, [ref]$TicketId) -and $TicketId -gt 0)) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = "'$TicketIn' is not a ConnectWise ticket number." } })
    }

    try {
        $Bundle = $Request.Body.Bundle
        if ($Bundle -is [string] -and $Bundle) { $Bundle = $Bundle | ConvertFrom-Json -Depth 20 }
        if (-not $Bundle -or -not $Bundle.Steps) {
            $Recipient = [string]($Request.Body.Recipient.value ?? $Request.Body.Recipient)
            if (-not $Recipient) {
                return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Send the triage Bundle, or the Recipient to run it again.' } })
            }
            $Hours = if ($Request.Body.Hours) { [math]::Min(240, [math]::Max(1, [int]$Request.Body.Hours)) } else { 48 }
            $Bundle = Get-CIPPMailTriage -TenantFilter $TenantFilter -Recipient $Recipient -Sender ([string]$Request.Body.Sender) -Hours $Hours
        }
        if ($Bundle.Tenant -and [string]$Bundle.Tenant -ne $TenantFilter) {
            return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = "The bundle is for $($Bundle.Tenant), not $TenantFilter." } })
        }
        $Text = ConvertTo-CIPPMailTriageNote -Bundle $Bundle
        if ($Preview) {
            return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = @{ Results = 'Preview only; nothing posted.'; Note = $Text } })
        }

        # The tenant's ConnectWise company, so a note cannot land on another client's ticket.
        $ExpectedCompanyId = 0
        if (-not $Force) {
            $CustomerId = (Get-Tenants -TenantFilter $TenantFilter).customerId
            $MappingTable = Get-CIPPTable -TableName CippMapping
            $Mapping = Get-CIPPAzDataTableEntity @MappingTable -Filter "PartitionKey eq 'ConnectWiseMapping' and RowKey eq '$CustomerId'"
            $Mapped = @($Mapping.IntegrationId | Where-Object { $_ }) | Select-Object -Last 1
            if ($Mapped) { [void][int]::TryParse("$Mapped", [ref]$ExpectedCompanyId) }
        }
        $Result = Add-ConnectWiseTicketNote -TicketId $TicketId -Text $Text -NoteType 'Internal' -ExpectedCompanyId $ExpectedCompanyId
        $Message = $Result.Message
        if ($Result.Success -and -not $Force -and $ExpectedCompanyId -eq 0) { $Message += ' (This tenant has no ConnectWise company mapping, so the ticket company was not checked.)' }
        Write-LogMessage -headers $Request.Headers -API 'MailTriage' -tenant $TenantFilter -message $Message -Sev $(if ($Result.Success) { 'Info' } else { 'Warning' })
        $Code = if ($Result.Success) { [HttpStatusCode]::OK } else { [HttpStatusCode]::BadRequest }
        return ([HttpResponseContext]@{ StatusCode = $Code; Body = @{ Results = $Message; NoteId = $Result.NoteId } })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'MailTriage' -tenant $TenantFilter -message "Posting triage note failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $($ErrorMessage.NormalizedError)" } })
    }
}
