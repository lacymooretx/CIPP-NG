function Invoke-ExecSignInExplanationNote {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.User.ReadWrite
    .SYNOPSIS
        Posts a sign-in failure explanation as an internal note on an existing ConnectWise Manage ticket (preview by default)
    .DESCRIPTION
        Body: tenantFilter, TicketId (the ConnectWise ticket number), Bundle (the ListSignInExplanation result) and
        Preview. Without a Bundle the explanation is run again from userPrincipalName / correlationId / hours.
        Preview defaults to true and returns the note text without posting; send Preview=false to post. The note is
        Markdown on the Internal Analysis tab with processNotifications off (no ConnectWise email, not on the
        customer portal). Refused unless the tenant has a ConnectWise company mapping and the ticket belongs to that
        company; unlike the mail triage note there is no Force override. Changes nothing in the tenant.
        Aspendora fork addition (Vikunja CIPP-10).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = [string]($Request.Body.tenantFilter ?? $Request.Query.tenantFilter)
    $TicketIn = "$($Request.Body.TicketId)".Trim().TrimStart('#')
    $Preview = ConvertTo-CIPPBoolean -Value ($Request.Body.Preview ?? $true)
    $TicketId = 0
    $Reply = { param($Code, $Body) [HttpResponseContext]@{ StatusCode = $Code; Body = $Body } }
    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return (& $Reply ([HttpStatusCode]::BadRequest) @{ Results = 'Pick a single tenant.' })
    }
    if (-not $Preview -and -not ([int]::TryParse($TicketIn, [ref]$TicketId) -and $TicketId -gt 0)) {
        return (& $Reply ([HttpStatusCode]::BadRequest) @{ Results = "'$TicketIn' is not a ConnectWise ticket number." })
    }

    try {
        $Bundle = $Request.Body.Bundle
        if ($Bundle -is [string] -and $Bundle) { $Bundle = $Bundle | ConvertFrom-Json -Depth 30 }
        if (-not $Bundle -or (-not $Bundle.SignIns -and -not $Bundle.LicenseRequired -and -not $Bundle.Headline)) {
            $Upn = [string]($Request.Body.userPrincipalName.value ?? $Request.Body.userPrincipalName)
            $CorrelationId = [string]$Request.Body.correlationId
            if (-not $Upn -and -not $CorrelationId) {
                return (& $Reply ([HttpStatusCode]::BadRequest) @{ Results = 'Send the explanation Bundle, or userPrincipalName / correlationId to run it again.' })
            }
            $Params = @{ TenantFilter = $TenantFilter; IncludeNonInteractive = (ConvertTo-CIPPBoolean -Value ($Request.Body.includeNonInteractive ?? $false)) }
            if ($Upn) { $Params.UserPrincipalName = $Upn }
            if ($CorrelationId) { $Params.CorrelationId = $CorrelationId }
            if ($Request.Body.hours -as [int]) { $Params.Hours = [math]::Min(720, [math]::Max(1, [int]$Request.Body.hours)) }
            $Bundle = Get-CIPPSignInExplanation @Params
        }
        if ($Bundle.Tenant -and [string]$Bundle.Tenant -ne $TenantFilter) {
            return (& $Reply ([HttpStatusCode]::BadRequest) @{ Results = "The explanation is for $($Bundle.Tenant), not $TenantFilter." })
        }
        $Text = ConvertTo-CIPPSignInExplanationNote -Bundle $Bundle
        if ($Preview) {
            return (& $Reply ([HttpStatusCode]::OK) @{ Results = 'Preview only; nothing posted.'; Note = $Text })
        }

        # The tenant's ConnectWise company, so a note about one client's user cannot land on another client's ticket.
        $CustomerId = (Get-Tenants -TenantFilter $TenantFilter).customerId
        $MappingTable = Get-CIPPTable -TableName CippMapping
        $Mapping = Get-CIPPAzDataTableEntity @MappingTable -Filter "PartitionKey eq 'ConnectWiseMapping' and RowKey eq '$CustomerId'"
        $Mapped = @($Mapping.IntegrationId | Where-Object { $_ }) | Select-Object -Last 1
        $ExpectedCompanyId = 0
        if ($Mapped) { [void][int]::TryParse("$Mapped", [ref]$ExpectedCompanyId) }
        if ($ExpectedCompanyId -le 0) {
            return (& $Reply ([HttpStatusCode]::BadRequest) @{ Results = "$TenantFilter has no ConnectWise company mapping, so the ticket's company cannot be checked. Map the tenant under Integrations > ConnectWise first. Nothing was posted." })
        }

        $Result = Add-ConnectWiseTicketNote -TicketId $TicketId -Text $Text -NoteType 'Internal' -ExpectedCompanyId $ExpectedCompanyId
        Write-LogMessage -headers $Request.Headers -API 'SignInExplainer' -tenant $TenantFilter -message $Result.Message -Sev $(if ($Result.Success) { 'Info' } else { 'Warning' })
        $Code = if ($Result.Success) { [HttpStatusCode]::OK } else { [HttpStatusCode]::BadRequest }
        return (& $Reply $Code @{ Results = $Result.Message; NoteId = $Result.NoteId })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'SignInExplainer' -tenant $TenantFilter -message "Posting sign-in explanation note failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return (& $Reply ([HttpStatusCode]::InternalServerError) @{ Results = "Failed: $($ErrorMessage.NormalizedError)" })
    }
}
