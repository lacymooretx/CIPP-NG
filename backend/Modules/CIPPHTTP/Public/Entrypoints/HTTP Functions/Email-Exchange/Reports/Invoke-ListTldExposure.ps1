function Invoke-ListTldExposure {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Exchange.SpamFilter.Read
    .SYNOPSIS
        Audit-only: what an abused-TLD block would have stopped (inbound) or broken (outbound) in one tenant
    .DESCRIPTION
        Reads Get-MessageTraceV2 for the last Days days (default 10, max 90; 10-day windows, 5000-row pages, at most
        MaxPages pages, default 10) and counts mail from senders under the abused TLDs (Config/AbusedTlds.json, or
        a Tlds override such as "xyz,top") and mail users sent to those TLDs - a *.TLD sender block stops both.
        Returns per-TLD counts and the top sender / recipient domains. Truncated=true means the page cap was hit
        and CoveredFromUtc is how far back it got; use Historical Search for a full 90-day report.
        Changes nothing. Aspendora fork addition (Vikunja CIPP-30).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Pick a single tenant. Message trace is too heavy to run across all tenants in one request.' } })
    }
    $Days = 10
    $DaysIn = $Request.Query.Days ?? $Request.Body.Days
    if ($DaysIn) { $Days = [math]::Min(90, [math]::Max(1, [int]$DaysIn)) }
    $MaxPages = 10
    $PagesIn = $Request.Query.MaxPages ?? $Request.Body.MaxPages
    if ($PagesIn) { $MaxPages = [math]::Min(60, [math]::Max(1, [int]$PagesIn)) }
    $TldsIn = [string]($Request.Query.Tlds ?? $Request.Body.Tlds)

    try {
        $Catalog = Get-CIPPAbusedTldCatalog
        $Tlds = if ($TldsIn) { @($TldsIn -split '[,;\s]+' | ForEach-Object { $_.Trim().TrimStart('*').TrimStart('.') } | Where-Object { $_ }) } else { @($Catalog.Tlds.tld) }
        $Accepted = @(New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-AcceptedDomain' | ForEach-Object { [string]$_.DomainName })

        $End = [DateTime]::UtcNow
        $Trace = Get-CIPPMessageTraceRange -TenantFilter $TenantFilter -StartUtc $End.AddDays(-$Days) -EndUtc $End -MaxPages $MaxPages
        $Exposure = Measure-CIPPTldExposure -Rows $Trace.Rows -Tlds $Tlds -AcceptedDomains $Accepted

        $Risk = @{}
        foreach ($T in $Catalog.Tlds) { $Risk[$T.tld] = $T }
        foreach ($Row in $Exposure.ByTld) {
            $Meta = $Risk[$Row.Tld]
            $Row | Add-Member -NotePropertyName 'SenderRisk' -NotePropertyValue ($Meta.senderRisk ?? 'Unknown') -Force
            $Row | Add-Member -NotePropertyName 'UrlRisk' -NotePropertyValue ($Meta.urlRisk ?? 'Unknown') -Force
        }

        $Covered = ConvertTo-CIPPCentralTime -Value $Trace.OldestUtc
        $Notes = [System.Collections.Generic.List[string]]::new()
        $Notes.Add('Audit only: nothing was changed. A *.TLD sender block quarantines inbound mail from the TLD AND makes Microsoft reject outbound mail to it (NDR 550 5.7.703) - the outbound counts are what would break.')
        $Notes.Add('URL blocks (*.TLD/*) act on links in message bodies, which message trace cannot see. Use Threat Explorer / URL click reports for link exposure.')
        if ($Trace.Truncated) { $Notes.Add("Stopped at the $MaxPages-page cap ($($Trace.Rows.Count) rows); data covers back to $($Covered.Display). Raise MaxPages or run a Historical Search for the full window.") }

        $Body = [pscustomobject]@{
            Tenant             = $TenantFilter
            Days               = $Days
            WindowStart        = ConvertTo-CIPPCentralTime -Value $Trace.StartUtc
            WindowEnd          = ConvertTo-CIPPCentralTime -Value $Trace.EndUtc
            CoveredFrom        = $Covered
            Truncated          = [bool]$Trace.Truncated
            Pages              = $Trace.Pages
            RowsScanned        = $Exposure.RowsScanned
            InboundMessages    = $Exposure.InboundMessages
            OutboundMessages   = $Exposure.OutboundMessages
            TldsWithTraffic    = @($Exposure.TldsWithTraffic)
            ByTld              = @($Exposure.ByTld)
            TopSenderDomains   = @($Exposure.TopSenderDomains)
            TopOutboundDomains = @($Exposure.TopOutboundDomains)
            CatalogVersion     = $Catalog.Version
            Notes              = @($Notes)
        }
        Write-LogMessage -headers $Request.Headers -API 'ListTldExposure' -tenant $TenantFilter -message "TLD exposure audit: $($Exposure.InboundMessages) inbound / $($Exposure.OutboundMessages) outbound messages over $Days days (truncated: $($Trace.Truncated))" -Sev 'Info'
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Body })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'ListTldExposure' -tenant $TenantFilter -message "TLD exposure audit failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $($ErrorMessage.NormalizedError)" } })
    }
}
