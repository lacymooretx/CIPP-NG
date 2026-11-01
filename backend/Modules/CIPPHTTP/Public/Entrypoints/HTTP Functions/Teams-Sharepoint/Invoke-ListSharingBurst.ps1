function Invoke-ListSharingBurst {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Sharepoint.Site.Read
    .SYNOPSIS
        Lists lateral-phishing and mass external sharing findings for a tenant, with ready parameters for the existing sharing-link cleanup actions
    .DESCRIPTION
        Runs the same detection as the SharingBurst alert (Get-CIPPSharingBurstReport) on demand and returns every
        finding, not only new ones: UserBurst (one account sharing with many outsiders within the window), FileSpread
        (one item reaching many outsiders over the lookback) and LinkMailBlast (sharing links created, then a spike in
        new external mail recipients). Each finding has the preceding risky/unfamiliar sign-in, the send-spread
        comparison, and Remediation: parameter sets for ExecRemoveSharingLink, ExecBulkRemoveSharingLinks and
        ExecSetOneDriveSharing. Nothing is changed - the caller decides what to run.

        Query/body: tenantFilter (required), hours (lookback, 1-168, default 24), recipients (default 25),
        windowMinutes (default 60), fileRecipients (default 25), sendSpread (default 25), allowList (comma
        separated UPNs), resolve (true = read link permission ids live from Graph for items not in the
        sharing-links cache; read only). Aspendora fork addition (Vikunja CIPP-13).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $Get = { param($Name) $Request.Body.$Name ?? $Request.Query.$Name }
    $TenantFilter = [string](& $Get 'tenantFilter')
    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'tenantFilter (a single tenant) is required.' } })
    }
    $IntOr = { param($Value, $Default) $Parsed = 0; if ([int]::TryParse([string]$Value, [ref]$Parsed) -and $Parsed -gt 0) { $Parsed } else { $Default } }

    try {
        $Params = @{
            TenantFilter           = $TenantFilter
            LookbackHours          = [Math]::Min((& $IntOr (& $Get 'hours') 24), 168)
            RecipientThreshold     = & $IntOr (& $Get 'recipients') 25
            WindowMinutes          = & $IntOr (& $Get 'windowMinutes') 60
            FileRecipientThreshold = & $IntOr (& $Get 'fileRecipients') 25
            SendSpreadThreshold    = & $IntOr (& $Get 'sendSpread') 25
            AllowList              = @(([string](& $Get 'allowList')) -split '[,;\s]+' | Where-Object { $_ })
            Resolve                = (ConvertTo-CIPPBoolean -Value (& $Get 'resolve')) -eq $true
        }
        $Report = Get-CIPPSharingBurstReport @Params
        $StatusCode = [HttpStatusCode]::OK
        $Body = [pscustomobject]@{
            Results        = @($Report.Findings)
            EventsAnalysed = $Report.EventsAnalysed
            Complete       = $Report.Complete
            Cap            = $Report.Cap
            Window         = $Report.Window
            Errors         = $Report.Errors
        }
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API $Request.Params.CIPPEndpoint -tenant $TenantFilter -message "Sharing burst report failed: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        $StatusCode = [HttpStatusCode]::InternalServerError
        $Body = @{ Results = "Sharing burst report failed: $($ErrorMessage.NormalizedError)" }
    }

    return ([HttpResponseContext]@{ StatusCode = $StatusCode; Body = $Body })
}
