function Invoke-ListEwsStatus {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Exchange.Mailbox.ReadWrite
    .SYNOPSIS
        Exchange Web Services (EWS) status for a tenant, with an optional one-click pin
    .DESCRIPTION
        Default: EwsEnabled (True / False / unset), the apps holding EWS permissions (full_access_as_app or
        EWS.AccessAsUser.All) and findings. IncludeUsage=true also scans 7 days of the audit log for EWS mailbox reads
        (slow). Action=Pin sets EwsEnabled to True so Microsoft's rollout cannot switch EWS off underneath those apps;
        it takes about an hour to apply. Aspendora fork addition (Vikunja CIPP-29).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    $Action = [string]($Request.Query.Action ?? $Request.Body.Action ?? 'Report')
    $IncludeUsage = ($Request.Query.IncludeUsage ?? $Request.Body.IncludeUsage) -eq $true
    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Pick a single tenant.' } })
    }
    try {
        if ($Action -eq 'Pin') {
            $null = New-ExoRequest -tenantid $TenantFilter -cmdlet 'Set-OrganizationConfig' -cmdParams @{ EwsEnabled = $true } -useSystemMailbox $true
            $Now = (New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-OrganizationConfig').EwsEnabled
            Write-LogMessage -headers $Request.Headers -API 'EWS' -tenant $TenantFilter -message "Pinned EwsEnabled to True (read back: $Now)" -Sev 'Info'
            return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = @{ Results = "EwsEnabled set to True (read back: $Now). Allow about an hour before EWS works again if it had been switched off." } })
        }
        $Report = Get-CIPPEwsStatus -TenantFilter $TenantFilter -IncludeUsage:$IncludeUsage
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Report })
    } catch {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $((Get-CippException -Exception $_).NormalizedError)" } })
    }
}
