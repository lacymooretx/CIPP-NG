function Invoke-ListDefenderPendingRemediation {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Security.Alert.Read
    .SYNOPSIS
        Defender automated investigation remediations waiting for approval (Action Center pending)
    .DESCRIPTION
        Unresolved Defender alerts from the last LookbackDays (default 90) whose automated investigation is in
        pendingApproval, with age since the alert was created, the number of evidence actions awaiting approval
        and the incident link. Source=MDO|MDE|All (default All). MinAgeHours (default 24) sets OverThreshold.
        Also returns the MDO automation setting as Manual: soft delete for similar files / URLs is configured only
        in the Defender portal and no cmdlet or Graph API exposes it. tenantFilter=AllTenants returns one summary
        row per tenant (Tenant, PendingCount, OverThresholdCount, Oldest). Report only.
        Aspendora fork addition (Vikunja CIPP-31).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    if (-not $TenantFilter) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'tenantFilter is required.' } })
    }
    $Source = [string]($Request.Query.Source ?? $Request.Body.Source ?? 'All')
    if ($Source -notin @('All', 'MDO', 'MDE')) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Source must be All, MDO or MDE.' } })
    }
    $Ints = @{ LookbackDays = 90; MinAgeHours = 24 }
    foreach ($Name in @('LookbackDays', 'MinAgeHours')) {
        $Raw = [string]($Request.Query.$Name ?? $Request.Body.$Name)
        if (-not $Raw) { continue }
        $Parsed = 0
        if (-not [int]::TryParse($Raw, [ref]$Parsed) -or $Parsed -lt 1 -or $Parsed -gt 180 * 24) {
            return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = "$Name must be a positive whole number." } })
        }
        $Ints[$Name] = $Parsed
    }
    $Ints.LookbackDays = [math]::Min($Ints.LookbackDays, 180)
    try {
        if ($TenantFilter -ne 'AllTenants') {
            $Report = Get-CIPPDefenderPendingRemediation -TenantFilter $TenantFilter -LookbackDays $Ints.LookbackDays -MinAgeHours $Ints.MinAgeHours -Source $Source
            return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Report })
        }
        $Rows = foreach ($T in @(Get-Tenants)) {
            $Domain = [string]$T.defaultDomainName
            try {
                $R = Get-CIPPDefenderPendingRemediation -TenantFilter $Domain -LookbackDays $Ints.LookbackDays -MinAgeHours $Ints.MinAgeHours -Source $Source
                $Oldest = @($R.Alerts) | Select-Object -First 1
                [pscustomobject]@{ Tenant = $Domain; PendingCount = $R.PendingCount; OverThresholdCount = $R.OverThresholdCount; Oldest = [string]$Oldest.Created; OldestTitle = [string]$Oldest.Title; Error = '' }
            } catch {
                [pscustomobject]@{ Tenant = $Domain; PendingCount = $null; OverThresholdCount = $null; Oldest = ''; OldestTitle = ''; Error = (Get-CippException -Exception $_).NormalizedError }
            }
        }
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = @($Rows) })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API $Request.Params.CIPPEndpoint -tenant $TenantFilter -message "Pending remediation lookup failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $($ErrorMessage.NormalizedError)" } })
    }
}
