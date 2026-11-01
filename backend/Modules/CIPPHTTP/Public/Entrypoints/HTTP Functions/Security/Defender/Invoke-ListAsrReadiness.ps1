function Invoke-ListAsrReadiness {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .SYNOPSIS
        ASR audit-to-block readiness per rule for one tenant
    .DESCRIPTION
        Lists every Attack Surface Reduction rule with its effective mode across the tenant's assigned ASR policies
        (Block / Audit / Warn / Off / NotConfigured / Conflict), the audit and block hits over the last WindowDays
        (default 14, 1-90) and a recommendation: ReadyForBlock (no audit hits over the whole window), KeepAudit,
        AlreadyBlock, NotConfigured or FixConflict. Hits come from Defender advanced hunting where the tenant has
        the device tables, otherwise from the ControlR collector rows posted to ExecAsrEvidence. With no evidence
        source no rule is called ready. SkipHunting=true skips the hunting attempt.
        Report only: nothing is changed. Aspendora fork addition (Vikunja CIPP-26).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Pick a single tenant.' } })
    }
    $WindowDays = 14
    $RawWindow = [string]($Request.Query.WindowDays ?? $Request.Body.WindowDays)
    if ($RawWindow) {
        $Parsed = 0
        if (-not [int]::TryParse($RawWindow, [ref]$Parsed) -or $Parsed -lt 1 -or $Parsed -gt 90) {
            return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'WindowDays must be a whole number from 1 to 90.' } })
        }
        $WindowDays = $Parsed
    }
    $SkipHunting = ConvertTo-CIPPBoolean ($Request.Query.SkipHunting ?? $Request.Body.SkipHunting)
    try {
        $Report = Get-CIPPAsrReadiness -TenantFilter $TenantFilter -WindowDays $WindowDays -SkipHunting:($SkipHunting -eq $true)
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Report })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API $Request.Params.CIPPEndpoint -tenant $TenantFilter -message "ASR readiness failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $($ErrorMessage.NormalizedError)" } })
    }
}
