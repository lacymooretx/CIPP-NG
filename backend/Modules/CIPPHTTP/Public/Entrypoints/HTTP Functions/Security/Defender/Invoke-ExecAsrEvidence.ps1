function Invoke-ExecAsrEvidence {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.ReadWrite
    .SYNOPSIS
        Store ASR event counts from the ControlR collector for ASR readiness
    .DESCRIPTION
        POST { tenantFilter, Reports: [ <Get-AsrEvents output>, ... ] } (or Report: one object). Each report is the
        JSON the ControlR Get-AsrEvents script prints per device: Device, CollectedUtc, WindowHours, RulesOnDevice,
        ConfiguredMix, Detections[{ RuleId, Mode, ProcessName, ... }]. CIPP keeps per-rule counts and up to five
        process names per rule, one row per device per UTC day in its own AsrEvidence table; command lines, paths
        and user names are discarded. Writes only to CIPP's table: nothing in the tenant is changed.
        ListAsrReadiness and the AsrReadiness alert read these rows when advanced hunting is not available.
        Aspendora fork addition (Vikunja CIPP-26).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $TenantFilter = [string]($Request.Body.tenantFilter ?? $Request.Body.TenantFilter ?? $Request.Query.tenantFilter)
    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Pick a single tenant.' } })
    }
    $Reports = @()
    if ($Request.Body.Reports) { $Reports = @($Request.Body.Reports) } elseif ($Request.Body.Report) { $Reports = @($Request.Body.Report) }
    # The collector prints compressed JSON; accept it as a string too.
    $Reports = @($Reports | ForEach-Object { if ($_ -is [string]) { $_ | ConvertFrom-Json -ErrorAction SilentlyContinue } else { $_ } } | Where-Object { $_ })
    if ($Reports.Count -eq 0) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Reports (or Report) is required: the Get-AsrEvents JSON per device.' } })
    }
    if ($Reports.Count -gt 500) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'At most 500 reports per call.' } })
    }
    try {
        $Key = Get-CIPPAsrEvidenceTenantKey -TenantFilter $TenantFilter
        $Table = Get-CIPPTable -tablename 'AsrEvidence'
        $Stored = 0
        $Rejected = [System.Collections.Generic.List[string]]::new()
        foreach ($R in $Reports) {
            try {
                $Row = ConvertTo-CIPPAsrEvidenceRow -TenantFilter $Key -Report $R
                Add-CIPPAzDataTableEntity @Table -Entity $Row -Force | Out-Null
                $Stored++
            } catch {
                $Rejected.Add("$([string]$R.Device): $($_.Exception.Message)")
            }
        }
        $Msg = "Stored ASR evidence for $Stored device(s)" + $(if ($Rejected.Count) { "; rejected $($Rejected.Count): $($Rejected -join '; ')" } else { '' })
        Write-LogMessage -headers $Request.Headers -API $Request.Params.CIPPEndpoint -tenant $Key -message $Msg -Sev 'Info'
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = @{ Results = $Msg; Stored = $Stored; Rejected = @($Rejected) } })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API $Request.Params.CIPPEndpoint -tenant $TenantFilter -message "Storing ASR evidence failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $($ErrorMessage.NormalizedError)" } })
    }
}
