function Invoke-ListDefenderHardening {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .SYNOPSIS
        Defender for Endpoint hardening posture: Network Protection, Device Control, web content filtering
    .DESCRIPTION
        Per tenant: Network Protection mode across the assigned Settings Catalog / endpoint security policies
        (Block = Pass, Audit = Warn, off / not set / conflicting = Fail), Device Control state (Enforced, Audit,
        EnabledNoRules, Disabled, NotConfigured), and a Manual row for web content filtering, which is
        configured only in the Defender portal and has no API. tenantFilter=AllTenants returns one row per tenant
        and control (Tenant, Control, State, Status, Policies, Detail); a tenant that fails gets an Error row.
        Report only: nothing is changed. Aspendora fork addition (Vikunja CIPP-26).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    if (-not $TenantFilter) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'tenantFilter is required.' } })
    }
    try {
        if ($TenantFilter -ne 'AllTenants') {
            $Report = Get-CIPPDefenderHardening -TenantFilter $TenantFilter
            return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Report })
        }
        $Rows = foreach ($T in @(Get-Tenants)) {
            $Domain = [string]$T.defaultDomainName
            try {
                $R = Get-CIPPDefenderHardening -TenantFilter $Domain
                foreach ($C in @($R.Controls)) {
                    [pscustomobject]@{ Tenant = $Domain; Control = $C.Control; State = $C.State; Status = $C.Status; Policies = $C.Policies; Detail = $C.Detail; Errors = (@($R.Errors) -join '; ') }
                }
            } catch {
                [pscustomobject]@{ Tenant = $Domain; Control = 'All'; State = 'Error'; Status = 'Error'; Policies = ''; Detail = (Get-CippException -Exception $_).NormalizedError; Errors = '' }
            }
        }
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = @($Rows) })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API $Request.Params.CIPPEndpoint -tenant $TenantFilter -message "Defender hardening check failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $($ErrorMessage.NormalizedError)" } })
    }
}
