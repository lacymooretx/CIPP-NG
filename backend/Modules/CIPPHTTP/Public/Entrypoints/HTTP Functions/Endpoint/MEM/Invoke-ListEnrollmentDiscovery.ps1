function Invoke-ListEnrollmentDiscovery {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .SYNOPSIS
        Intune enrollment discovery: CNAME records, MDM user scope and hybrid devices per tenant
    .DESCRIPTION
        For one tenant, or every tenant the caller may see with tenantFilter=AllTenants: the enterpriseenrollment and
        enterpriseregistration CNAMEs of each custom verified domain, the Intune MDM user scope (none / all /
        selected and its groups), Windows and hybrid-joined (GPO / co-management enrolled) device counts, and
        findings flagging tenants still relying on CNAME-based enrollment (CNAME published with scope None or a
        narrow group, CNAME missing where Windows enrollment is used, unexpected targets, hybrid devices that depend
        on the scope). Single tenant returns the report object; AllTenants returns
        @{ Results = @(one report per tenant); Findings = @(flattened, with Tenant); Failed; Skipped }.
        Report only: nothing is changed. Aspendora fork addition (Vikunja CIPP-22).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    if (-not $TenantFilter) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'tenantFilter is required (a tenant or AllTenants).' } })
    }
    try {
        $Sweep = Invoke-CIPPTenantSweep -Request $Request -TenantFilter $TenantFilter -ScriptBlock { param($T) Get-CIPPEnrollmentDiscovery -TenantFilter $T }
        if ($TenantFilter -ne 'AllTenants') {
            return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = @($Sweep.Results)[0] })
        }
        $Findings = @(foreach ($R in $Sweep.Results) {
                foreach ($F in @($R.Findings)) {
                    [pscustomobject]@{ Tenant = $R.Tenant; Severity = $F.Severity; Category = $F.Category; Domain = $F.Domain; MdmScope = $R.MdmScope; Message = $F.Message; Id = $F.Id }
                }
            })
        $Body = [pscustomobject]@{
            Results  = @($Sweep.Results | ForEach-Object { $_ | Select-Object Tenant, MdmScope, MdmScopeGroups, WindowsDeviceCount, HybridDeviceCount, Domains, Errors, @{ n = 'FindingCount'; e = { @($_.Findings).Count } } })
            Findings = $Findings
            Failed   = @($Sweep.Failed)
            Skipped  = @($Sweep.Skipped)
        }
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Body })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API $Request.Params.CIPPEndpoint -tenant $TenantFilter -message "Enrollment discovery failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $($ErrorMessage.NormalizedError)" } })
    }
}
