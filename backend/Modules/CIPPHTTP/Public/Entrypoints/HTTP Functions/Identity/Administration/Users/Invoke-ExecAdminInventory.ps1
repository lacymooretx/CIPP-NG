function Invoke-ExecAdminInventory {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.User.ReadWrite
    .SYNOPSIS
        Microsoft 365 privileged-role inventory per tenant, written to Hudu as "Microsoft 365 admins — <client>"
    .DESCRIPTION
        Action=Preview (default) returns the inventory and the article HTML for tenantFilter; writes nothing.
        Action=Sync    writes or updates the Hudu article for tenantFilter (or AllTenants) and reads it back.
        Runs weekly on Mondays from Start-BreakGlassProvisionTimer. Aspendora fork addition (onboarding Phase 3).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $Action = [string]($Request.Body.Action ?? $Request.Query.Action ?? 'Preview')
    $TenantFilter = [string]($Request.Body.tenantFilter ?? $Request.Query.tenantFilter)
    if (-not $TenantFilter) { return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'tenantFilter is required (AllTenants allowed for Sync).' } }) }
    try {
        $Results = switch ($Action) {
            'Preview' { if ($TenantFilter -eq 'AllTenants') { throw 'Preview needs a single tenant.' }; Invoke-CIPPAdminInventorySync -TenantFilter $TenantFilter -Preview }
            'Sync' { if ($TenantFilter -eq 'AllTenants') { Invoke-CIPPAdminInventorySync -NoAlert } else { Invoke-CIPPAdminInventorySync -TenantFilter $TenantFilter -NoAlert } }
            default { throw "Unknown Action '$Action'. Use Preview or Sync." }
        }
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = @{ Results = @($Results) } })
    } catch {
        $Err = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'AdminInventory' -tenant $TenantFilter -message "ExecAdminInventory $Action failed: $($Err.NormalizedError)" -Sev 'Error' -LogData $Err
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $($Err.NormalizedError)" } })
    }
}
