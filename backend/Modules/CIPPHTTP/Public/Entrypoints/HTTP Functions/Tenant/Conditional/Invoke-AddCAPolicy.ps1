function Invoke-AddCAPolicy {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.ConditionalAccess.ReadWrite
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers

    $Tenants = $Request.body.tenantFilter.value
    if ('AllTenants' -in $Tenants) { $Tenants = (Get-Tenants).defaultDomainName }

    # Aspendora fork addition (Vikunja CIPP-5): a policy that ends up On must pass the lockout pre-flight,
    # per tenant, unless the operator ticked the override (logged by Resolve-CIPPCAPreflightGate).
    $PreflightOverride = $Request.Body.PreflightOverride -eq $true

    $Failed = 0
    $results = foreach ($Tenant in $tenants) {
        try {
            $NewCAPolicy = @{
                Preflight         = 'Enforce'
                PreflightOverride = $PreflightOverride
                replacePattern = $Request.Body.replacename
                Overwrite      = $Request.Body.overwrite
                TenantFilter   = $Tenant
                state          = $Request.Body.NewState
                DisableSD      = $Request.Body.DisableSD
                CreateGroups   = $Request.Body.CreateGroups
                RawJSON        = $Request.Body.RawJSON
                APIName        = $APIName
                Headers        = $Headers
            }
            $CAPolicy = New-CIPPCAPolicy @NewCAPolicy

            "$CAPolicy"
        } catch {
            $Failed++
            "$($_.Exception.Message)"
            continue
        }

    }

    $body = [pscustomobject]@{'Results' = @($results) }

    return ([HttpResponseContext]@{
            StatusCode = Get-CippBulkStatusCode -Total @($Tenants).Count -Failed $Failed
            Body       = $body
        })

}
