function Invoke-ExecGraphRequest {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        CIPP.Core.ReadWrite
    .DESCRIPTION
        Write-capable generic Microsoft Graph passthrough. Executes an arbitrary Graph
        request (GET/POST/PATCH/PUT/DELETE) against a single tenant. This is the on-demand
        escape hatch for one-off reads and writes that do not yet have a dedicated CIPP
        endpoint. Gated to CIPP.Core.ReadWrite (the write counterpart of ListGraphRequest's
        CIPP.Core.Read); every mutating call is audited. It can reach any Graph endpoint with
        any method, so the underlying SAM/GDAP permissions remain the real safety boundary.

        Parameters may be supplied via query string (GET-style) or request body (POST-style):
          TenantFilter (required) - tenant default domain or customer id
          Endpoint     (required) - relative Graph path (e.g. 'users/{id}') or a full URL
          Method                  - GET (default) | POST | PATCH | PUT | DELETE
          Version                 - 'beta' (default) | 'v1.0'  (ignored if Endpoint is a full URL)
          Body / GraphRequestBody - request body for write methods (object or JSON string)
          AsApp                   - $true to force an application token instead of delegated
          NoPagination / DisablePagination - $true to disable paging on GET

        Writes: a 2xx from Graph is NOT proof the change applied. Graph returns 204 No Content for
        an applied write, and for several resources it also ACCEPTS AND IGNORES properties it does
        not recognise - same 204, nothing changed, no error. The usual cause is a body written for
        one API version sent to the other: on authorizationPolicy, for example, beta exposes
        `permissionGrantPolicyIdsAssignedToDefaultUserRole` at the top level while v1.0 exposes it
        as `defaultUserRolePermissions.permissionGrantPoliciesAssigned`. Match the body to the
        Version you pass, and always read the resource back to confirm a write landed.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers

    # Accept params from body (POST-style) first, falling back to query (GET-style).
    $TenantFilter = $Request.Body.TenantFilter ?? $Request.Query.TenantFilter
    $Endpoint = $Request.Body.Endpoint ?? $Request.Query.Endpoint
    $Method = ($Request.Body.Method ?? $Request.Query.Method ?? 'GET').ToString().ToUpper()
    $Version = $Request.Body.Version ?? $Request.Query.Version ?? 'beta'
    $AsAppRaw = $Request.Body.AsApp ?? $Request.Query.AsApp
    # DisablePagination is the name the MCP gateway/openapi spec uses; NoPagination
    # is the native one. Accept either from either transport - previously
    # Body.DisablePagination was never read, so a POST-style caller asking to
    # disable paging was silently paginated through the entire result set (on
    # auditLogs/signIns that is every sign-in in the tenant, i.e. a guaranteed timeout).
    $NoPaginationRaw = $Request.Body.NoPagination ?? $Request.Body.DisablePagination ??
        $Request.Query.NoPagination ?? $Request.Query.DisablePagination
    $GraphBody = $Request.Body.GraphRequestBody ?? $Request.Body.Body

    # Coerce loosely-typed flags (query values arrive as strings) without throwing.
    $TruthyValues = @($true, 'true', 'True', 1, '1', 'yes', 'on')
    $AsApp = $AsAppRaw -in $TruthyValues
    $NoPagination = $NoPaginationRaw -in $TruthyValues

    $ValidMethods = @('GET', 'POST', 'PATCH', 'PUT', 'DELETE')

    # Validation
    if (-not $TenantFilter) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = 'TenantFilter is required.' }
            })
    }
    if (-not $Endpoint) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = 'Endpoint is required.' }
            })
    }
    if ($Method -notin $ValidMethods) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = "Invalid Method '$Method'. Allowed: $($ValidMethods -join ', ')." }
            })
    }

    # Serialize the body up front so a write with nothing to send can be rejected before it
    # reaches Graph. A bodyless PATCH/POST/PUT is not a no-op that happens to be harmless: Graph
    # answers it 2xx with no content, which is indistinguishable from an applied write, so the
    # caller is told a change succeeded that was never even described. DELETE is excluded - it
    # legitimately carries no body.
    $WriteMethods = @('POST', 'PATCH', 'PUT')
    $BodyJson = if ($null -ne $GraphBody -and $GraphBody -ne '') {
        if ($GraphBody -is [string]) { $GraphBody } else { ConvertTo-Json -InputObject $GraphBody -Depth 20 -Compress }
    } else { $null }

    if ($Method -in $WriteMethods -and -not $BodyJson) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = "Method $Method requires a Body/GraphRequestBody." }
            })
    }

    # Build the full Graph URI. Allow a fully-qualified URL (e.g. a nextLink) to pass through.
    if ($Endpoint -match '^https?://') {
        $Uri = $Endpoint
    } else {
        $Uri = 'https://graph.microsoft.com/{0}/{1}' -f $Version, ($Endpoint -replace '^/+', '')
    }

    Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Graph passthrough: $Method $Uri (AsApp: $AsApp)" -Sev 'Debug'

    try {
        if ($Method -eq 'GET') {
            $GetParams = @{
                uri      = $Uri
                tenantid = $TenantFilter
            }
            if ($NoPagination) { $GetParams.noPagination = $true }
            if ($AsApp) { $GetParams.AsApp = $true }
            $Results = New-GraphGetRequest @GetParams
        } else {
            $PostParams = @{
                uri      = $Uri
                tenantid = $TenantFilter
                type     = $Method
            }
            if ($BodyJson) { $PostParams.body = $BodyJson }
            if ($AsApp) { $PostParams.AsApp = $true }
            $Results = New-GraphPOSTRequest @PostParams

            # Audit every mutating call at Info so it shows in the CIPP log. The body LENGTH is
            # recorded, never the body itself - it can carry secrets - so that a write that sent
            # nothing is visible in the log rather than reading as a successful change.
            $BodyLength = if ($BodyJson) { $BodyJson.Length } else { 0 }
            Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Executed Graph $Method against $Endpoint (request body: $BodyLength chars)" -Sev 'Info'
        }

        $StatusCode = [HttpStatusCode]::OK
        $ResponseBody = [pscustomobject]@{ Results = $Results }
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Graph passthrough failed: $Method $Endpoint - $ErrorMessage" -Sev 'Error'
        $StatusCode = [HttpStatusCode]::BadRequest
        $ResponseBody = [pscustomobject]@{ Results = "Graph Error: $ErrorMessage - Endpoint: $Endpoint" }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $ResponseBody
        })
}
