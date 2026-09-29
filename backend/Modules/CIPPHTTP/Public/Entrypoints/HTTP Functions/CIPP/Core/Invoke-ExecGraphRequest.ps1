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
          NoPagination / DisablePagination - $true: return one page only. $false: follow
                                    @odata.nextLink. Default: one page when the Endpoint
                                    carries $top (the caller asked for N), otherwise follow.
          MaxItems                - cap on items collected while paging (default 1000). Paging
                                    also stops after ~90 s so it can't hit the gateway timeout.

        Collection GETs return { Results: [...], Metadata: { Count, Pages, NextLink, Truncated } }.
        Results is always an array for a collection - an empty result is [], never null - and
        NextLink is set when more data exists (pass it back as Endpoint to page on). A Graph error
        is returned with Graph's own status code and message, never as a 200.

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
    $AsApp = ConvertTo-CIPPBoolean -Value $AsAppRaw
    $NoPagination = ConvertTo-CIPPBoolean -Value $NoPaginationRaw

    $ValidMethods = @('GET', 'POST', 'PATCH', 'PUT', 'DELETE')

    # A caller that names the verb in the wrong parameter used to be answered with a silent GET.
    # `Type` is the obvious wrong guess - it is what New-GraphPOSTRequest calls its verb - and
    # nothing here ever read it, so `Type: POST` fell through to the 'GET' default. Against an
    # endpoint where GET is invalid that surfaces as a confusing Graph error ("No OData route
    # exists ... with http verb GET") that reads like a CIPP write-path bug. Against an endpoint
    # where GET IS valid it is far worse: the caller asking for a write gets 200 and a payload,
    # and believes the write happened. Same false-success class as the bodyless-write guard below.
    # Refuse it and say which parameter to use.
    $VerbAliases = @('Type', 'Verb', 'HttpMethod', 'RequestMethod')
    foreach ($Alias in $VerbAliases) {
        $AliasValue = $Request.Body.$Alias ?? $Request.Query.$Alias
        if ($null -ne $AliasValue -and "$AliasValue" -ne '') {
            if (-not ($Request.Body.Method ?? $Request.Query.Method)) {
                return ([HttpResponseContext]@{
                        StatusCode = [HttpStatusCode]::BadRequest
                        Body       = [pscustomobject]@{ Results = "'$Alias' is not a parameter of ExecGraphRequest - the HTTP verb goes in 'Method'. Received $Alias='$AliasValue' with no Method, which would previously have been executed as a GET. Resend as Method='$AliasValue'." }
                    })
            }
        }
    }

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

    $ErrorStatus = $null
    try {
        $Metadata = $null
        if ($Method -eq 'GET') {
            # Paging defaults. New-GraphGetRequest follows @odata.nextLink until the collection is
            # exhausted, so a caller's `$top=5` against a 24k-item Inbox crawled the whole mailbox and
            # timed out at the gateway. `$top` means "give me N": when present, and the caller hasn't
            # said otherwise, return a single page. An explicit crawl is still bounded by MaxItems
            # and a time budget so it returns partial data and a NextLink instead of timing out.
            $PaginationExplicit = $null -ne $NoPaginationRaw -and "$NoPaginationRaw" -ne ''
            $PaginationDefaulted = $false
            if (-not $PaginationExplicit -and $Uri -match '[?&](\$|%24)top=\d+') {
                $NoPagination = $true
                $PaginationDefaulted = $true
            }
            $MaxItems = 1000
            $MaxItemsRaw = $Request.Body.MaxItems ?? $Request.Query.MaxItems
            if ($null -ne $MaxItemsRaw -and "$MaxItemsRaw" -match '^\d+$' -and [int]"$MaxItemsRaw" -gt 0) { $MaxItems = [int]"$MaxItemsRaw" }
            $Deadline = (Get-Date).AddSeconds(90)

            $GetParams = @{
                tenantid          = $TenantFilter
                ReturnRawResponse = $true
            }
            if ($AsApp) { $GetParams.AsApp = $true }

            # Raw mode gives us the status code and the envelope (value / @odata.nextLink) instead of
            # an unwrapped value that is $null for BOTH an empty collection and a failed read.
            $Items = [System.Collections.Generic.List[object]]::new()
            $IsCollection = $false
            $Single = $null
            $Pages = 0
            $NextUri = $Uri
            do {
                $Raw = $null
                for ($Attempt = 1; $Attempt -le 4; $Attempt++) {
                    $Raw = New-GraphGetRequest @GetParams -uri $NextUri
                    if ($Raw.StatusCode -ne 429 -or $Attempt -eq 4) { break }
                    $RetryAfter = 2
                    try { $RetryAfter = [int]("$($Raw.Headers['Retry-After'])") } catch {}
                    Start-Sleep -Seconds ([Math]::Min([Math]::Max($RetryAfter, 1), 10))
                }
                if ($null -eq $Raw) {
                    # New-GraphGetRequest writes a non-terminating error and returns nothing when the
                    # tenant is excluded or not in the tenant list.
                    $ErrorStatus = [HttpStatusCode]::Forbidden
                    throw "Tenant '$TenantFilter' is not authorised for Graph requests (excluded or not found)."
                }
                $Status = [int]$Raw.StatusCode
                if ($Status -lt 200 -or $Status -ge 300) {
                    $ErrorStatus = [HttpStatusCode]$Status
                    $GraphError = $Raw.Content.error
                    $GraphMessage = if ($GraphError.message) { $GraphError.message } elseif ($GraphError.code) { $GraphError.code } else { "$($Raw.Content)" }
                    $GraphCode = if ($GraphError.code) { " ($($GraphError.code))" } else { '' }
                    throw "HTTP $Status$GraphCode $GraphMessage"
                }
                $Pages++
                $Content = $Raw.Content
                if ($null -ne $Content -and $Content -isnot [string] -and $Content.PSObject.Properties.Name -contains 'value') {
                    $IsCollection = $true
                    foreach ($Item in @($Content.value)) { $Items.Add($Item) }
                    $NextUri = $Content.'@odata.nextLink'
                } else {
                    $Single = $Content
                    $NextUri = $null
                }
            } while ($NextUri -and -not $NoPagination -and $Items.Count -lt $MaxItems -and (Get-Date) -lt $Deadline)

            if ($IsCollection) {
                $Results = $Items.ToArray()
                $Metadata = [pscustomobject]@{
                    Count               = $Items.Count
                    Pages               = $Pages
                    NextLink            = $NextUri
                    Truncated           = [bool]$NextUri
                    PaginationDefaulted = $PaginationDefaulted
                }
                if ($NextUri -and -not $NoPagination) {
                    Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Graph passthrough stopped paging $Endpoint at $($Items.Count) items / $Pages pages (MaxItems $MaxItems or time budget)" -Sev 'Info'
                }
            } else {
                $Results = $Single
            }
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
        $ResponseBody = if ($Metadata) {
            [pscustomobject]@{ Results = $Results; Metadata = $Metadata }
        } else {
            [pscustomobject]@{ Results = $Results }
        }
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Graph passthrough failed: $Method $Endpoint - $ErrorMessage" -Sev 'Error'
        # GET failures carry Graph's own status (403, 404, ...) so a denied read can't be mistaken
        # for an empty one. Write paths keep the historical 400.
        $StatusCode = $ErrorStatus ?? [HttpStatusCode]::BadRequest
        $ResponseBody = [pscustomobject]@{ Results = "Graph Error: $ErrorMessage - Endpoint: $Endpoint" }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $ResponseBody
        })
}
