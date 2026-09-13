function Invoke-ExecTeamsVoiceApp {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Teams.Voice.ReadWrite
    .DESCRIPTION
        Creates, updates and deletes Teams voice-app objects - call queues, auto
        attendants, schedules, resource-account associations - via the Teams ConfigAPI
        (New-TeamsRequestV2 -Path). The write counterpart of ListTeamsVoiceApp.

        Body params:
          TenantFilter (required) - tenant default domain or customer id
          Route        (required) - route key from Config/TeamsVoiceAppRoutes.json
                                    (e.g. 'CallQueues', 'AutoAttendants', 'Schedules')
          Method                  - POST (default) | PUT | PATCH | DELETE
          Identity                - instance id, appended to the route. Required for
                                    PUT/PATCH/DELETE against a specific object
          Body                    - request payload (object or pre-serialized JSON string)

        Read the object with ListTeamsVoiceApp first and send back a full, modified copy:
        these routes are not documented as merge semantics, so a partial PUT can drop
        properties. Always read back after writing - a 2xx is not proof the write landed.

        Every call is audited. The SAM/GDAP scope remains the real safety boundary.

    .EXAMPLE
        POST /api/ExecTeamsVoiceApp
        { "TenantFilter": "contoso.com", "Route": "CallQueues", "Method": "PUT",
          "Identity": "c480e28b-...", "Body": { ...full call queue object... } }
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers

    $TenantFilter = $Request.Body.TenantFilter ?? $Request.Query.TenantFilter ?? $Request.Query.tenantFilter
    $Route = $Request.Body.Route ?? $Request.Query.Route
    $Method = ($Request.Body.Method ?? $Request.Query.Method ?? 'POST').ToString().ToUpper()
    $Identity = $Request.Body.Identity ?? $Request.Query.Identity
    $PayloadBody = $Request.Body.Body ?? $Request.Body.TeamsRequestBody

    $TruthyValues = @($true, 'true', 'True', 1, '1', 'yes', 'on')
    $AsApp = ($Request.Body.AsApp ?? $Request.Query.AsApp) -in $TruthyValues

    $ValidMethods = @('POST', 'PUT', 'PATCH', 'DELETE')

    if (-not $TenantFilter) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = 'TenantFilter is required.' }
            })
    }
    if (-not $Route) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = 'Route is required. Call ListTeamsVoiceApp with Catalog=true for valid route keys.' }
            })
    }
    if ($Method -notin $ValidMethods) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = "Invalid Method '$Method'. Allowed: $($ValidMethods -join ', '). Use ListTeamsVoiceApp to read." }
            })
    }
    if ($Method -in @('PUT', 'PATCH', 'DELETE') -and -not $Identity) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = "Method '$Method' requires Identity so it targets a specific object." }
            })
    }
    if ($Method -in @('POST', 'PUT', 'PATCH') -and ($null -eq $PayloadBody -or $PayloadBody -eq '')) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = "Method '$Method' requires a Body." }
            })
    }

    try {
        $RoutePath = Join-Path $env:CIPPRootPath 'Config' 'TeamsVoiceAppRoutes.json'
        $RouteMap = ([System.IO.File]::ReadAllText($RoutePath) | ConvertFrom-Json).routes
    } catch {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = [pscustomobject]@{ Results = "Could not load TeamsVoiceAppRoutes.json: $($_.Exception.Message)" }
            })
    }

    $Entry = $RouteMap | Where-Object { $_.key -eq $Route } | Select-Object -First 1
    if (-not $Entry) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = "Unknown Route '$Route'. Call ListTeamsVoiceApp with Catalog=true to list valid route keys." }
            })
    }

    $Path = $Entry.path
    if ($Path -match '\{tenantId\}') { $Path = $Path -replace '\{tenantId\}', (Get-Tenants -TenantFilter $TenantFilter).customerId }
    if ($Identity) { $Path = '{0}/{1}' -f $Path.TrimEnd('/'), $Identity }

    try {
        $Splat = @{ TenantFilter = $TenantFilter; Path = $Path; Method = $Method }
        if ($null -ne $PayloadBody -and $PayloadBody -ne '') { $Splat.Body = $PayloadBody }
        if ($AsApp) { $Splat.AsApp = $true }
        if ($Entry.path -like 'Skype.TelephoneNumberMgmt/*') {
            $Splat.AdditionalHeaders = @{ 'x-ms-tnm-applicationid' = '045268c0-445e-4ac1-9157-d58f67b167d9' }
        }

        $Results = New-TeamsRequestV2 @Splat

        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Teams voice-app $Method on $Route$(if ($Identity) { "/$Identity" })" -Sev 'Info'

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = [pscustomobject]@{
                    Results = "Successfully executed $Method on $Route$(if ($Identity) { "/$Identity" }). Read back to confirm."
                    Details = $Results
                }
            })
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Teams voice-app $Method failed on $Route - $ErrorMessage" -Sev 'Error'
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = "Teams Error: $ErrorMessage - $Method $Path" }
            })
    }
}
