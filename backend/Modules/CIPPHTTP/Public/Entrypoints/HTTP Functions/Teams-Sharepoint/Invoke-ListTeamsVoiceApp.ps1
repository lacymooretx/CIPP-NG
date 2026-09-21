function Invoke-ListTeamsVoiceApp {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Teams.Voice.Read
    .DESCRIPTION
        Reads Teams voice-app and assignment surfaces that live OUTSIDE
        /Skype.Policy/configurations - call queues, auto attendants, schedules, resource
        accounts, emergency locations and group policy assignments - via the Teams
        ConfigAPI (New-TeamsRequestV2 -Path).

        Where ListTeamsPolicy covers the policy/configuration surface, this covers the
        rest. The route map is Config/TeamsVoiceAppRoutes.json, which also records which
        routes were verified live and which are denied or absent.

        Query/body params:
          TenantFilter - required unless Catalog=true
          Route        - route key from the catalog (e.g. 'CallQueues', 'AutoAttendants',
                         'GroupPolicyAssignments'). Omit to sweep the whole catalog.
          Identity     - optional instance id appended to the route
          Catalog      - true to return the route catalog only, no tenant calls
          Category     - filter to one category (Voice apps, Voice, Assignment, Tenant)
          AsApp        - true to use an application token instead of delegated

        A sweep reports per-route errors inline rather than failing the whole request,
        because this surface is undocumented and route availability varies by tenant.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers

    $TenantFilter = $Request.Body.TenantFilter ?? $Request.Query.TenantFilter ?? $Request.Query.tenantFilter
    $Route = $Request.Body.Route ?? $Request.Query.Route
    $Identity = $Request.Body.Identity ?? $Request.Query.Identity
    $Category = $Request.Body.Category ?? $Request.Query.Category

    $Catalog = ConvertTo-CIPPBoolean -Value ($Request.Body.Catalog ?? $Request.Query.Catalog)
    $AsApp = ConvertTo-CIPPBoolean -Value ($Request.Body.AsApp ?? $Request.Query.AsApp)

    try {
        $RoutePath = Join-Path $env:CIPPRootPath 'Config' 'TeamsVoiceAppRoutes.json'
        $RouteMap = ([System.IO.File]::ReadAllText($RoutePath) | ConvertFrom-Json).routes
    } catch {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = [pscustomobject]@{ Results = "Could not load TeamsVoiceAppRoutes.json: $($_.Exception.Message)" }
            })
    }
    if ($Category) { $RouteMap = $RouteMap | Where-Object { $_.category -eq $Category } }

    if ($Catalog) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = @($RouteMap) })
    }

    if (-not $TenantFilter) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = 'TenantFilter is required unless Catalog=true.' }
            })
    }

    # Routes may carry a {tenantId} placeholder; resolve it lazily so tenants whose
    # routes do not need it never pay for the lookup.
    function Resolve-RoutePath {
        param($Entry, $InstanceIdentity, $Tenant)
        $P = $Entry.path
        if ($P -match '\{tenantId\}') {
            $P = $P -replace '\{tenantId\}', (Get-Tenants -TenantFilter $Tenant).customerId
        }
        if ($InstanceIdentity) { $P = '{0}/{1}' -f $P.TrimEnd('/'), $InstanceIdentity }
        return $P
    }

    function Invoke-Route {
        param($Entry, $InstanceIdentity)
        $Splat = @{ TenantFilter = $TenantFilter; Path = (Resolve-RoutePath -Entry $Entry -InstanceIdentity $InstanceIdentity -Tenant $TenantFilter); Method = 'GET' }
        if ($AsApp) { $Splat.AsApp = $true }
        # The telephone-number surface needs its own application id header.
        if ($Entry.path -like 'Skype.TelephoneNumberMgmt/*') {
            $Splat.AdditionalHeaders = @{ 'x-ms-tnm-applicationid' = '045268c0-445e-4ac1-9157-d58f67b167d9' }
        }
        $Result = New-TeamsRequestV2 @Splat
        # Most voice-app routes wrap the array in a named collection property.
        if ($Entry.collection -and $null -ne $Result -and ($Result.PSObject.Properties.Name -contains $Entry.collection)) {
            return $Result.($Entry.collection)
        }
        return $Result
    }

    try {
        if ($Route) {
            $Entry = $RouteMap | Where-Object { $_.key -eq $Route } | Select-Object -First 1
            if (-not $Entry) {
                return ([HttpResponseContext]@{
                        StatusCode = [HttpStatusCode]::BadRequest
                        Body       = [pscustomobject]@{ Results = "Unknown Route '$Route'. Call with Catalog=true to list valid route keys." }
                    })
            }
            Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Read Teams voice-app route $Route" -Sev 'Debug'
            $Results = Invoke-Route -Entry $Entry -InstanceIdentity $Identity
            return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = @($Results) })
        }

        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Swept $($RouteMap.Count) Teams voice-app routes" -Sev 'Debug'
        $Results = foreach ($Entry in $RouteMap) {
            try {
                $Data = Invoke-Route -Entry $Entry -InstanceIdentity $null
                [pscustomobject]@{
                    Route = $Entry.key; Category = $Entry.category; Path = $Entry.path
                    Items = @($Data); Count = @($Data).Count; Error = $null
                }
            } catch {
                [pscustomobject]@{
                    Route = $Entry.key; Category = $Entry.category; Path = $Entry.path
                    Items = @(); Count = 0; Error = Get-NormalizedError -Message $_.Exception.Message
                }
            }
        }
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = @($Results) })
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Teams voice-app read failed: $ErrorMessage" -Sev 'Error'
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = "Teams Error: $ErrorMessage" }
            })
    }
}
