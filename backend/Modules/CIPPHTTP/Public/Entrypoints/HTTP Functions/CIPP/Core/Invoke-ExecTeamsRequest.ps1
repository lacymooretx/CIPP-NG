function Invoke-ExecTeamsRequest {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        CIPP.Core.ReadWrite
    .DESCRIPTION
        Generic Microsoft Teams admin ConfigAPI passthrough - the Teams counterpart of
        ExecGraphRequest and ExecExoRequest. Executes an arbitrary Teams admin request
        against a single tenant via New-TeamsRequestV2, which speaks the ACMS surface
        (api.interfaces.records.teams.microsoft.com) rather than the MicrosoftTeams
        PowerShell module. The module's policy writes go through
        /Skype.Policy/tenants/policies and return 40301 Forbidden under CSP/GDAP; the
        ConfigAPI surface this uses authorizes with the roles CIPP already holds.

        Gated to CIPP.Core.ReadWrite. It can reach any Teams surface with any verb, so the
        underlying SAM/GDAP permissions remain the real safety boundary. Every mutating
        call is audited.

        Two mutually exclusive modes, mirroring New-TeamsRequestV2's parameter sets.

        Configuration mode (default) - addresses /Skype.Policy/configurations/{Type}:
          TenantFilter (required) - tenant default domain or customer id
          Type         (required) - ConfigAPI type ('TeamsMeetingPolicy'), a cmdlet noun,
                                    or a full cmdlet name ('Set-CsTeamsMeetingPolicy');
                                    the verb is stripped and noun->type aliases applied
          Action                  - Get (default) | Set | New | Remove
          Identity                - policy instance, default 'Global' (e.g. 'Tag:Executives')
          Parameters              - object of properties to write (Set/New). Only these are
                                    sent; Set is a merge, not a replace
          ListAll                 - Get: return every instance of the type as an array
          NoRead                  - Set: skip the read-for-Key step and PUT bare props

        Path mode - any other ConfigAPI surface, by raw path:
          Path         (required) - e.g. 'Skype.Ncs/locations',
                                    'Teams.PlatformService/v2/ApplicationInstances'
          Method                  - GET (default) | POST | PUT | PATCH | DELETE
          Body                    - request body (object or JSON string)
          QueryParameters         - object appended as a query string
          AdditionalHeaders       - object of extra request headers

        Both modes:
          AsApp                - $true to force an application token instead of delegated
          UseServiceDiscovery  - $true to resolve the per-tenant ConfigApi host and
                                 X-MS-Forest header first. Required for federation types
                                 and the legacy OcsPowershellWebservice surfaces.

    .EXAMPLE
        POST /api/ExecTeamsRequest
        { "TenantFilter": "contoso.com", "Type": "TeamsMeetingPolicy", "ListAll": true }

    .EXAMPLE
        POST /api/ExecTeamsRequest
        { "TenantFilter": "contoso.com", "Type": "TeamsMeetingPolicy", "Action": "Set",
          "Identity": "Global", "Parameters": { "AllowAnonymousUsersToJoinMeeting": false } }

    .EXAMPLE
        POST /api/ExecTeamsRequest
        { "TenantFilter": "contoso.com", "Path": "Skype.Ncs/locations" }
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers

    # Accept params from body (POST-style) first, falling back to query (GET-style).
    $TenantFilter = $Request.Body.TenantFilter ?? $Request.Query.TenantFilter
    $Type = $Request.Body.Type ?? $Request.Query.Type
    $Action = $Request.Body.Action ?? $Request.Query.Action ?? 'Get'
    $Identity = $Request.Body.Identity ?? $Request.Query.Identity
    $Parameters = $Request.Body.Parameters
    $Path = $Request.Body.Path ?? $Request.Query.Path
    $Method = ($Request.Body.Method ?? $Request.Query.Method ?? 'GET').ToString().ToUpper()
    $TeamsBody = $Request.Body.Body ?? $Request.Body.TeamsRequestBody
    $QueryParameters = $Request.Body.QueryParameters
    $AdditionalHeaders = $Request.Body.AdditionalHeaders

    # Coerce loosely-typed flags (query values arrive as strings) without throwing.
    $ListAll = ConvertTo-CIPPBoolean -Value ($Request.Body.ListAll ?? $Request.Query.ListAll)
    $NoRead = ConvertTo-CIPPBoolean -Value ($Request.Body.NoRead ?? $Request.Query.NoRead)
    $AsApp = ConvertTo-CIPPBoolean -Value ($Request.Body.AsApp ?? $Request.Query.AsApp)
    $UseServiceDiscovery = ConvertTo-CIPPBoolean -Value ($Request.Body.UseServiceDiscovery ?? $Request.Query.UseServiceDiscovery)

    $ValidActions = @('Get', 'Set', 'New', 'Remove')
    $ValidMethods = @('GET', 'POST', 'PUT', 'PATCH', 'DELETE')

    # ---- validation ----
    if (-not $TenantFilter) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = 'TenantFilter is required.' }
            })
    }
    if (-not $Type -and -not $Path) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = 'Either Type (configuration mode) or Path (raw path mode) is required.' }
            })
    }
    if ($Type -and $Path) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = 'Type and Path are mutually exclusive. Use Type for /Skype.Policy/configurations, Path for any other surface.' }
            })
    }
    if ($Path -and $Method -notin $ValidMethods) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = "Invalid Method '$Method'. Allowed: $($ValidMethods -join ', ')." }
            })
    }
    if ($Type) {
        # Normalize case so callers can send 'set'/'SET' as well as 'Set'.
        $Action = ($ValidActions | Where-Object { $_ -eq $Action }) ?? $Action
        if ($Action -notin $ValidActions) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = [pscustomobject]@{ Results = "Invalid Action '$Action'. Allowed: $($ValidActions -join ', ')." }
                })
        }
        if ($Action -in @('Set', 'New') -and -not $Parameters) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = [pscustomobject]@{ Results = "Action '$Action' requires Parameters." }
                })
        }
    }

    # JSON bodies deserialize to PSCustomObject; New-TeamsRequestV2 takes [hashtable].
    function ConvertTo-TeamsParamHash($InputObject) {
        if ($null -eq $InputObject) { return $null }
        if ($InputObject -is [hashtable]) { return $InputObject }
        $Hash = @{}
        foreach ($Prop in $InputObject.PSObject.Properties) { $Hash[$Prop.Name] = $Prop.Value }
        return $Hash
    }

    $Descriptor = if ($Path) { "$Method $Path" } else { "$Action $Type/$($Identity ?? 'Global')" }
    Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Teams passthrough: $Descriptor (AsApp: $AsApp)" -Sev 'Debug'

    try {
        $Splat = @{ TenantFilter = $TenantFilter }
        if ($AsApp) { $Splat.AsApp = $true }
        if ($UseServiceDiscovery) { $Splat.UseServiceDiscovery = $true }

        if ($Path) {
            $Splat.Path = $Path
            $Splat.Method = $Method
            if ($null -ne $TeamsBody -and $TeamsBody -ne '') { $Splat.Body = $TeamsBody }
            $QueryHash = ConvertTo-TeamsParamHash $QueryParameters
            if ($QueryHash) { $Splat.QueryParameters = $QueryHash }
            $HeaderHash = ConvertTo-TeamsParamHash $AdditionalHeaders
            if ($HeaderHash) { $Splat.AdditionalHeaders = $HeaderHash }
        } else {
            $Splat.Type = $Type
            $Splat.Action = $Action
            if ($Identity) { $Splat.Identity = $Identity }
            if ($ListAll) { $Splat.ListAll = $true }
            if ($NoRead) { $Splat.NoRead = $true }
            $ParamHash = ConvertTo-TeamsParamHash $Parameters
            if ($ParamHash) { $Splat.Parameters = $ParamHash }
        }

        $Results = New-TeamsRequestV2 @Splat

        # Audit every mutating call at Info so it shows in the CIPP log.
        $IsMutating = ($Type -and $Action -in @('Set', 'New', 'Remove')) -or ($Path -and $Method -ne 'GET')
        if ($IsMutating) {
            Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Executed Teams $Descriptor" -Sev 'Info'
        }

        $StatusCode = [HttpStatusCode]::OK
        $ResponseBody = [pscustomobject]@{ Results = $Results }
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Teams passthrough failed: $Descriptor - $ErrorMessage" -Sev 'Error'
        $StatusCode = [HttpStatusCode]::BadRequest
        $ResponseBody = [pscustomobject]@{ Results = "Teams Error: $ErrorMessage - Request: $Descriptor" }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $ResponseBody
        })
}
