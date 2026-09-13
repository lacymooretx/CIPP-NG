function Invoke-ListTeamsPolicy {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Teams.Config.Read
    .DESCRIPTION
        Reads Microsoft Teams admin policies and configuration for a tenant via the Teams
        ConfigAPI (New-TeamsRequestV2). The typed read counterpart of ExecTeamsPolicy.

        Query/body params:
          TenantFilter - tenant default domain or customer id. Required unless Catalog=true.
          PolicyType   - ConfigAPI type, cmdlet noun, or full cmdlet name
                         (e.g. 'TeamsMeetingPolicy' / 'Get-CsTeamsMeetingPolicy').
                         Omit to return every type in the catalog for this tenant.
          Identity     - a single policy instance to read (e.g. 'Global', 'Tag:Executives').
                         Omit to list all instances of the type.
          Catalog      - true to return the static type catalog only, with no tenant calls.
          Category     - filter the catalog / all-types sweep to one category
                         (Meetings, Messaging, Apps, External access, Voice, Client & general).
          AsApp        - true to use an application token instead of delegated.

        With neither PolicyType nor Catalog this sweeps every catalogued type for the
        tenant. That is a lot of sequential ConfigAPI calls, so it reports per-type errors
        inline rather than failing the whole request, and Category is the way to narrow it.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers

    $TenantFilter = $Request.Body.TenantFilter ?? $Request.Query.TenantFilter ?? $Request.Query.tenantFilter
    $PolicyType = $Request.Body.PolicyType ?? $Request.Query.PolicyType
    $Identity = $Request.Body.Identity ?? $Request.Query.Identity
    $Category = $Request.Body.Category ?? $Request.Query.Category

    $TruthyValues = @($true, 'true', 'True', 1, '1', 'yes', 'on')
    $Catalog = ($Request.Body.Catalog ?? $Request.Query.Catalog) -in $TruthyValues
    $AsApp = ($Request.Body.AsApp ?? $Request.Query.AsApp) -in $TruthyValues

    # Static catalog of known ConfigAPI types. Also lets the UI enumerate what exists
    # without making a single tenant call.
    try {
        $CatalogPath = Join-Path $env:CIPPRootPath 'Config' 'TeamsPolicyTypes.json'
        $TypeCatalog = ([System.IO.File]::ReadAllText($CatalogPath) | ConvertFrom-Json).types
    } catch {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = [pscustomobject]@{ Results = "Could not load TeamsPolicyTypes.json: $($_.Exception.Message)" }
            })
    }
    if ($Category) { $TypeCatalog = $TypeCatalog | Where-Object { $_.category -eq $Category } }

    if ($Catalog) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @($TypeCatalog)
            })
    }

    if (-not $TenantFilter) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = 'TenantFilter is required unless Catalog=true.' }
            })
    }

    # Federation-backed types sit on the legacy OcsPowershellWebservice and need the
    # discovered host + target-uri headers, so those reads always use service discovery.
    $FederationTypes = @('TenantFederationSettings', 'TenantFederationConfiguration', 'TeamsAcsFederationConfiguration')

    function Get-TeamsPolicyInstance {
        param($Tenant, $Type, $InstanceIdentity, $UseApp)
        $Splat = @{ TenantFilter = $Tenant; Type = $Type; Action = 'Get' }
        if ($UseApp) { $Splat.AsApp = $true }
        if (($Type -replace '^(Get|Set|New|Remove|Grant|Revoke)-Cs', '') -in $FederationTypes) { $Splat.UseServiceDiscovery = $true }
        if ($InstanceIdentity) { $Splat.Identity = $InstanceIdentity } else { $Splat.ListAll = $true }
        New-TeamsRequestV2 @Splat
    }

    try {
        if ($PolicyType) {
            Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Read Teams policy $PolicyType/$($Identity ?? '*')" -Sev 'Debug'
            $Results = Get-TeamsPolicyInstance -Tenant $TenantFilter -Type $PolicyType -InstanceIdentity $Identity -UseApp $AsApp
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::OK
                    Body       = @($Results)
                })
        }

        # No type given: sweep the catalog. Per-type failures are reported inline - a
        # single unsupported type must not sink the whole sweep.
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Swept $($TypeCatalog.Count) Teams policy types" -Sev 'Debug'
        $Results = foreach ($Entry in $TypeCatalog) {
            try {
                $Instances = Get-TeamsPolicyInstance -Tenant $TenantFilter -Type $Entry.type -InstanceIdentity $null -UseApp $AsApp
                [pscustomobject]@{
                    PolicyType  = $Entry.type
                    Category    = $Entry.category
                    Premium     = $Entry.premium
                    Description = $Entry.description
                    Instances   = @($Instances)
                    Count       = @($Instances).Count
                    Error       = $null
                }
            } catch {
                [pscustomobject]@{
                    PolicyType  = $Entry.type
                    Category    = $Entry.category
                    Premium     = $Entry.premium
                    Description = $Entry.description
                    Instances   = @()
                    Count       = 0
                    Error       = Get-NormalizedError -Message $_.Exception.Message
                }
            }
        }

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @($Results)
            })
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Teams policy read failed: $ErrorMessage" -Sev 'Error'
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = "Teams Error: $ErrorMessage" }
            })
    }
}
