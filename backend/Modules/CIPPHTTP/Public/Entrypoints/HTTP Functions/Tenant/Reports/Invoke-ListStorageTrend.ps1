function Invoke-ListStorageTrend {
    <#
    .SYNOPSIS
        Return a tenant's stored M365 storage history and derived growth figures.
    .DESCRIPTION
        Feeds the Storage & Usage page: the daily series for the chart, plus the growth
        summary so the tiles and the report cannot disagree about the rate.

        Managed clients only, matching the rest of the feature. An unmanaged tenant gets a
        200 with an explanation rather than a 403 - the page needs to say why it is empty,
        and an error code would look like a fault.
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.Reports.Read
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $TriggerMetadata.FunctionName
    $Headers = $Request.Headers
    Write-LogMessage -headers $Headers -API $APIName -message 'Accessed storage trend' -Sev 'Debug'

    $TenantFilter = $Request.Query.TenantFilter ?? $Request.Body.TenantFilter
    $Days = $Request.Query.Days ?? $Request.Body.Days

    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = ConvertTo-Json -Depth 5 -InputObject @{
                    Results = 'Select a single tenant. Storage history is stored per tenant and there is no meaningful all-tenants total.'
                }
            })
    }

    try {
        $Managed = Test-CIPPTenantManaged -TenantFilter $TenantFilter
        if (-not $Managed.IsManaged) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::OK
                    Body       = ConvertTo-Json -Depth 5 -InputObject @{
                        Tenant          = $TenantFilter
                        ManagementStatus = $Managed.Status
                        Collected       = $false
                        Message         = "This tenant is '$($Managed.Status)'. Storage reporting is limited to managed clients; membership syncs from ConnectWise."
                        Series          = @()
                    }
                })
        }

        $Trend = Get-CIPPStorageTrend -TenantFilter $TenantFilter -Days ([int]($Days ?? 0))
        $Growth = Get-CIPPStorageGrowth -Series $Trend.Series

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = ConvertTo-Json -Depth 6 -InputObject @{
                    Tenant           = $Trend.Tenant
                    ManagementStatus = $Managed.Status
                    Collected        = [bool]($Trend.Days -gt 0)
                    Days             = $Trend.Days
                    Series           = @($Trend.Series)
                    Latest           = $Trend.Latest
                    Growth           = $Growth
                    Message          = $(if ($Trend.Days -eq 0) {
                            'No storage history stored yet. The first collection backfills up to 180 days of tenant totals.'
                        } else { $null })
                }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = ConvertTo-Json -InputObject @{ Results = "Failed to read storage trend: $($ErrorMessage.NormalizedError)" }
            })
    }
}
