function Invoke-ListOIBDrift {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .SYNOPSIS
        OpenIntuneBaseline (OIB) version drift for a tenant or for the CIPP Intune template library
    .DESCRIPTION
        Compares every "Win - OIB -" item with the latest OIB Windows release on GitHub (windows-v* tag, cached a
        day in the CIPPOIBRelease table). Matching is by the OIBID in the description, then by name without the
        version. Each finding has a State: Current, Outdated (with CurrentVersion -> LatestVersion), Retired
        (deprecated in or absent from the release), Newer, Unknown (no version), or Missing (in the release, not
        here; informational, partial adoption is normal).
        Pass tenantFilter for a tenant's deployed Intune policies, or TemplateLibrary=true (no tenant) for the
        IntuneTemplate rows in the CIPP template library. RefreshRelease=true bypasses the release cache;
        ExcludeMissing=true drops the Missing rows. Report only: nothing is changed.
        Aspendora fork addition (Vikunja CIPP-20).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $TemplateLibrary = ($Request.Query.TemplateLibrary ?? $Request.Body.TemplateLibrary) -eq $true
    $RefreshRelease = ($Request.Query.RefreshRelease ?? $Request.Body.RefreshRelease) -eq $true
    $ExcludeMissing = ($Request.Query.ExcludeMissing ?? $Request.Body.ExcludeMissing) -eq $true
    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)

    if (-not $TemplateLibrary -and (-not $TenantFilter -or $TenantFilter -eq 'AllTenants')) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Pick a single tenant, or pass TemplateLibrary=true to check the CIPP template library.' } })
    }
    try {
        $Report = if ($TemplateLibrary) {
            Get-CIPPOIBDrift -TemplateLibrary -RefreshRelease:$RefreshRelease -ExcludeMissing:$ExcludeMissing
        } else {
            Get-CIPPOIBDrift -TenantFilter $TenantFilter -RefreshRelease:$RefreshRelease -ExcludeMissing:$ExcludeMissing
        }
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Report })
    } catch {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $((Get-CippException -Exception $_).NormalizedError)" } })
    }
}
