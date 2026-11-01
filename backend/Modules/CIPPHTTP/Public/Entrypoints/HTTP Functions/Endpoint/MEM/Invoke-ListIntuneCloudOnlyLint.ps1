function Invoke-ListIntuneCloudOnlyLint {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .SYNOPSIS
        Flags Intune settings that misbehave or do nothing on Entra joined (cloud-only) devices
    .DESCRIPTION
        Lints either the live Intune policies of one tenant (Settings Catalog, custom OMA-URI profiles and
        Administrative Templates) or one saved CIPP Intune template against a curated rule list
        (Config/IntuneCloudOnlyLintRules.json): settings such as 'Display information about previous logons during
        user logon' that only work for local or Active Directory accounts, Windows LAPS backup to Active Directory,
        and on-premises-only Kerberos, Net Logon and Group Policy settings. Each finding carries the symptom, why it
        happens, the alternative and a Microsoft Learn source. With a tenant, also returns how many Windows devices
        are Entra joined (cloud-only) versus hybrid joined and whether the tenant syncs from on-premises AD, and marks
        each finding's relevance accordingly.
        Report only: nothing is changed. Aspendora fork addition (Vikunja CIPP-28).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    # Not AnyTenant on purpose: in tenant mode this reads a tenant's policies, so the normal tenant-access check
    # must apply.

    # The tenant whose live policies are linted, or the tenant used for device context in template mode.
    # Required unless templateId is given. AllTenants is not supported.
    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    # A saved CIPP Intune template GUID. When set, that template is linted instead of the tenant's live policies.
    $TemplateId = [string]($Request.Query.templateId ?? $Request.Body.templateId)

    $HasTenant = [bool]($TenantFilter -and $TenantFilter -ne 'AllTenants')
    if (-not $TemplateId -and -not $HasTenant) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Pick a single tenant, or pass templateId to lint a saved template.' } })
    }
    try {
        $Params = @{}
        if ($HasTenant) { $Params.TenantFilter = $TenantFilter }
        if ($TemplateId) { $Params.TemplateId = $TemplateId }
        $Report = Get-CIPPIntuneCloudOnlyLint @Params
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Report })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API $Request.Params.CIPPEndpoint -tenant $TenantFilter -message "Intune cloud-only lint failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $($ErrorMessage.NormalizedError)" } })
    }
}
