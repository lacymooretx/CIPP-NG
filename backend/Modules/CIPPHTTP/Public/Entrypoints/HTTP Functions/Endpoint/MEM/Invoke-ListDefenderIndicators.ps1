Function Invoke-ListDefenderIndicators {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .DESCRIPTION
        Lists Microsoft Defender for Endpoint custom indicators (IOCs) for a tenant.

        Uses the Defender for Endpoint API rather than Graph — MDE custom indicators are
        not exposed through Microsoft Graph. Requires the SAM app to hold Ti.ReadWrite.All
        (or Ti.Read.All) on WindowsDefenderATP; see SAMManifest.json.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    Write-LogMessage -Headers $Headers -API $APIName -message 'Accessed this API' -Sev 'Debug'

    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter

    try {
        $Indicators = New-GraphGetRequest -tenantid $TenantFilter `
            -uri 'https://api.securitycenter.microsoft.com/api/indicators' `
            -scope 'https://api.securitycenter.microsoft.com/.default'

        # Optional client-side filters — the MDE API's OData support is inconsistent.
        if ($Request.Query.indicatorType) {
            $Indicators = $Indicators | Where-Object { $_.indicatorType -eq $Request.Query.indicatorType }
        }
        if ($Request.Query.indicatorValue) {
            $Indicators = $Indicators | Where-Object { $_.indicatorValue -eq $Request.Query.indicatorValue }
        }

        $StatusCode = [HttpStatusCode]::OK
        $Body = @($Indicators)
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -Headers $Headers -API $APIName -tenant $TenantFilter -message "Failed to list Defender indicators: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [HttpStatusCode]::Forbidden
        $Body = $ErrorMessage.NormalizedError
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Body
        })
}
