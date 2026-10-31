function Invoke-ListGDAPHealth {
    <#
    .FUNCTIONALITY
        Entrypoint,AnyTenant
    .ROLE
        Tenant.Relationship.Read
    .SYNOPSIS
        GDAP relationship, partner token and SAM credential health report
    .DESCRIPTION
        Returns the latest daily GDAP health report: relationships expiring at 30/14/7 days or already lapsed,
        auto-extend that Microsoft has not applied, managed tenants with no active relationship, removed access
        assignments, tenants whose Graph calls fail, and CIPP-SAM token or credential problems.
        Refresh=true runs the check now and sends alerts for new findings, the same as the daily timer.
        Preview=true runs the check now without alerting or changing stored state.
        Resend=true runs the check now and re-sends every open Error/Warning finding.
        Aspendora fork addition (Vikunja CIPP-2).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $Refresh = [string]($Request.Query.Refresh ?? $Request.Body.Refresh) -eq 'true'
    $Preview = [string]($Request.Query.Preview ?? $Request.Body.Preview) -eq 'true'
    $Resend = [string]($Request.Query.Resend ?? $Request.Body.Resend) -eq 'true'

    try {
        if ($Preview) {
            $Report = Invoke-CIPPGDAPHealthCheck -SkipAlerts
        } elseif ($Resend) {
            $Report = Invoke-CIPPGDAPHealthCheck -Resend
        } elseif ($Refresh) {
            $Report = Invoke-CIPPGDAPHealthCheck
        } else {
            $Table = Get-CIPPTable -tablename 'GDAPHealthState'
            $Row = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Report' and RowKey eq 'Latest'"
            $Report = if ($Row.Data) { $Row.Data | ConvertFrom-Json } else { @{ GeneratedUtc = $null; Findings = @(); Message = 'The GDAP health check has not run yet. Call with Refresh=true to run it now.' } }
        }
        $StatusCode = [HttpStatusCode]::OK
        $Body = $Report
    } catch {
        $StatusCode = [HttpStatusCode]::InternalServerError
        $Body = @{ Results = "GDAP health check failed: $((Get-CippException -Exception $_).NormalizedError)" }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Body
        })
}
