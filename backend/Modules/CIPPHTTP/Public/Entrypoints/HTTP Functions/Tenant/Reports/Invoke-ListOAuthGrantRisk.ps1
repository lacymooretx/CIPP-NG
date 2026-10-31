function Invoke-ListOAuthGrantRisk {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.Application.Read
    .SYNOPSIS
        Risk-scored OAuth grants (app-only and delegated) per client app, with AI/SaaS connectors flagged
    .DESCRIPTION
        Live Graph inventory of every client app's application permissions on Microsoft Graph, Exchange Online and
        SharePoint, and its delegated grants (tenant-wide or per user), scored by Measure-CIPPOAuthGrantRisk: app-only
        mailbox/file/directory access is Critical, tenant-wide high-risk delegated consent is High. Each app has
        reasons, a blast-radius sentence and a suggested action; AI connectors are matched against Config/ShadowAI.json.
        Apps are sorted by score. MinRisk (Critical, High, Medium or Low; default Low = all) drops lower-scored apps.
        Report only: nothing is changed. Aspendora fork addition (Vikunja CIPP-11).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Pick a single tenant.' } })
    }
    $Levels = @('Low', 'Medium', 'High', 'Critical')
    $MinRisk = [string]($Request.Query.MinRisk ?? $Request.Body.MinRisk)
    if (-not $MinRisk) { $MinRisk = 'Low' }
    $MinIndex = [array]::IndexOf($Levels, ($Levels | Where-Object { $_ -eq $MinRisk } | Select-Object -First 1))
    if ($MinIndex -lt 0) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'MinRisk must be Critical, High, Medium or Low.' } })
    }
    try {
        $Report = Get-CIPPOAuthGrantRisk -TenantFilter $TenantFilter
        $Report.Apps = @($Report.Apps | Where-Object { [array]::IndexOf($Levels, [string]$_.Risk) -ge $MinIndex })
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Report })
    } catch {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $((Get-CippException -Exception $_).NormalizedError)" } })
    }
}
