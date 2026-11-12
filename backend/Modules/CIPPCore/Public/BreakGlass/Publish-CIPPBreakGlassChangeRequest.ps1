function Publish-CIPPBreakGlassChangeRequest {
    <#
    .SYNOPSIS
        Posts a stored, Pending break-glass plan to ControlR's Change Requests queue and records the request on the
        plan row (ChangeRequestId, ChangeRequestUrl, PlanHash).
    .DESCRIPTION
        planId = the tenant id. A new hash for the same planId supersedes the open request in ControlR, so a refreshed
        plan replaces the old request by itself. The same hash returns the existing request (created=false).
        ControlR stores the body for the reviewer's view only. CIPP executes its own stored plan, matched by hash.
        Returns the ControlR response, or an object with Error. Aspendora fork addition (ONB-13).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$PlanRow)
    $Table = Get-CIPPTable -tablename 'BreakGlassProvision'
    $Plan = $PlanRow.PlanJson | ConvertFrom-Json
    $Hash = Get-CIPPBreakGlassPlanHash -Plan $Plan
    $Summary = "Create $(@($Plan.AccountsToCreate).Count) Aspendora break-glass account(s) in $($Plan.DisplayName) ($($Plan.Tenant)): cloud-only, permanent Global Admin, no licence. " +
    "Exclusion group: $($Plan.GroupAction)$(if ($Plan.GroupId) { " $($Plan.GroupId)" }). Exclude it from $(@($Plan.PolicyEdits).Count) Conditional Access policies (snapshotted first). " +
    "Password set by ControlR into Keeper. FIDO2 keys registered afterwards by a tech.$(if (@($Plan.Warnings).Count) { ' Warnings: ' + (@($Plan.Warnings) -join ' ') })"
    if ($Summary.Length -gt 2000) { $Summary = $Summary.Substring(0, 1997) + '...' }
    $Body = @{
        planId = [string]$Plan.TenantId; planHash = $Hash; entraTenantId = [string]$Plan.TenantId; tenantName = [string]$Plan.DisplayName
        accounts = @($Plan.AccountsToCreate); groupAction = [string]$Plan.GroupAction; summary = $Summary
        policies = @(@($Plan.PolicyEdits) | Select-Object -First 200 | ForEach-Object { @{ id = [string]$_.Id; name = [string]$_.DisplayName; state = [string]$_.State } })
    }
    $R = Invoke-CippControlRIntegrationRequest -Method POST -Path 'change-requests/break-glass' -Body $Body
    if ($R.Status -ne 200 -or -not $R.Data.changeRequestId) {
        return [pscustomobject]@{ Error = $R.Message ?? "ControlR returned HTTP $($R.Status)."; PlanHash = $Hash }
    }
    foreach ($Pair in @{ ChangeRequestId = [string]$R.Data.changeRequestId; ChangeRequestUrl = [string]$R.Data.url; PlanHash = $Hash; ChangeRequestError = '' }.GetEnumerator()) {
        $PlanRow | Add-Member -NotePropertyName $Pair.Key -NotePropertyValue $Pair.Value -Force
    }
    Add-CIPPAzDataTableEntity @Table -Entity $PlanRow -Force
    return [pscustomobject]@{ Error = $null; PlanHash = $Hash; ChangeRequestId = $R.Data.changeRequestId; Url = $R.Data.url; Created = $R.Data.created; Status = $R.Data.status }
}
