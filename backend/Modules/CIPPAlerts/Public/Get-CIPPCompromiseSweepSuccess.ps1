function Get-CIPPCompromiseSweepSuccess {
    <#
    .SYNOPSIS
        Successful sign-ins in the sweep window matching an extra OData filter (internal helper)
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([string]$TenantFilter, [string]$Cutoff, [string]$Filter, [string]$Before, [int]$Top = 20)
    $Range = "createdDateTime ge $Cutoff" + $(if ($Before) { " and createdDateTime lt $Before" } else { '' })
    $Uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$Range and status/errorCode eq 0 and $Filter&`$select=createdDateTime,userPrincipalName,ipAddress&`$top=$Top"
    try { @(New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -noPagination $true -ErrorAction Stop) } catch { @() }
}
