function Get-CIPPAlertEwsEnabled {
    <#
    .SYNOPSIS
        Alert when EWS is off or unset in a tenant whose apps still have EWS permissions
    .DESCRIPTION
        Daily. Raises Error when EwsEnabled is False and Warning when it is unset, if any app holds EWS permissions
        (backup, email security, iOS Mail). Microsoft's EWS shutdown flips unset to False, and EWS stops within about an
        hour, so this catches the flip before users or backups notice. State mode: notifies once, resolves when fixed.
        Aspendora fork addition (Vikunja CIPP-29).
    .FUNCTIONALITY
        Entrypoint
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Alias('input')]
        $InputValue,
        [Parameter(Mandatory)]
        $TenantFilter
    )
    try {
        $Status = Get-CIPPEwsStatus -TenantFilter $TenantFilter
        $Rows = @($Status.Findings | Where-Object { $_.Severity -in @('Error', 'Warning') } | ForEach-Object {
                [pscustomobject]@{ Severity = $_.Severity; EwsEnabled = $Status.EwsEnabled; Message = $_.Message; Fix = $_.Fix; Key = $_.Key }
            })
        Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data $Rows
    } catch {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "EWS status check failed: $((Get-CippException -Exception $_).NormalizedError)" -sev Error
    }
}
