function Get-CIPPAlertEntraEntitlementGap {
    <#
    .SYNOPSIS
        Weekly check that a tenant owns enough Entra ID P1/P2 seats for its Conditional Access scope
    .DESCRIPTION
        Runs Get-CIPPEntraEntitlement and raises only its Warning findings: a P1 or P2 pool smaller than the users in
        scope of enforced policies. Per-user assignment gaps stay on the report, because they are true-up evidence and
        not failures. Each row has a stable Id, so the lifecycle notifies once per shortfall and resolves it when fixed;
        counts in the message do not re-notify. A run with collection errors does not report, because "could not check"
        is not "clear". Report only: nothing in the tenant is changed. Aspendora fork addition (Vikunja CIPP-47).
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
        $Report = Get-CIPPEntraEntitlement -TenantFilter $TenantFilter
        if (@($Report.Errors).Count -gt 0 -or -not $Report.Summary) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Entra entitlement: skipped reporting, could not read everything: $(@($Report.Errors) -join '; ')" -sev Warning
            return
        }
        Save-CIPPEntraEntitlementSummary -TenantFilter $TenantFilter -Report $Report
        $Rows = @($Report.Findings | Where-Object { $_.Severity -eq 'Warning' } | ForEach-Object {
                [pscustomobject]@{
                    Id       = $_.Key
                    Severity = $_.Severity
                    Check    = $_.Check
                    Message  = $_.Message
                    Fix      = $_.Fix
                }
            })
        Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data @($Rows)
    } catch {
        $ErrorData = Get-CippException -Exception $_
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Entra entitlement check failed: $($ErrorData.NormalizedError)" -sev (Get-CIPPAlertFailureSeverity -ErrorText "$($ErrorData.NormalizedError) $_") -LogData $ErrorData
    }
}
