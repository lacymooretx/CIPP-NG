function Get-CIPPAlertPostureSnapshot {
    <#
    .SYNOPSIS
        Store a monthly security posture snapshot for the Security Posture Change report. Never raises an alert.
    .DESCRIPTION
        The Security Posture Change report (ReportType PostureChange) compares today's CIPPTests results and Secure
        Score with a snapshot from about a month ago. The report stores a snapshot whenever it runs, but a tenant
        whose report is only run on demand would have no history. This scripted alert, scheduled every 30 days
        through the normal alert scheduler, captures the snapshot regardless (Save-CIPPPostureSnapshot), so no new
        Azure Function timer is needed. It reads only CIPP's own tables (no Graph call), writes one row to
        CippPostureSnapshots and returns nothing, so no alert is ever sent. Aspendora fork addition (Vikunja CIPP-16).
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
        $Current = Get-CIPPPostureCurrent -TenantFilter $TenantFilter
        $null = Save-CIPPPostureSnapshot -Snapshot $Current
    } catch {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Posture snapshot could not be stored: $((Get-CippException -Exception $_).NormalizedError)" -sev Warning
    }
    # Deliberately no Write-AlertTrace: this "alert" only maintains report history.
}
