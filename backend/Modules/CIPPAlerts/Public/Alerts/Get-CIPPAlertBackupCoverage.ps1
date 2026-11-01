function Get-CIPPAlertBackupCoverage {
    <#
    .SYNOPSIS
        Alert when a tenant has no current CIPP backup of its identity configuration
    .DESCRIPTION
        Microsoft Entra Backup and Recovery keeps only about 5 days of daily snapshots and cannot bring back hard-deleted
        objects, so a slow compromise noticed after a week has nothing native to roll back to. This alert raises the
        tenant's CIPP backup gaps from Get-CIPPEntraRecoveryCoverage: no scheduled CIPP backup task, the task disabled,
        no backup taken yet, the last backup older than BackupCoverageMaxAgeDays (default 2), or Conditional Access /
        users and groups left out of the backup. No live Graph calls are made (coverage comes from CIPP's own tables).
        State mode: Id = 'BackupCoverage|<tenant>|<gap code>', so a stale backup stays one alert while it ages.
        Report only. Aspendora fork addition (Vikunja CIPP-17).
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
    $MaxAge = 2
    $Parsed = 0
    # Multiple-input alerts pass an object; accept a bare number too in case the alert is saved as single input.
    $Raw = if ($InputValue -is [string] -or $InputValue -is [ValueType]) { $InputValue } else { $InputValue.BackupCoverageMaxAgeDays }
    if ($null -ne $Raw -and [int]::TryParse([string]$Raw, [ref]$Parsed) -and $Parsed -ge 1) { $MaxAge = $Parsed }
    try {
        $Report = Get-CIPPEntraRecoveryCoverage -TenantFilter $TenantFilter -MaxBackupAgeDays $MaxAge -SkipLive
    } catch {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Backup coverage: could not build the report: $((Get-CippException -Exception $_).NormalizedError)" -sev Warning
        return
    }
    $Rows = foreach ($Row in @($Report.Rows)) {
        $Codes = @($Row.gapCodes)
        $Messages = @($Row.gapList)
        for ($i = 0; $i -lt $Codes.Count; $i++) {
            [pscustomobject]@{
                Id         = "BackupCoverage|$($Row.tenant)|$($Codes[$i])"
                Tenant     = [string]$Row.tenant
                Gap        = [string]$Messages[$i]
                LastBackup = if ($Row.cippLastBackup) { Format-CIPPCentralTime -Value $Row.cippLastBackup } else { 'Never' }
                Components = if ($Row.cippComponents) { [string]$Row.cippComponents } else { 'None' }
                Message    = "$($Row.tenant): $($Messages[$i]). Entra's own backup keeps only about 5 days and cannot restore hard-deleted objects; schedule a daily CIPP backup with Conditional Access, users and groups (Tenant > Backup > Add Configuration Backup Task)."
            }
        }
    }
    Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data @($Rows | Where-Object { $_ })
}
