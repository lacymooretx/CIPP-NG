function Get-CIPPDefaultReportRecipient {
    <#
    .SYNOPSIS
        The address a fork report email goes to when nobody has saved one: CIPP's notification email.
    .DESCRIPTION
        Reads the email field of CIPP's notification settings (Settings > Notifications, SchedulerConfig row
        CippNotifications) and returns its first address. Returns '' when none is set, so callers can say so
        instead of mailing a hard-coded person. Aspendora fork addition (CIPP-64).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param()
    $Table = Get-CIPPTable -TableName SchedulerConfig
    $Config = try { Get-CIPPAzDataTableEntity @Table -Filter "RowKey eq 'CippNotifications' and PartitionKey eq 'CippNotifications'" } catch { $null }
    $First = @(([string]$Config.email) -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ -like '*@*' })[0]
    return [string]$First
}
