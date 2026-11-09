function Invoke-CIPPVendorAccessWeekly {
    <#
    .SYNOPSIS
        Sends the Vendor Access email once each Monday at or after 07:00 US Central.
    .DESCRIPTION
        Called hourly by Start-VendorAccessReportTimer. A timer cron runs in one fixed zone, so 07:00 Central would
        drift an hour across CST/CDT; instead this checks the America/Chicago wall clock and records each sent
        Monday (Weekly/<yyyy-MM-dd> row), so the email goes out once, at the first hourly run from 07:00, and is
        caught up later the same Monday if that run was missed. Settings/Weekly Enabled = false turns it off.
        -Now is for tests. Returns a short status string. Aspendora fork addition (Vendor Access).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([datetime]$Now = [datetime]::UtcNow)

    $Zone = try { [TimeZoneInfo]::FindSystemTimeZoneById('America/Chicago') } catch { [TimeZoneInfo]::FindSystemTimeZoneById('Central Standard Time') }
    $Local = [TimeZoneInfo]::ConvertTimeFromUtc($Now.ToUniversalTime(), $Zone)
    if ($Local.DayOfWeek -ne [DayOfWeek]::Monday -or $Local.Hour -lt 7) { return 'Not due' }
    $Table = Get-CIPPTable -TableName 'CippVendorAccess'
    $Settings = try { Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Settings' and RowKey eq 'Weekly'" } catch { $null }
    if ($Settings -and $Settings.Enabled -eq $false) { return 'Disabled' }
    $Day = $Local.ToString('yyyy-MM-dd')
    $Sent = try { Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Weekly' and RowKey eq '$Day'" } catch { $null }
    if ($Sent.Status -eq 'Sent') { return 'Already sent' }
    # A claim left by a run that died mid-send is retried after two hours; a failed send is retried next hour.
    if ($Sent.Status -eq 'Sending' -and $Sent.StartedAt -and ([datetimeoffset]$Sent.StartedAt).UtcDateTime -gt $Now.ToUniversalTime().AddHours(-2)) { return 'Already sending' }
    # Claim the day first: two processors firing in the same hour must not both send.
    Add-CIPPAzDataTableEntity @Table -Entity @{ PartitionKey = 'Weekly'; RowKey = $Day; Status = 'Sending'; StartedAt = $Now } -Force | Out-Null
    try {
        $Result = Send-CIPPVendorAccessReport
        Add-CIPPAzDataTableEntity @Table -Entity @{ PartitionKey = 'Weekly'; RowKey = $Day; Status = 'Sent'; StartedAt = $Now; SentAt = [datetime]::UtcNow; Recipient = $Result.Recipient; Subject = $Result.Subject } -Force | Out-Null
        return 'Sent'
    } catch {
        $Message = try { (Get-CippException -Exception $_).NormalizedError } catch { $_.Exception.Message }
        Add-CIPPAzDataTableEntity @Table -Entity @{ PartitionKey = 'Weekly'; RowKey = $Day; Status = 'Failed'; StartedAt = $Now; Error = [string]$Message } -Force | Out-Null
        Write-LogMessage -API 'VendorAccess' -tenant 'Global' -message "Weekly vendor access email failed: $Message" -Sev 'Error'
        throw
    }
}
