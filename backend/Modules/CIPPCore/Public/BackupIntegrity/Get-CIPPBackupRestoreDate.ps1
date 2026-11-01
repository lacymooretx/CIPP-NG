function Get-CIPPBackupRestoreDate {
    <#
    .FUNCTIONALITY
        Internal
    .SYNOPSIS
        Today's date in US Central time as yyyy-MM-dd, for the ' (restored yyyy-MM-dd)' name suffix.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-23). Falls back to UTC when no Central time zone is available.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    foreach ($ZoneId in 'America/Chicago', 'Central Standard Time') {
        try {
            $Zone = [System.TimeZoneInfo]::FindSystemTimeZoneById($ZoneId)
            return [System.TimeZoneInfo]::ConvertTimeFromUtc([datetime]::UtcNow, $Zone).ToString('yyyy-MM-dd')
        } catch {
            Write-Verbose "Time zone $ZoneId not available: $($_.Exception.Message)"
        }
    }
    return [datetime]::UtcNow.ToString('yyyy-MM-dd')
}
