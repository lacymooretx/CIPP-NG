function Format-CIPPCentralTime {
    <#
    .SYNOPSIS
        Formats a UTC timestamp as US Central time with the zone and the UTC value, e.g. "2026-10-31 12:00 CDT (17:00 UTC)".
    .DESCRIPTION
        Pure function. Accepts a [datetime], [datetimeoffset] or ISO string. Returns '' for empty input. Falls back to
        UTC when the America/Chicago zone is not available on the host. Aspendora fork addition (Vikunja CIPP-27).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param($Value)
    if ($null -eq $Value -or [string]$Value -eq '') { return '' }
    try {
        $Utc = if ($Value -is [datetime]) { ([datetime]$Value).ToUniversalTime() } else { ([datetimeoffset]$Value).UtcDateTime }
    } catch { return [string]$Value }
    if ($Utc.Year -le 1) { return '' }
    $Central = try { [System.TimeZoneInfo]::FindSystemTimeZoneById('America/Chicago') } catch { $null }
    if (-not $Central) { return "$($Utc.ToString('yyyy-MM-dd HH:mm')) UTC" }
    $Local = [System.TimeZoneInfo]::ConvertTimeFromUtc($Utc, $Central)
    $Zone = if ($Central.IsDaylightSavingTime($Local)) { 'CDT' } else { 'CST' }
    return "$($Local.ToString('yyyy-MM-dd HH:mm')) $Zone ($($Utc.ToString('HH:mm')) UTC)"
}
