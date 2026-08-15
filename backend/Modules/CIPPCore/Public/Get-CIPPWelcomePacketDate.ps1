function Get-CIPPWelcomePacketDate {
    <#
    .SYNOPSIS
    The current date in US Central, for the "Prepared" line on a welcome packet.

    .DESCRIPTION
    The container runs in UTC. A packet printed at 19:30 on a Thursday in Houston
    is generated at 00:30 Friday UTC, so a plain Get-Date puts tomorrow's date on
    a sheet handed over today. Whoever notices assumes the packet is stale.

    House rule: operators and clients read times in US Central whatever the source
    zone. Central is UTC-6 in winter and UTC-5 from mid-March to early November, so
    this resolves the zone rather than subtracting a fixed offset.

    Falls back to UTC if the zone database is unavailable — a date one evening off
    beats an endpoint that cannot build a packet at all.

    Aspendora fork addition.
    #>
    [CmdletBinding()]
    param()

    try {
        # 'America/Chicago' on Linux containers, 'Central Standard Time' on Windows.
        # FindSystemTimeZoneById accepts the IANA id on .NET 6+ on both.
        $Central = [System.TimeZoneInfo]::FindSystemTimeZoneById('America/Chicago')
        return [System.TimeZoneInfo]::ConvertTimeFromUtc([datetime]::UtcNow, $Central)
    } catch {
        try {
            $Central = [System.TimeZoneInfo]::FindSystemTimeZoneById('Central Standard Time')
            return [System.TimeZoneInfo]::ConvertTimeFromUtc([datetime]::UtcNow, $Central)
        } catch {
            Write-Warning "Could not resolve US Central, dating the welcome packet in UTC: $($_.Exception.Message)"
            return [datetime]::UtcNow
        }
    }
}
