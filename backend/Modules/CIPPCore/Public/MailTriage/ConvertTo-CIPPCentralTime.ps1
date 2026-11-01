function ConvertTo-CIPPCentralTime {
    <#
    .SYNOPSIS
        Renders a timestamp as US Central time with the zone stated, plus UTC alongside.
    .DESCRIPTION
        Exchange and Graph return UTC. A DateTime of Kind Unspecified is treated as UTC (that is what EXO
        deserialises to); strings are parsed as UTC unless they carry an offset. Returns $null for empty input.
        Output: Utc = 2026-10-31T23:51:53Z, Central = 2026-10-31 18:51:53 CDT, Display = 2026-10-31 18:51 CDT (23:51 UTC).
        Aspendora fork addition (Vikunja CIPP-38).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([AllowNull()]$Value)

    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    $Utc = $null
    if ($Value -is [DateTimeOffset]) {
        $Utc = $Value.UtcDateTime
    } elseif ($Value -is [DateTime]) {
        $Utc = if ($Value.Kind -eq [DateTimeKind]::Local) { $Value.ToUniversalTime() } else { [DateTime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
    } else {
        $Parsed = [DateTimeOffset]::MinValue
        $Styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AllowWhiteSpaces
        if (-not [DateTimeOffset]::TryParse([string]$Value, [cultureinfo]::InvariantCulture, $Styles, [ref]$Parsed)) { return $null }
        $Utc = $Parsed.UtcDateTime
    }

    # IANA id works on Linux and on Windows with ICU (.NET 6+); the Windows id is the fallback.
    $Zone = $null
    foreach ($Id in @('America/Chicago', 'Central Standard Time')) {
        try { $Zone = [System.TimeZoneInfo]::FindSystemTimeZoneById($Id); break } catch { $Zone = $null }
    }
    if (-not $Zone) {
        return [pscustomobject]@{ Utc = $Utc.ToString('yyyy-MM-ddTHH:mm:ssZ'); Central = $null; Display = "$($Utc.ToString('yyyy-MM-dd HH:mm')) UTC" }
    }
    $Local = [System.TimeZoneInfo]::ConvertTimeFromUtc($Utc, $Zone)
    $Abbrev = if ($Zone.IsDaylightSavingTime($Local)) { 'CDT' } else { 'CST' }
    # Spell out the UTC date only when it differs from the Central date (evening Central = next day UTC).
    $UtcShort = if ($Utc.Date -eq $Local.Date) { $Utc.ToString('HH:mm') } else { $Utc.ToString('yyyy-MM-dd HH:mm') }
    [pscustomobject]@{
        Utc     = $Utc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        Central = "$($Local.ToString('yyyy-MM-dd HH:mm:ss')) $Abbrev"
        Display = "$($Local.ToString('yyyy-MM-dd HH:mm')) $Abbrev ($UtcShort UTC)"
    }
}
