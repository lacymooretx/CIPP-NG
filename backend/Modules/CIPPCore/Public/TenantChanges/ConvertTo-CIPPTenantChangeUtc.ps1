function ConvertTo-CIPPTenantChangeUtc {
    <#
    .SYNOPSIS
        Turns a stored timestamp into a UTC [datetime], or $null when it is empty or unreadable.
    .DESCRIPTION
        Pure function. The change record's sources hand back ISO strings, [datetime] (with any Kind) and
        [datetimeoffset], depending on the table and the JSON parser. A value with no zone is read as UTC, since
        every source stores UTC. Aspendora fork addition (Vikunja CIPP-58).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param($Value)

    if ($null -eq $Value -or [string]$Value -eq '') { return $null }
    try {
        if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
        if ($Value -is [datetime]) {
            if ($Value.Kind -eq [System.DateTimeKind]::Local) { return $Value.ToUniversalTime() }
            return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
        }
        return [datetimeoffset]::Parse([string]$Value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal).UtcDateTime
    } catch {
        return $null
    }
}
