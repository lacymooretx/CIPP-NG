function ConvertFrom-CIPPOIBPolicyName {
    <#
    .SYNOPSIS
        Parses an OpenIntuneBaseline (OIB) Windows policy name into its identity and version.
    .DESCRIPTION
        OIB Windows policies are named "Win - OIB - <type> - <area> - <D/U> - <name> - v<version>", for example
        "Win - OIB - SC - Microsoft Edge - D - Security - v4.0". Some do not follow the D/U pattern
        ("Win - OIB - WUfB Drivers - Ring 1 - Pilot - v3.0"), so only the "Win - OIB -" prefix and the
        " - v<version>" suffix are relied on. The version is per policy, not the release: the windows-v4.0
        release still ships policies at v3.0 to v3.8.

        BaseKey is the name without the version, lower-cased with spacing collapsed, so the same policy
        matches across versions. When the version token appears more than once the last one wins, and text
        after it (" - Copy", " (1)", a client suffix) is returned as Suffix. Win365/MacOS OIB policies are
        not Windows OIB policies and return IsOib = $false.

        Also pulls the OIBID GUID from a description ("OIBID:<guid>"), which OIB writes into every v4.0
        policy and which survives renames. Pure: no Graph or table calls.
        Aspendora fork addition (Vikunja CIPP-20).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$Name,
        [AllowNull()][AllowEmptyString()][string]$Description
    )

    $Result = [ordered]@{ Name = $Name; IsOib = $false; BaseName = $null; BaseKey = $null; Version = $null; Suffix = $null; OibId = $null }
    if ($Description -match 'OIBID:\s*\{?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})') {
        $Result.OibId = $Matches[1].ToUpperInvariant()
    }
    if ([string]::IsNullOrWhiteSpace($Name)) { return [pscustomobject]$Result }

    $Clean = ($Name -replace '\s+', ' ').Trim()
    if ($Clean -notmatch '^Win ?- ?OIB ?- ?(?<body>.+)$') { return [pscustomobject]$Result }
    $Body = $Matches.body
    $Result.IsOib = $true

    # Greedy body: the LAST " - v<digits>" token is the version.
    if ($Body -match '^(?<core>.+) ?- ?v(?<ver>\d+(?:\.\d+){0,3})(?![\d.])(?<rest>.*)$') {
        $Core = $Matches.core.Trim().TrimEnd('-').Trim()
        $Ver = $Matches.ver
        if ($Ver -notmatch '\.') { $Ver = "$Ver.0" }
        $Result.Version = $Ver
        $Rest = $Matches.rest.Trim()
        if ($Rest) { $Result.Suffix = $Rest }
    } else {
        $Core = $Body.Trim()
    }
    $Result.BaseName = "Win - OIB - $Core"
    $Result.BaseKey = ($Core -replace '\s*-\s*', ' - ').ToLowerInvariant()
    [pscustomobject]$Result
}
