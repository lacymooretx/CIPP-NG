function ConvertTo-CIPPBackupNormalizedValue {
    <#
    .FUNCTIONALITY
        Internal
    .SYNOPSIS
        Turns a parsed backup value into a canonical tree: ordered dictionaries with keys sorted
        ordinally, plain object[] arrays and scalars.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-23).

        Hashes and diffs of backup items have to be computed over the same shape no matter whether
        the value came straight out of Graph, out of a hashtable or back out of ConvertFrom-Json.
        This walks any of those and returns:
          - [ordered] dictionaries, keys sorted with an ordinal comparer (property order never matters)
          - object[] for every list (returned wrapped so PowerShell does not unroll it)
          - strings, bools and numbers unchanged; DateTime/DateTimeOffset as UTC ISO-8601 ('o');
            enums and GUIDs as strings

        IgnoreProperty / IgnorePropertyLike drop keys at every depth (case-insensitive). The diff
        uses them to skip volatile fields; hashing passes nothing so every byte of content counts.
    .PARAMETER Value
        The value to normalise.
    .PARAMETER IgnoreProperty
        Exact property names to drop at any depth.
    .PARAMETER IgnorePropertyLike
        Wildcard patterns (-like) of property names to drop at any depth, e.g. '@odata*'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        $Value,
        [string[]]$IgnoreProperty = @(),
        [string[]]$IgnorePropertyLike = @()
    )

    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o', [cultureinfo]::InvariantCulture) }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime.ToString('o', [cultureinfo]::InvariantCulture) }
    if ($Value -is [enum] -or $Value -is [guid] -or $Value -is [char]) { return $Value.ToString() }
    if ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int] -or $Value -is [uint32] -or $Value -is [long] -or $Value -is [uint64] -or
        $Value -is [double] -or $Value -is [single] -or $Value -is [decimal] -or $Value -is [bigint]) {
        return $Value
    }

    $Skip = {
        param([string]$Name)
        if ($IgnoreProperty.Count -gt 0 -and $Name -in $IgnoreProperty) { return $true }
        foreach ($Pattern in $IgnorePropertyLike) {
            if ($Name -like $Pattern) { return $true }
        }
        return $false
    }

    # Collect name/value pairs into a list - a bare foreach assignment would unroll a single pair.
    $Keys = [System.Collections.Generic.List[string]]::new()
    $Values = @{}
    $AddPair = {
        param([string]$Name, $PairValue)
        if (& $Skip $Name) { return }
        if (-not $Values.ContainsKey($Name)) { $Keys.Add($Name) }
        $Values[$Name] = $PairValue
    }
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($Key in $Value.Keys) { & $AddPair ([string]$Key) $Value[$Key] }
    } elseif ($Value -is [System.Collections.IEnumerable]) {
        $List = [System.Collections.Generic.List[object]]::new()
        foreach ($Element in $Value) {
            $List.Add((ConvertTo-CIPPBackupNormalizedValue -Value $Element -IgnoreProperty $IgnoreProperty -IgnorePropertyLike $IgnorePropertyLike))
        }
        return , $List.ToArray()
    } else {
        # PSCustomObject (ConvertFrom-Json, Select-Object) or any other object: use its note/real properties.
        foreach ($Property in $Value.PSObject.Properties) {
            if ($Property.MemberType -in @('NoteProperty', 'Property')) { & $AddPair ([string]$Property.Name) $Property.Value }
        }
    }

    $Result = [ordered]@{}
    $SortedKeys = $Keys.ToArray()
    [Array]::Sort($SortedKeys, [System.StringComparer]::Ordinal)
    foreach ($Name in $SortedKeys) {
        $Result[$Name] = ConvertTo-CIPPBackupNormalizedValue -Value $Values[$Name] -IgnoreProperty $IgnoreProperty -IgnorePropertyLike $IgnorePropertyLike
    }
    return $Result
}
