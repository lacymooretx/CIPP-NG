function ConvertTo-CIPPBackupCanonicalJson {
    <#
    .FUNCTIONALITY
        Internal
    .SYNOPSIS
        Serialises a value to canonical JSON: sorted keys, no whitespace, fixed number and string formatting.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-23).

        ConvertTo-Json keeps insertion order, so the same object read back from a blob can hash
        differently from the one that was written. This writer always emits keys in ordinal order
        (via ConvertTo-CIPPBackupNormalizedValue), numbers in invariant culture ('R' for floating
        point) and strings with a minimal, fixed escape set, so equal content always yields equal text.
    .PARAMETER Value
        Any value. It is normalised first unless -Normalized says that was already done.
    .PARAMETER Normalized
        Skip normalisation because Value is already the output of ConvertTo-CIPPBackupNormalizedValue.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        $Value,
        [switch]$Normalized
    )

    if (-not $Normalized.IsPresent) {
        $Value = ConvertTo-CIPPBackupNormalizedValue -Value $Value
    }

    $Builder = [System.Text.StringBuilder]::new()
    $Invariant = [cultureinfo]::InvariantCulture

    $WriteString = {
        param([string]$Text)
        $Escaped = $Text.Replace('\', '\\').Replace('"', '\"')
        $Escaped = [regex]::Replace($Escaped, '[\x00-\x1f]', { param($M) '\u{0:x4}' -f [int][char]$M.Value })
        $null = $Builder.Append('"').Append($Escaped).Append('"')
    }

    $WriteNode = $null
    $WriteNode = {
        param($Node)
        if ($null -eq $Node) { $null = $Builder.Append('null'); return }
        if ($Node -is [string]) { & $WriteString $Node; return }
        if ($Node -is [bool]) { $null = $Builder.Append($(if ($Node) { 'true' } else { 'false' })); return }
        if ($Node -is [double] -or $Node -is [single]) { $null = $Builder.Append(([double]$Node).ToString('R', $Invariant)); return }
        if ($Node -is [System.Collections.IDictionary]) {
            $null = $Builder.Append('{')
            $First = $true
            foreach ($Key in $Node.Keys) {
                if (-not $First) { $null = $Builder.Append(',') }
                $First = $false
                & $WriteString ([string]$Key)
                $null = $Builder.Append(':')
                & $WriteNode $Node[$Key]
            }
            $null = $Builder.Append('}')
            return
        }
        if ($Node -is [System.Array]) {
            $null = $Builder.Append('[')
            for ($i = 0; $i -lt $Node.Count; $i++) {
                if ($i -gt 0) { $null = $Builder.Append(',') }
                & $WriteNode $Node[$i]
            }
            $null = $Builder.Append(']')
            return
        }
        if ($Node -is [System.IFormattable]) { $null = $Builder.Append($Node.ToString($null, $Invariant)); return }
        & $WriteString ([string]$Node)
    }

    & $WriteNode $Value
    return $Builder.ToString()
}
