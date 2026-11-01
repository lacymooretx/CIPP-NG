function Compare-CIPPBackupValue {
    <#
    .FUNCTIONALITY
        Internal
    .SYNOPSIS
        Property-level diff of two normalised values.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-23).

        Both inputs must be ConvertTo-CIPPBackupNormalizedValue output (ordered dictionaries, object[]
        and scalars). Returns one record per difference: @{ Path; Change = Added|Removed|Modified; Before; After }.

        Dictionaries are compared key by key. Arrays that hold the same elements in a different order
        are treated as equal (Graph does not guarantee array order). Arrays of equal length are then
        compared index by index (path[i]); arrays of different length report the elements present on
        only one side as Removed/Added at path[]. Complex Before/After values are rendered as canonical
        JSON and long values are truncated so a response stays readable.
    .PARAMETER Before
        The normalised earlier/existing value.
    .PARAMETER After
        The normalised later/incoming value.
    .PARAMETER Path
        Path prefix used in the output records.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]$Before,
        [AllowNull()]$After,
        [string]$Path = ''
    )

    $Changes = [System.Collections.Generic.List[object]]::new()
    $MaxLength = 2000

    $Render = {
        param($Value)
        if ($null -eq $Value -or $Value -is [string] -or $Value -is [bool] -or $Value -is [ValueType]) {
            if ($Value -is [string] -and $Value.Length -gt $MaxLength) { return $Value.Substring(0, $MaxLength) + '...(truncated)' }
            return $Value
        }
        $Json = ConvertTo-CIPPBackupCanonicalJson -Value $Value -Normalized
        if ($Json.Length -gt $MaxLength) { return $Json.Substring(0, $MaxLength) + '...(truncated)' }
        return $Json
    }
    $Canon = { param($Value) ConvertTo-CIPPBackupCanonicalJson -Value $Value -Normalized }
    $Join = {
        param([string]$Prefix, [string]$Name)
        if ([string]::IsNullOrEmpty($Prefix)) { return $Name }
        return "$Prefix.$Name"
    }
    $Record = {
        param([string]$P, [string]$Change, $B, $A)
        $Changes.Add([pscustomobject][ordered]@{ Path = $(if ($P) { $P } else { '(value)' }); Change = $Change; Before = (& $Render $B); After = (& $Render $A) })
    }

    $Walk = $null
    $Walk = {
        param($B, $A, [string]$P)
        $BIsDict = $B -is [System.Collections.IDictionary]
        $AIsDict = $A -is [System.Collections.IDictionary]
        $BIsList = $B -is [System.Array]
        $AIsList = $A -is [System.Array]

        if ($BIsDict -and $AIsDict) {
            $Keys = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($K in $B.Keys) { $null = $Keys.Add([string]$K) }
            foreach ($K in $A.Keys) { $null = $Keys.Add([string]$K) }
            foreach ($K in $Keys) {
                $Child = & $Join $P $K
                $InB = $B.Contains($K)
                $InA = $A.Contains($K)
                if ($InB -and -not $InA) { & $Record $Child 'Removed' $B[$K] $null }
                elseif ($InA -and -not $InB) { & $Record $Child 'Added' $null $A[$K] }
                else { & $Walk $B[$K] $A[$K] $Child }
            }
            return
        }

        if ($BIsList -and $AIsList) {
            $BCanon = @(foreach ($E in $B) { & $Canon $E })
            $ACanon = @(foreach ($E in $A) { & $Canon $E })
            if (($BCanon -join "`n") -ceq ($ACanon -join "`n")) { return }
            $SortedB = [string[]]$BCanon.Clone(); [Array]::Sort($SortedB, [System.StringComparer]::Ordinal)
            $SortedA = [string[]]$ACanon.Clone(); [Array]::Sort($SortedA, [System.StringComparer]::Ordinal)
            if (($SortedB -join "`n") -ceq ($SortedA -join "`n")) { return }
            if ($B.Count -eq $A.Count) {
                for ($i = 0; $i -lt $B.Count; $i++) { & $Walk $B[$i] $A[$i] "$($P)[$i]" }
                return
            }
            # Different lengths: report the multiset difference.
            $Remaining = [System.Collections.Generic.List[string]]::new()
            foreach ($C in $ACanon) { $Remaining.Add($C) }
            for ($i = 0; $i -lt $B.Count; $i++) {
                $Idx = $Remaining.IndexOf($BCanon[$i])
                if ($Idx -ge 0) { $Remaining.RemoveAt($Idx) } else { & $Record "$($P)[]" 'Removed' $B[$i] $null }
            }
            $Pool = [System.Collections.Generic.List[string]]::new()
            foreach ($C in $BCanon) { $Pool.Add($C) }
            for ($i = 0; $i -lt $A.Count; $i++) {
                $Idx = $Pool.IndexOf($ACanon[$i])
                if ($Idx -ge 0) { $Pool.RemoveAt($Idx) } else { & $Record "$($P)[]" 'Added' $null $A[$i] }
            }
            return
        }

        if ((& $Canon $B) -cne (& $Canon $A)) { & $Record $P 'Modified' $B $A }
    }

    & $Walk $Before $After $Path
    return , $Changes.ToArray()
}
