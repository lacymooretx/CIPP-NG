function Test-CIPPIntuneAssignmentFilterRule {
    <#
    .SYNOPSIS
        Evaluates an Intune assignment filter rule against the device properties CIPP can read.
    .DESCRIPTION
        Pure function, no Graph calls. Returns $true (the device matches the rule), $false (it does not) or $null
        (not evaluated). $null is returned whenever the answer cannot be computed reliably: an unknown property, an
        operator not implemented here, a device property that is empty, a value that does not parse, or a rule
        that does not parse. Three-valued (Kleene) logic is used for and/or/not, so one unevaluable clause only
        poisons the result when it can actually change it ("A or B" is still $true when A is $true).

        Supported properties (device.<name>): deviceName, manufacturer, model, osVersion / operatingSystemVersion,
        enrollmentProfileName, deviceOwnership (Corporate / Personal), deviceCategory, operatingSystemSKU.
        Supported operators: -eq -ne -startsWith -notStartsWith -endsWith -notEndsWith -contains -notContains
        -in -notIn, and -gt -ge -lt -le for operatingSystemVersion only (compared as versions). String comparisons
        are case-insensitive, as Intune's are. -match / -notMatch are deliberately NOT evaluated: Intune's regex
        dialect is not documented to match .NET's, and a wrong answer is worse than "not evaluated".
        Aspendora fork addition (Vikunja CIPP-19).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [string]$Rule,
        # Keys are the property names above without the "device." prefix (case-insensitive).
        [hashtable]$Device = @{}
    )

    if ([string]::IsNullOrWhiteSpace($Rule)) { return $null }

    # --- Tokenise ---------------------------------------------------------------------------------
    $Tokens = [System.Collections.Generic.List[object]]::new()
    $i = 0
    $Len = $Rule.Length
    while ($i -lt $Len) {
        $c = $Rule[$i]
        if ([char]::IsWhiteSpace($c)) { $i++; continue }
        if ($c -eq '(' -or $c -eq ')' -or $c -eq '[' -or $c -eq ']' -or $c -eq ',') { $Tokens.Add(@{ T = [string]$c }); $i++; continue }
        if ($c -eq '"' -or $c -eq "'") {
            $Quote = $c; $j = $i + 1; $Sb = [System.Text.StringBuilder]::new()
            while ($j -lt $Len -and $Rule[$j] -ne $Quote) { $null = $Sb.Append($Rule[$j]); $j++ }
            if ($j -ge $Len) { return $null } # unterminated string
            $Tokens.Add(@{ T = 'STR'; V = $Sb.ToString() }); $i = $j + 1; continue
        }
        if ($c -eq '-') {
            $j = $i + 1
            while ($j -lt $Len -and [char]::IsLetter($Rule[$j])) { $j++ }
            $Tokens.Add(@{ T = 'OP'; V = $Rule.Substring($i + 1, $j - $i - 1).ToLowerInvariant() }); $i = $j; continue
        }
        $j = $i
        while ($j -lt $Len -and -not [char]::IsWhiteSpace($Rule[$j]) -and [string]$Rule[$j] -notin @('(', ')', '[', ']', ',', '"', "'")) { $j++ }
        $Word = $Rule.Substring($i, $j - $i)
        switch ($Word.ToLowerInvariant()) {
            'and' { $Tokens.Add(@{ T = 'AND' }) }
            'or' { $Tokens.Add(@{ T = 'OR' }) }
            'not' { $Tokens.Add(@{ T = 'NOT' }) }
            default { $Tokens.Add(@{ T = 'WORD'; V = $Word }) }
        }
        $i = $j
    }

    # Device properties, case-insensitive.
    $Props = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($K in $Device.Keys) { $Props[[string]$K] = $Device[$K] }
    if ($Props.ContainsKey('osVersion') -and -not $Props.ContainsKey('operatingSystemVersion')) { $Props['operatingSystemVersion'] = $Props['osVersion'] }
    $Supported = @('deviceName', 'manufacturer', 'model', 'operatingSystemVersion', 'osVersion', 'enrollmentProfileName', 'deviceOwnership', 'deviceCategory', 'operatingSystemSKU')

    $State = @{ Pos = 0; Failed = $false }
    $Peek = { if ($State.Pos -lt $Tokens.Count) { $Tokens[$State.Pos] } else { @{ T = 'EOF' } } }
    $Next = { $Tok = & $Peek; $State.Pos++; $Tok }

    $And3 = { param($a, $b) if ($a -eq $false -or $b -eq $false) { $false } elseif ($null -eq $a -or $null -eq $b) { $null } else { $true } }
    $Or3 = { param($a, $b) if ($a -eq $true -or $b -eq $true) { $true } elseif ($null -eq $a -or $null -eq $b) { $null } else { $false } }

    $Compare = {
        param([string]$Prop, [string]$Op, $Values)
        $Name = $Prop -replace '^device\.', ''
        if ($Prop -notmatch '^device\.' -or $Name -notin $Supported) { return $null }
        $Actual = $Props[$Name]
        if ($null -eq $Actual -or [string]::IsNullOrEmpty([string]$Actual)) { return $null }
        $Actual = [string]$Actual
        $Values = @($Values | ForEach-Object { [string]$_ })
        $V = if ($Values.Count -gt 0) { $Values[0] } else { '' }
        $Cmp = [System.StringComparison]::OrdinalIgnoreCase
        switch ($Op) {
            'eq' { return [string]::Equals($Actual, $V, $Cmp) }
            'ne' { return -not [string]::Equals($Actual, $V, $Cmp) }
            'startswith' { return $Actual.StartsWith($V, $Cmp) }
            'notstartswith' { return -not $Actual.StartsWith($V, $Cmp) }
            'endswith' { return $Actual.EndsWith($V, $Cmp) }
            'notendswith' { return -not $Actual.EndsWith($V, $Cmp) }
            'contains' { return $Actual.IndexOf($V, $Cmp) -ge 0 }
            'notcontains' { return $Actual.IndexOf($V, $Cmp) -lt 0 }
            'in' { return [bool](@($Values | Where-Object { [string]::Equals($Actual, $_, $Cmp) }).Count) }
            'notin' { return -not [bool](@($Values | Where-Object { [string]::Equals($Actual, $_, $Cmp) }).Count) }
            { $_ -in @('gt', 'ge', 'lt', 'le') } {
                if ($Name -notin @('operatingSystemVersion', 'osVersion')) { return $null }
                $A = $null; $B = $null
                if (-not [version]::TryParse($Actual, [ref]$A) -or -not [version]::TryParse($V, [ref]$B)) { return $null }
                $R = $A.CompareTo($B)
                switch ($Op) { 'gt' { return $R -gt 0 } 'ge' { return $R -ge 0 } 'lt' { return $R -lt 0 } 'le' { return $R -le 0 } }
            }
            default { return $null } # match / notMatch and anything unknown
        }
    }

    $ParseOr = $null; $ParseAnd = $null; $ParseUnary = $null
    $ParseUnary = {
        $Tok = & $Peek
        if ($Tok.T -eq 'NOT') { $null = & $Next; $R = & $ParseUnary; if ($null -eq $R) { return $null }; return -not $R }
        if ($Tok.T -eq '(') {
            $null = & $Next
            $R = & $ParseOr
            if ((& $Next).T -ne ')') { $State.Failed = $true }
            return $R
        }
        if ($Tok.T -eq 'WORD') {
            $Prop = (& $Next).V
            $OpTok = & $Next
            if ($OpTok.T -ne 'OP') { $State.Failed = $true; return $null }
            $ValTok = & $Next
            $Values = @()
            if ($ValTok.T -eq 'STR' -or $ValTok.T -eq 'WORD') {
                $Values = @($ValTok.V)
            } elseif ($ValTok.T -eq '[') {
                while ($true) {
                    $Item = & $Next
                    if ($Item.T -eq ']') { break }
                    if ($Item.T -eq ',') { continue }
                    if ($Item.T -eq 'STR' -or $Item.T -eq 'WORD') { $Values += $Item.V; continue }
                    $State.Failed = $true; return $null
                }
            } else { $State.Failed = $true; return $null }
            return (& $Compare $Prop $OpTok.V $Values)
        }
        $State.Failed = $true
        return $null
    }
    $ParseAnd = {
        $L = & $ParseUnary
        while ((& $Peek).T -eq 'AND') { $null = & $Next; $R = & $ParseUnary; $L = & $And3 $L $R }
        return $L
    }
    $ParseOr = {
        $L = & $ParseAnd
        while ((& $Peek).T -eq 'OR') { $null = & $Next; $R = & $ParseAnd; $L = & $Or3 $L $R }
        return $L
    }

    $Result = & $ParseOr
    if ($State.Failed -or $State.Pos -ne $Tokens.Count) { return $null }
    return $Result
}
