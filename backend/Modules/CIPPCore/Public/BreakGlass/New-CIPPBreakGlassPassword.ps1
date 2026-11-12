function New-CIPPBreakGlassPassword {
    <#
    .SYNOPSIS
        A random 64-character password for a new break-glass account. It is set once at creation and discarded.
    .DESCRIPTION
        CIPP never stores, logs or returns this value. ControlR rotates the account straight afterwards and its
        KeeperRotationService owns the real credential (Keeper first, then Entra).
        No '%' in the alphabet: New-GraphPOSTRequest runs request bodies through Get-CIPPTextReplacement, which
        would rewrite a %token%. No quotes or backslashes, so JSON escaping cannot change it.
        Aspendora fork addition (onboarding Phase 3).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([int]$Length = 64)
    $Sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!#$*+-.:=?@^_~')
    $All = ($Sets -join '').ToCharArray()
    $Chars = [System.Collections.Generic.List[char]]::new()
    # One from each set guarantees Entra's complexity rule, the rest from the full alphabet.
    foreach ($S in $Sets) { $Chars.Add($S[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($S.Length)]) }
    while ($Chars.Count -lt $Length) { $Chars.Add($All[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($All.Length)]) }
    # Fisher-Yates so the guaranteed characters are not always first.
    for ($i = $Chars.Count - 1; $i -gt 0; $i--) {
        $j = [System.Security.Cryptography.RandomNumberGenerator]::GetInt32($i + 1)
        $T = $Chars[$i]; $Chars[$i] = $Chars[$j]; $Chars[$j] = $T
    }
    return -join $Chars
}
