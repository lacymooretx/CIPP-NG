function New-CIPPBreakGlassAccountName {
    <#
    .SYNOPSIS
        Proposes break-glass account names: bg-<8 random chars>@<tenant>.onmicrosoft.com.
    .DESCRIPTION
        The random part makes the name hard to guess (a failed sign-in alert means someone knows the name).
        The bg- prefix never matches ControlR's *_admin rotation patterns, so the account is not rotated on a
        schedule by accident. ControlR's break-glass rotate route also checks for this prefix.
        Pure function. Aspendora fork addition (onboarding Phase 3).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InitialDomain,
        [int]$Count = 2,
        # UPNs already in use in the tenant, so a collision is never proposed.
        [string[]]$Existing = @()
    )
    if ($InitialDomain -notmatch '^[A-Za-z0-9-]+\.onmicrosoft\.com$') {
        throw "Break-glass accounts must use the tenant's *.onmicrosoft.com domain, not '$InitialDomain'."
    }
    $Alphabet = 'abcdefghjkmnpqrstuvwxyz23456789'.ToCharArray()
    $Taken = @($Existing | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $Names = [System.Collections.Generic.List[string]]::new()
    while ($Names.Count -lt $Count) {
        $Bytes = [byte[]]::new(8)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($Bytes)
        $Suffix = -join ($Bytes | ForEach-Object { $Alphabet[$_ % $Alphabet.Length] })
        $Upn = "bg-$Suffix@$($InitialDomain.ToLowerInvariant())"
        if ($Upn -notin $Taken -and $Upn -notin $Names) { $Names.Add($Upn) }
    }
    return @($Names)
}
