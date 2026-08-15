function Get-CIPPWelcomePacketFirstName {
    <#
    .SYNOPSIS
    Works out what to call someone on the front of their welcome packet.

    .DESCRIPTION
    The sheet opens 'Welcome, <first name>.' Getting this wrong is the one error on
    the packet a new hire is guaranteed to notice, so it is worth more than a
    substring.

    givenName is used when Entra has it. When it does not -- common for accounts
    created by a sync or in bulk -- the display name is parsed, including the
    'Last, First' form that comes out of HR systems and would otherwise greet
    somebody by their surname.

    Returns an empty string rather than a guess when there is nothing usable; the
    caller decides whether a greeting without a name is better than a wrong one.

    Aspendora fork addition.

    .PARAMETER User
    A Graph user object, or anything with givenName and displayName.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $User
    )

    if (![string]::IsNullOrWhiteSpace($User.givenName)) {
        return $User.givenName.Trim()
    }

    $DisplayName = "$($User.displayName)".Trim()
    if ([string]::IsNullOrWhiteSpace($DisplayName)) {
        return ''
    }

    # 'Whitfield, Dana' -> 'Dana'. Take the first word after the comma so a middle
    # name or initial does not end up in the greeting.
    $Comma = $DisplayName.IndexOf(',')
    if ($Comma -ge 0) {
        $AfterComma = $DisplayName.Substring($Comma + 1).Trim()
        return ($AfterComma -split '\s+' | Where-Object { $_ } | Select-Object -First 1) ?? ''
    }

    return ($DisplayName -split '\s+' | Select-Object -First 1)
}
