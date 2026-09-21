function ConvertTo-CIPPBoolean {
    <#
    .FUNCTIONALITY
    Internal
    .DESCRIPTION
        Coerce a loosely-typed flag from an HTTP request into a real boolean.

        Replaces the `ConvertTo-CIPPBoolean -Value $Value` idiom, which was wrong in a way that read as
        correct. `-in` compares as the COLLECTION's element type, so with $true in the list
        PowerShell converts the right-hand side to boolean, and every non-empty string is
        boolean true:

            'false' -in @($true,'true',1,'1','yes','on')   ->  True
            'no'    -in @(...)                             ->  True
            '0'     -in @(...)                             ->  True

        So a caller explicitly turning a flag OFF turned it ON. On a read flag that is a wrong
        answer; on ExecCloudPCProvisioningPolicyAssign's AllowRemoveAll it would have authorised
        unassigning a provisioning policy from every group in the tenant.

        Only the listed false words are false, only the listed true words are true, and anything
        unrecognised falls back to $Default rather than being guessed - an unparseable flag should
        behave like an absent one, not like "on".
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()][Parameter(Position = 0)]$Value,
        [bool]$Default = $false
    )

    if ($null -eq $Value) { return $Default }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
        return ([double]$Value -ne 0)
    }

    $Text = "$Value".Trim().ToLowerInvariant()
    if ($Text -eq '') { return $Default }
    if ($Text -in @('true', '1', 'yes', 'on', 'y', 't')) { return $true }
    if ($Text -in @('false', '0', 'no', 'off', 'n', 'f')) { return $false }
    return $Default
}
