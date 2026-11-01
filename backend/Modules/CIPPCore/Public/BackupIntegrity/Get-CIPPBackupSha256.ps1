function Get-CIPPBackupSha256 {
    <#
    .FUNCTIONALITY
        Internal
    .SYNOPSIS
        Lower-case hex SHA-256 of a string's UTF-8 bytes.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-23). A leading byte-order mark is ignored so a blob that
        was read back with a BOM hashes the same as the string that was written.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowEmptyString()]
        [string]$Text
    )
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Text.TrimStart([char]0xFEFF))
    $Hash = [System.Security.Cryptography.SHA256]::HashData($Bytes)
    return ([System.Convert]::ToHexString($Hash)).ToLowerInvariant()
}
