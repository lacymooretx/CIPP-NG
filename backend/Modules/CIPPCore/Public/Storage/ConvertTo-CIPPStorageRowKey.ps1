function ConvertTo-CIPPStorageRowKey {
    <#
    .SYNOPSIS
        Build a table-safe RowKey for a storage snapshot row.
    .DESCRIPTION
        Azure Table Storage rejects '/', '\', '#' and '?' plus control characters in a
        RowKey, and caps it at 1024 characters. UPNs and SharePoint site identifiers can
        contain several of those, and a rejected key fails the whole 100-row transaction -
        so one awkward mailbox would silently cost a hundred rows.

        The scope prefix and date come first so a prefix range scan can select "every site
        row for this date" server-side, which is how the readers and the retention rule
        query it.

        Sanitising can in principle collapse two different identifiers onto one key. A short
        hash of the original is appended whenever anything was replaced, so a collision
        needs both the sanitised form and the hash to match. The unmodified identifier is
        stored separately in the ObjectId column, so nothing is lost either way.

    .PARAMETER Scope
        'Mailbox' or 'Site'.
    .PARAMETER Date
        Snapshot date, compact yyyyMMdd.
    .PARAMETER Id
        The object identifier - UPN or site id.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Scope,
        [Parameter(Mandatory = $true)][string]$Date,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Id
    )

    $Clean = $Id -replace '[\\/#?]', '_'
    $Clean = [regex]::Replace($Clean, '[\x00-\x1F\x7F-\x9F]', '')

    if ($Clean -ne $Id) {
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Id)
        $Sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $Hash = ([System.BitConverter]::ToString($Sha.ComputeHash($Bytes)) -replace '-', '').Substring(0, 8).ToLowerInvariant()
        } finally {
            $Sha.Dispose()
        }
        $Clean = "$Clean~$Hash"
    }

    $Key = '{0}-{1}-{2}' -f $Scope, $Date, $Clean
    if ($Key.Length -gt 1024) { $Key = $Key.Substring(0, 1024) }
    return $Key
}
