function New-CIPPBackupManifest {
    <#
    .FUNCTIONALITY
        Internal
    .SYNOPSIS
        Builds the integrity manifest for a backup: SHA-256 of the whole file, SHA-256 per item, item counts per type.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-23).

        The manifest is computed from the exact JSON text that is uploaded, parsed back with
        ConvertFrom-Json - the same path verification takes - so the write side and the verify side
        hash identical structures. Item hashes are taken over canonical JSON (sorted keys), so they
        survive a round trip even when property order changes.

        Shape (HashVersion 1):
          { HashVersion, Algorithm, Canonicalization, BackupSha256, CreatedUtc,
            ItemCounts: { <type>: n },
            Types: [ { Type, Count, Items: [ { Key, Sha256 } ] } ] }
    .PARAMETER BackupJson
        The backup file content exactly as written to storage.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupJson
    )

    $Parsed = ConvertFrom-Json -InputObject $BackupJson.TrimStart([char]0xFEFF) -Depth 100 -NoEnumerate -ErrorAction Stop
    $Items = Get-CIPPBackupItemList -Backup $Parsed

    $Counts = [ordered]@{}
    $TypeBlocks = [System.Collections.Generic.List[object]]::new()
    foreach ($Group in ($Items | Group-Object -Property Type | Sort-Object -Property Name)) {
        $Hashes = foreach ($Item in $Group.Group) {
            [ordered]@{
                Key    = $Item.Key
                Sha256 = Get-CIPPBackupSha256 -Text (ConvertTo-CIPPBackupCanonicalJson -Value $Item.Raw)
            }
        }
        $Counts[$Group.Name] = $Group.Count
        $TypeBlocks.Add([ordered]@{
                Type  = $Group.Name
                Count = $Group.Count
                Items = @($Hashes)
            })
    }

    return [pscustomobject][ordered]@{
        HashVersion      = 1
        Algorithm        = 'SHA256'
        Canonicalization = 'cipp-sorted-keys-v1'
        BackupSha256     = Get-CIPPBackupSha256 -Text $BackupJson
        CreatedUtc       = [datetime]::UtcNow.ToString('o')
        ItemCounts       = $Counts
        Types            = $TypeBlocks.ToArray()
    }
}
