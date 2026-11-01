function Test-CIPPBackupIntegrity {
    <#
    .FUNCTIONALITY
        Internal
    .SYNOPSIS
        Recomputes a backup's hashes and counts and compares them with what was recorded at write time.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-23). Pure: no storage or Graph calls, so it is unit tested
        on fixtures. Get-CIPPBackupIntegrityReport does the fetching.

        Status values:
          Verified                 file SHA-256 matches and every item and count matches
          Unverified (pre-hash)    the backup was written before hashing existed; only counts are reported
          Corrupt                  file or manifest hash mismatch, an item hash mismatch, or unparseable JSON
          Missing                  the file could not be read, or items listed in the manifest are absent
          CountMismatch            items or counts differ from the manifest without any hash mismatch
    .PARAMETER BackupJson
        The backup file content as read back from storage ($null/empty when it could not be read).
    .PARAMETER Manifest
        The parsed manifest, or $null when none was found.
    .PARAMETER ManifestJson
        The manifest text as read back, used to check it against the ManifestSha256 on the table row.
    .PARAMETER Entity
        The backup's table row (HashVersion, BackupSha256, ManifestSha256, ItemCounts).
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$BackupJson,
        [AllowNull()]$Manifest,
        [AllowNull()][AllowEmptyString()][string]$ManifestJson,
        [AllowNull()]$Entity
    )

    $Issues = [System.Collections.Generic.List[string]]::new()
    $TypeResults = [System.Collections.Generic.List[object]]::new()
    $EntityHashVersion = 0
    if ($null -ne $Entity -and $null -ne $Entity.HashVersion) { $EntityHashVersion = [int]$Entity.HashVersion }
    $HasHashes = $EntityHashVersion -ge 1 -or $null -ne $Manifest

    $Finish = {
        param([string]$Status, [string]$Detail, $ActualSha, $ExpectedSha)
        return [pscustomobject][ordered]@{
            Status               = $Status
            Detail               = $Detail
            HashVersion          = if ($null -ne $Manifest -and $Manifest.HashVersion) { [int]$Manifest.HashVersion } else { $EntityHashVersion }
            BackupSha256Expected = $ExpectedSha
            BackupSha256Actual   = $ActualSha
            ManifestFound        = $null -ne $Manifest
            Issues               = $Issues.ToArray()
            Types                = $TypeResults.ToArray()
        }
    }

    if ([string]::IsNullOrWhiteSpace($BackupJson)) {
        $Issues.Add('The backup file could not be read from storage.')
        return (& $Finish 'Missing' 'Backup file missing or unreadable' $null $null)
    }

    $ActualSha = Get-CIPPBackupSha256 -Text $BackupJson
    try {
        $Parsed = ConvertFrom-Json -InputObject $BackupJson.TrimStart([char]0xFEFF) -Depth 100 -NoEnumerate -ErrorAction Stop
    } catch {
        $Issues.Add("The backup file is not valid JSON: $($_.Exception.Message)")
        return (& $Finish 'Corrupt' 'Backup file is not valid JSON' $ActualSha $null)
    }

    $ActualItems = Get-CIPPBackupItemList -Backup $Parsed
    $ActualByType = @{}
    foreach ($Item in $ActualItems) {
        if (-not $ActualByType.ContainsKey($Item.Type)) { $ActualByType[$Item.Type] = [System.Collections.Generic.List[object]]::new() }
        $ActualByType[$Item.Type].Add($Item)
    }

    if (-not $HasHashes) {
        foreach ($Type in ($ActualByType.Keys | Sort-Object)) {
            $TypeResults.Add([pscustomobject][ordered]@{
                    Type = $Type; ExpectedCount = $null; ActualCount = $ActualByType[$Type].Count
                    Missing = @(); Corrupt = @(); Unexpected = @(); Status = 'Unverified'
                })
        }
        return (& $Finish 'Unverified (pre-hash)' 'This backup was written before hashing was added; it can be read but not verified.' $ActualSha $null)
    }

    # ---- what was recorded at write time ----
    $Tampered = $false
    if (-not $Manifest) { $Issues.Add('The integrity manifest is missing; checking the file hash and counts from the table row only.') }
    if ($ManifestJson -and $Entity.ManifestSha256 -and (Get-CIPPBackupSha256 -Text $ManifestJson) -ne [string]$Entity.ManifestSha256) {
        $Issues.Add('The manifest does not match the hash recorded on the backup row.')
        $Tampered = $true
    }
    if ($Manifest.BackupSha256 -and $Entity.BackupSha256 -and [string]$Manifest.BackupSha256 -ne [string]$Entity.BackupSha256) {
        $Issues.Add('The manifest and the backup row disagree about the file hash.')
        $Tampered = $true
    }
    $ExpectedSha = if ($Entity.BackupSha256) { [string]$Entity.BackupSha256 } elseif ($Manifest.BackupSha256) { [string]$Manifest.BackupSha256 } else { $null }
    $FileMatches = $ExpectedSha -and ($ActualSha -eq $ExpectedSha)
    if ($ExpectedSha -and -not $FileMatches) { $Issues.Add('The backup file hash does not match the hash recorded when it was written.') }

    $ExpectedCounts = @{}
    $CountSource = if ($Manifest -and $Manifest.ItemCounts) { $Manifest.ItemCounts } elseif ($Entity.ItemCounts) {
        if ($Entity.ItemCounts -is [string]) { try { $Entity.ItemCounts | ConvertFrom-Json -ErrorAction Stop } catch { $null } } else { $Entity.ItemCounts }
    } else { $null }
    if ($CountSource) {
        if ($CountSource -is [System.Collections.IDictionary]) {
            foreach ($CountKey in $CountSource.Keys) { $ExpectedCounts[[string]$CountKey] = [int]$CountSource[$CountKey] }
        } else {
            foreach ($CountProperty in $CountSource.PSObject.Properties) { $ExpectedCounts[$CountProperty.Name] = [int]$CountProperty.Value }
        }
    }

    $ExpectedHashes = @{}
    foreach ($Block in @($Manifest.Types)) {
        if ($null -eq $Block) { continue }
        $Map = @{}
        foreach ($Entry in @($Block.Items)) { if ($null -ne $Entry) { $Map[[string]$Entry.Key] = [string]$Entry.Sha256 } }
        $ExpectedHashes[[string]$Block.Type] = $Map
    }

    $AllTypes = @(@($ExpectedCounts.Keys) + @($ExpectedHashes.Keys) + @($ActualByType.Keys) | Sort-Object -Unique)
    $AnyCorrupt = $false; $AnyMissing = $false; $AnyCount = $false
    foreach ($Type in $AllTypes) {
        $Actual = if ($ActualByType.ContainsKey($Type)) { $ActualByType[$Type] } else { @() }
        $ExpectedCount = if ($ExpectedCounts.ContainsKey($Type)) { $ExpectedCounts[$Type] } elseif ($ExpectedHashes.ContainsKey($Type)) { $ExpectedHashes[$Type].Count } else { 0 }
        $Missing = [System.Collections.Generic.List[string]]::new()
        $Corrupt = [System.Collections.Generic.List[string]]::new()
        $Unexpected = [System.Collections.Generic.List[string]]::new()
        if ($ExpectedHashes.ContainsKey($Type)) {
            $Expected = $ExpectedHashes[$Type]
            $ActualMap = @{}
            foreach ($Item in $Actual) { $ActualMap[$Item.Key] = Get-CIPPBackupSha256 -Text (ConvertTo-CIPPBackupCanonicalJson -Value $Item.Raw) }
            foreach ($Key in ($Expected.Keys | Sort-Object)) {
                if (-not $ActualMap.ContainsKey($Key)) { $Missing.Add($Key) }
                elseif ($ActualMap[$Key] -ne $Expected[$Key]) { $Corrupt.Add($Key) }
            }
            foreach ($Key in ($ActualMap.Keys | Sort-Object)) { if (-not $Expected.ContainsKey($Key)) { $Unexpected.Add($Key) } }
        }
        $CountOk = $ExpectedCount -eq $Actual.Count
        $TypeStatus = if ($Corrupt.Count -gt 0) { 'Corrupt' } elseif ($Missing.Count -gt 0) { 'Missing' } elseif (-not $CountOk -or $Unexpected.Count -gt 0) { 'CountMismatch' } else { 'Verified' }
        if ($TypeStatus -eq 'Corrupt') { $AnyCorrupt = $true }
        if ($TypeStatus -eq 'Missing') { $AnyMissing = $true }
        if ($TypeStatus -eq 'CountMismatch') { $AnyCount = $true }
        $TypeResults.Add([pscustomobject][ordered]@{
                Type          = $Type
                ExpectedCount = $ExpectedCount
                ActualCount   = $Actual.Count
                Missing       = $Missing.ToArray()
                Corrupt       = $Corrupt.ToArray()
                Unexpected    = $Unexpected.ToArray()
                Status        = $TypeStatus
            })
    }

    if ($Tampered -or $AnyCorrupt -or ($ExpectedSha -and -not $FileMatches -and -not $AnyMissing -and -not $AnyCount)) {
        $Detail = if ($AnyCorrupt) { 'One or more items differ from the hash recorded at write time' }
        elseif ($Tampered) { 'The integrity manifest does not match the backup row' }
        else { 'The file bytes changed since it was written' }
        return (& $Finish 'Corrupt' $Detail $ActualSha $ExpectedSha)
    }
    if ($AnyMissing) { return (& $Finish 'Missing' 'Items recorded at write time are absent from the file' $ActualSha $ExpectedSha) }
    if ($AnyCount) { return (& $Finish 'CountMismatch' 'Item counts differ from those recorded at write time' $ActualSha $ExpectedSha) }
    if (-not $ExpectedSha) { $Issues.Add('No file hash was recorded; verified item counts only.') }
    return (& $Finish 'Verified' 'Hashes and counts match what was recorded when the backup was written' $ActualSha $ExpectedSha)
}
