function Compare-CIPPBackupItemSet {
    <#
    .FUNCTIONALITY
        Internal
    .SYNOPSIS
        Diffs two sets of backup items (Get-CIPPBackupItemList output) per object.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-23).

        Objects are matched per Type by Key (and, when -UseAltKey, by AltKey as a fallback - e.g. a
        user whose object id changed but whose UPN did not). Each object is classified:
          Added      only in the Compare set
          Removed    only in the Base set
          Changed    in both, with at least one property difference (Changes lists them)
          Unchanged  in both, identical after volatile fields are ignored
        Volatile fields ignored at every depth: id, createdDateTime, lastModifiedDateTime, modifiedDateTime (CA), version,
        Timestamp, ETag and any @odata.* annotation; assignments too unless -IncludeAssignments.
    .PARAMETER BaseItems
        The earlier backup (or the live tenant, for a restore preview) item list.
    .PARAMETER CompareItems
        The later backup (or the backup being restored, for a restore preview) item list.
    .PARAMETER IncludeAssignments
        Compare 'assignments' properties instead of ignoring them.
    .PARAMETER UseAltKey
        Fall back to AltKey when Key does not match.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object[]]$BaseItems = @(),
        [AllowNull()][object[]]$CompareItems = @(),
        [switch]$IncludeAssignments,
        [switch]$UseAltKey
    )

    $Ignore = @('id', 'createdDateTime', 'lastModifiedDateTime', 'modifiedDateTime', 'version', 'Timestamp', 'ETag')
    if (-not $IncludeAssignments.IsPresent) { $Ignore += 'assignments' }
    $IgnoreLike = @('@odata*', '*@odata.*', 'odata.*')

    $Normalize = { param($Value) ConvertTo-CIPPBackupNormalizedValue -Value $Value -IgnoreProperty $Ignore -IgnorePropertyLike $IgnoreLike }

    $CompareByKey = @{}
    $CompareByAlt = @{}
    foreach ($Item in @($CompareItems)) {
        if ($null -eq $Item) { continue }
        $CompareByKey["$($Item.Type)`n$($Item.Key)"] = $Item
        if ($Item.AltKey) { $CompareByAlt["$($Item.Type)`n$($Item.AltKey)"] = $Item }
    }

    $Matched = @{}
    $Results = [System.Collections.Generic.List[object]]::new()
    foreach ($Item in @($BaseItems)) {
        if ($null -eq $Item) { continue }
        $Other = $CompareByKey["$($Item.Type)`n$($Item.Key)"]
        if (-not $Other -and $UseAltKey.IsPresent -and $Item.AltKey) { $Other = $CompareByAlt["$($Item.Type)`n$($Item.AltKey)"] }
        if ($Other -and $Matched.ContainsKey("$($Other.Type)`n$($Other.Key)")) { $Other = $null }

        if (-not $Other) {
            $Results.Add([pscustomobject][ordered]@{ Type = $Item.Type; Key = $Item.Key; Name = $Item.Name; Status = 'Removed'; Changes = @(); Base = $Item; Compare = $null })
            continue
        }
        $Matched["$($Other.Type)`n$($Other.Key)"] = $true
        $Changes = Compare-CIPPBackupValue -Before (& $Normalize $Item.Content) -After (& $Normalize $Other.Content)
        $Status = if (@($Changes).Count -gt 0) { 'Changed' } else { 'Unchanged' }
        $Results.Add([pscustomobject][ordered]@{ Type = $Item.Type; Key = $Item.Key; Name = $Item.Name; Status = $Status; Changes = @($Changes); Base = $Item; Compare = $Other })
    }
    foreach ($Item in @($CompareItems)) {
        if ($null -eq $Item) { continue }
        if ($Matched.ContainsKey("$($Item.Type)`n$($Item.Key)")) { continue }
        $Results.Add([pscustomobject][ordered]@{ Type = $Item.Type; Key = $Item.Key; Name = $Item.Name; Status = 'Added'; Changes = @(); Base = $null; Compare = $Item })
    }
    return , $Results.ToArray()
}
