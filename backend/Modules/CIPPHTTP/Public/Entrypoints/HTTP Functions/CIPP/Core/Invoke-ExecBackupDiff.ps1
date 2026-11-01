function Invoke-ExecBackupDiff {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        CIPP.Backup.Read
    .SYNOPSIS
        Compare two backups of the same tenant object by object, with a property-level diff
    .DESCRIPTION
        Diffs BackupA (base, usually the older) against BackupB. Every object is Added (only in B),
        Removed (only in A), Changed (in both, with a list of property changes: Path, Change
        Added|Removed|Modified, Before, After) or Unchanged (counted, not listed). Intune and CA
        policies are matched by name, users and groups by object id. Volatile fields are ignored: id,
        createdDateTime, lastModifiedDateTime, version, Timestamp, ETag, @odata.* annotations, and
        assignments unless IncludeAssignments=true. Read-only.
        Parameters: BackupA, BackupB, tenantFilter (all required; both backups must belong to it),
        Types (optional component filter, array or comma-separated), IncludeAssignments,
        Type (Scheduled|CIPP, default Scheduled).
        Aspendora fork addition (Vikunja CIPP-23).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $BackupA = [string]($Request.Body.BackupA ?? $Request.Query.BackupA)
    $BackupB = [string]($Request.Body.BackupB ?? $Request.Query.BackupB)
    $TenantFilter = [string]($Request.Body.tenantFilter ?? $Request.Query.tenantFilter)
    $Type = [string]($Request.Body.Type ?? $Request.Query.Type ?? 'Scheduled')
    $IncludeAssignments = ConvertTo-CIPPBoolean -Value ($Request.Body.IncludeAssignments ?? $Request.Query.IncludeAssignments)
    $RawTypes = $Request.Body.Types ?? $Request.Query.Types
    $Types = @(foreach ($T in @($RawTypes)) {
            if ($null -eq $T) { continue }
            $V = if ($T -is [string]) { $T } else { [string]($T.value ?? $T) }
            foreach ($Part in ($V -split ',')) { if ($Part.Trim()) { $Part.Trim() } }
        })
    $Respond = { param($Code, $Body) [HttpResponseContext]@{ StatusCode = $Code; Body = $Body } }

    if (-not $BackupA -or -not $BackupB) { return (& $Respond ([HttpStatusCode]::BadRequest) @{ Results = 'BackupA and BackupB are required.' }) }
    if ($Type -notin @('Scheduled', 'CIPP')) { return (& $Respond ([HttpStatusCode]::BadRequest) @{ Results = 'Type must be Scheduled or CIPP.' }) }
    if ($Type -eq 'Scheduled' -and -not $TenantFilter) { return (& $Respond ([HttpStatusCode]::BadRequest) @{ Results = 'tenantFilter is required for tenant backups.' }) }

    try {
        $A = Get-CIPPBackupContent -Type $Type -Name $BackupA -TenantFilter $TenantFilter
        $B = Get-CIPPBackupContent -Type $Type -Name $BackupB -TenantFilter $TenantFilter
    } catch {
        if ($_.Exception.Message -like '*does not belong to tenant*') {
            return (& $Respond ([HttpStatusCode]::Forbidden) @{ Results = $_.Exception.Message })
        }
        $ErrorMessage = Get-CippException -Exception $_
        return (& $Respond ([HttpStatusCode]::InternalServerError) @{ Results = "Could not load backups: $($ErrorMessage.NormalizedError)" })
    }
    if (-not $A) { return (& $Respond ([HttpStatusCode]::NotFound) @{ Results = "Backup $BackupA not found." }) }
    if (-not $B) { return (& $Respond ([HttpStatusCode]::NotFound) @{ Results = "Backup $BackupB not found." }) }
    if ($Type -eq 'Scheduled' -and $A.TenantFilter -ne $B.TenantFilter) {
        return (& $Respond ([HttpStatusCode]::BadRequest) @{ Results = 'Both backups must belong to the same tenant.' })
    }
    foreach ($Loaded in @($A, $B)) {
        if (-not $Loaded.Readable) {
            return (& $Respond ([HttpStatusCode]::UnprocessableEntity) @{ Results = "Backup $($Loaded.Entity.RowKey) could not be read from storage." })
        }
    }

    try {
        $ParsedA = ConvertFrom-Json -InputObject $A.Json.TrimStart([char]0xFEFF) -Depth 100 -NoEnumerate -ErrorAction Stop
        $ParsedB = ConvertFrom-Json -InputObject $B.Json.TrimStart([char]0xFEFF) -Depth 100 -NoEnumerate -ErrorAction Stop
        $TypeArgs = @{}
        if ($Types.Count -gt 0) { $TypeArgs.Types = $Types }
        $ItemsA = Get-CIPPBackupItemList -Backup $ParsedA @TypeArgs
        $ItemsB = Get-CIPPBackupItemList -Backup $ParsedB @TypeArgs
        $Diff = Compare-CIPPBackupItemSet -BaseItems $ItemsA -CompareItems $ItemsB -IncludeAssignments:$IncludeAssignments
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'ExecBackupDiff' -tenant $TenantFilter -message "Could not compare backups $BackupA and $($BackupB): $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return (& $Respond ([HttpStatusCode]::InternalServerError) @{ Results = "Could not compare backups: $($ErrorMessage.NormalizedError)" })
    }

    $Count = { param($Status, $Set) @($Set | Where-Object { $_.Status -eq $Status }).Count }
    $TypeSummary = foreach ($Group in ($Diff | Group-Object -Property Type | Sort-Object -Property Name)) {
        [pscustomobject][ordered]@{
            Type      = $Group.Name
            Added     = & $Count 'Added' $Group.Group
            Removed   = & $Count 'Removed' $Group.Group
            Changed   = & $Count 'Changed' $Group.Group
            Unchanged = & $Count 'Unchanged' $Group.Group
        }
    }
    $Objects = foreach ($Entry in ($Diff | Where-Object { $_.Status -ne 'Unchanged' })) {
        [pscustomobject][ordered]@{
            Type    = $Entry.Type
            Key     = $Entry.Key
            Name    = $Entry.Name
            Status  = $Entry.Status
            Changes = @($Entry.Changes)
        }
    }

    return (& $Respond ([HttpStatusCode]::OK) @{
            Results = [pscustomobject][ordered]@{
                BackupA            = $BackupA
                BackupB            = $BackupB
                TenantFilter       = $A.TenantFilter
                IncludeAssignments = $IncludeAssignments
                Summary            = [pscustomobject][ordered]@{
                    Added     = & $Count 'Added' $Diff
                    Removed   = & $Count 'Removed' $Diff
                    Changed   = & $Count 'Changed' $Diff
                    Unchanged = & $Count 'Unchanged' $Diff
                }
                Types              = @($TypeSummary)
                Objects            = @($Objects)
            }
        })
}
