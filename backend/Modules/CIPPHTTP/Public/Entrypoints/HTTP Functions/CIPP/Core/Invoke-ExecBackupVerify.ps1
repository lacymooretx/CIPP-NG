function Invoke-ExecBackupVerify {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        CIPP.Backup.Read
    .SYNOPSIS
        Verify a stored backup against the hashes and counts recorded when it was written
    .DESCRIPTION
        Recomputes the SHA-256 of the backup file and of every item and compares them, and the item
        counts per type, with the integrity manifest written alongside the backup. Status is Verified,
        Corrupt, Missing, CountMismatch, or 'Unverified (pre-hash)' for backups written before hashing
        existed. Per-type results list missing, corrupt and unexpected item keys. Read-only.
        Parameters: BackupName (required), Type (Scheduled|CIPP, default Scheduled), tenantFilter
        (required for Scheduled; must own the backup).
        Aspendora fork addition (Vikunja CIPP-23).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $BackupName = [string]($Request.Body.BackupName ?? $Request.Query.BackupName)
    $Type = [string]($Request.Body.Type ?? $Request.Query.Type ?? 'Scheduled')
    $TenantFilter = [string]($Request.Body.tenantFilter ?? $Request.Query.tenantFilter)
    $Respond = { param($Code, $Body) [HttpResponseContext]@{ StatusCode = $Code; Body = $Body } }

    if (-not $BackupName) { return (& $Respond ([HttpStatusCode]::BadRequest) @{ Results = 'BackupName is required.' }) }
    if ($Type -notin @('Scheduled', 'CIPP')) { return (& $Respond ([HttpStatusCode]::BadRequest) @{ Results = 'Type must be Scheduled or CIPP.' }) }
    if ($Type -eq 'Scheduled' -and -not $TenantFilter) { return (& $Respond ([HttpStatusCode]::BadRequest) @{ Results = 'tenantFilter is required for tenant backups.' }) }

    try {
        $Report = Get-CIPPBackupIntegrityReport -Type $Type -Name $BackupName -TenantFilter $TenantFilter
    } catch {
        if ($_.Exception.Message -like '*does not belong to tenant*') {
            return (& $Respond ([HttpStatusCode]::Forbidden) @{ Results = $_.Exception.Message })
        }
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'ExecBackupVerify' -tenant $TenantFilter -message "Could not verify backup $($BackupName): $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return (& $Respond ([HttpStatusCode]::InternalServerError) @{ Results = "Could not verify backup: $($ErrorMessage.NormalizedError)" })
    }
    if (-not $Report) { return (& $Respond ([HttpStatusCode]::NotFound) @{ Results = "Backup $BackupName not found." }) }

    return (& $Respond ([HttpStatusCode]::OK) @{ Results = $Report })
}
