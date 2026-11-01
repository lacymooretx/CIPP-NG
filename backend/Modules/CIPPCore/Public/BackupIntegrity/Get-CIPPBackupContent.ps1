function Get-CIPPBackupContent {
    <#
    .FUNCTIONALITY
        Internal
    .SYNOPSIS
        Loads one backup's table row and file content, optionally checking it belongs to a tenant.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-23).

        Returns $null when no row with that name exists. Otherwise
        [pscustomobject]@{ Entity; Json; Readable; TenantFilter }, where Json is the file content
        (blob-backed backups are downloaded by Get-CIPPBackup) or $null when the blob could not be read.
        -TenantFilter throws when a Scheduled backup belongs to a different tenant, so a caller with
        access to one tenant cannot read another tenant's backup by name.
    .PARAMETER Type
        'Scheduled' (tenant backups) or 'CIPP' (core settings backups).
    .PARAMETER Name
        The backup name (RowKey).
    .PARAMETER TenantFilter
        For Scheduled backups: the tenant the backup must belong to.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Scheduled', 'CIPP')][string]$Type = 'Scheduled',
        [Parameter(Mandatory = $true)][string]$Name,
        [string]$TenantFilter
    )

    $Rows = @(Get-CIPPBackup -Type $Type -Name $Name)
    $Entity = $Rows | Where-Object { $_.RowKey -eq $Name } | Select-Object -First 1
    if (-not $Entity) { $Entity = $Rows | Select-Object -First 1 }
    if (-not $Entity) { return $null }

    $BackupTenant = [string]$Entity.TenantFilter
    if (-not $BackupTenant -and $Type -eq 'Scheduled') {
        $NameMatch = [regex]::Match([string]$Entity.RowKey, '^(.+)_\d{4}-\d{2}-\d{2}-\d{4}$')
        if ($NameMatch.Success) { $BackupTenant = $NameMatch.Groups[1].Value }
    }
    if ($Type -eq 'Scheduled' -and $TenantFilter -and $TenantFilter -ne 'AllTenants' -and $BackupTenant -ne $TenantFilter) {
        throw "Backup $Name does not belong to tenant $TenantFilter."
    }

    $Content = $Entity.Backup
    if ($null -eq $Content -and $Type -eq 'Scheduled' -and $null -eq $Entity.PSObject.Properties['Backup']) {
        # Legacy table-stored tenant backup: the components are columns on the row itself.
        $Content = $Entity | Select-Object * -ExcludeProperty ETag, Timestamp, BackupIsBlob, BackupIsBlobLink, BlobResourcePath, OriginalEntityId, SplitOverProps, PartIndex, HashVersion, BackupSha256, ManifestBlob, ManifestSha256, ItemCounts
    }
    if ($Content -isnot [string] -and $null -ne $Content) {
        $Content = ConvertTo-Json -InputObject $Content -Depth 100 -Compress
    }
    # Get-CIPPBackup leaves the blob URL in place when the download fails.
    $Readable = -not [string]::IsNullOrWhiteSpace($Content) -and $Content -notmatch '^https?://'
    return [pscustomobject]@{
        Entity       = $Entity
        Json         = if ($Readable) { [string]$Content } else { $null }
        Readable     = $Readable
        TenantFilter = $BackupTenant
    }
}
