function Get-CIPPBackupIntegrityReport {
    <#
    .FUNCTIONALITY
        Internal
    .SYNOPSIS
        Fetches a backup and its integrity manifest and verifies them (Test-CIPPBackupIntegrity).
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-23). Returns $null when the backup row does not exist.
        Throws when -TenantFilter does not own the backup (see Get-CIPPBackupContent).
    .PARAMETER Type
        'Scheduled' or 'CIPP'.
    .PARAMETER Name
        The backup name.
    .PARAMETER TenantFilter
        Tenant the backup must belong to (Scheduled backups).
    .PARAMETER Content
        An already loaded Get-CIPPBackupContent result, to avoid downloading the file twice.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Scheduled', 'CIPP')][string]$Type = 'Scheduled',
        [string]$Name,
        [string]$TenantFilter,
        $Content,
        [string]$ConnectionString = $env:AzureWebJobsStorage
    )

    if (-not $Content) { $Content = Get-CIPPBackupContent -Type $Type -Name $Name -TenantFilter $TenantFilter }
    if (-not $Content) { return $null }
    $Entity = $Content.Entity

    $Manifest = $null
    $ManifestJson = $null
    if ($Entity.ManifestBlob) {
        try {
            $Response = New-CIPPAzStorageRequest -Service 'blob' -Resource (ConvertTo-CIPPBackupBlobPath -Url ([string]$Entity.ManifestBlob)) -Method 'GET' -ConnectionString $ConnectionString
            if ($Response -and $Response.Bytes) {
                $ManifestJson = [System.Text.Encoding]::UTF8.GetString($Response.Bytes).TrimStart([char]0xFEFF)
                $Manifest = ConvertFrom-Json -InputObject $ManifestJson -Depth 100 -ErrorAction Stop
            }
        } catch {
            Write-Warning "Could not read integrity manifest for $($Entity.RowKey): $($_.Exception.Message)"
        }
    }

    $Result = Test-CIPPBackupIntegrity -BackupJson $Content.Json -Manifest $Manifest -ManifestJson $ManifestJson -Entity $Entity
    $Result | Add-Member -NotePropertyMembers ([ordered]@{
            BackupName   = [string]$Entity.RowKey
            BackupType   = $Type
            TenantFilter = $Content.TenantFilter
            Timestamp    = $Entity.Timestamp
        }) -Force
    return $Result
}
