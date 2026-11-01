function ConvertTo-CIPPBackupBlobPath {
    <#
    .FUNCTIONALITY
        Internal
    .SYNOPSIS
        Turns a stored blob URL (Azure or Azurite) into the container/blob resource path New-CIPPAzStorageRequest takes.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-23). Same parsing as Get-CIPPBackup and
        Start-BackupRetentionCleanup; a value that is already a resource path is returned unchanged.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Url)
    if ($Url -like '*:10000/*') {
        $Parts = $Url -split ':10000/'
        if ($Parts.Count -gt 1) { return ($Parts[1] -split '/', 2)[-1] }
    } elseif ($Url -like '*.blob.core.windows.net/*') {
        return ($Url -split '.blob.core.windows.net/', 2)[-1]
    } else {
        $UrlMatch = [regex]::Match($Url, '^https?://[^/]+/(.+)$')
        if ($UrlMatch.Success) { return $UrlMatch.Groups[1].Value }
    }
    return $Url
}
