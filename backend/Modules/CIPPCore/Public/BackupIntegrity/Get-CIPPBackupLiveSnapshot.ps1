function Get-CIPPBackupLiveSnapshot {
    <#
    .FUNCTIONALITY
        Internal
    .SYNOPSIS
        Reads the tenant's current state in exactly the shape a scheduled backup stores. Read-only.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-23).

        Runs the same capture New-CIPPBackup uses (New-CIPPBackupTask) for each requested component
        and round-trips the result through JSON, as a backup file does, so Get-CIPPBackupItemList and
        the diff see the live tenant and the backup in identical form. Capture only issues GET requests
        (and table reads for the CIPP components); nothing in the tenant is changed.
    .PARAMETER TenantFilter
        The tenant to read.
    .PARAMETER Types
        Backup component names (users, groups, ca, intuneconfig, intunecompliance, intuneprotection, ...).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantFilter,
        [Parameter(Mandatory = $true)][string[]]$Types
    )
    $Snapshot = [ordered]@{}
    $Errors = [System.Collections.Generic.List[string]]::new()
    $FailedTypes = [System.Collections.Generic.List[string]]::new()
    foreach ($Type in $Types) {
        try {
            $Snapshot[$Type] = New-CIPPBackupTask -Task $Type -TenantFilter $TenantFilter
        } catch {
            $Errors.Add("Could not read current $Type from the tenant: $($_.Exception.Message)")
            $FailedTypes.Add($Type)
        }
    }
    $Json = ConvertTo-Json -InputObject $Snapshot -Depth 100 -Compress
    return [pscustomobject]@{
        Backup      = (ConvertFrom-Json -InputObject $Json -Depth 100 -NoEnumerate)
        Errors      = $Errors.ToArray()
        FailedTypes = $FailedTypes.ToArray()
    }
}
