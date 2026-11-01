function Get-CIPPAlertIntuneDuplicateDevices {
    <#
    .SYNOPSIS
        Alert on duplicate Intune device records (same serial number), with a cleanup recommendation
    .DESCRIPTION
        Groups beta deviceManagement/managedDevices by serial number (Find-CIPPDuplicateDeviceSerials: placeholder
        serials such as "Default string" and retired / wiped records are ignored). For each serial held by
        DuplicateMinRecords (default 2) or more records it recommends keeping the most recently synced record and
        lists the rest as cleanup candidates. REPORT ONLY: nothing is deleted or retired.
        State mode: Id = 'DupSerial|<serial>', so a serial notifies once and resolves when only one record is left.
        Aspendora fork addition (Vikunja CIPP-27).
    .FUNCTIONALITY
        Entrypoint
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Alias('input')]
        $InputValue,
        [Parameter(Mandatory)]
        $TenantFilter
    )
    $Min = 2
    $Parsed = 0
    if ($null -ne $InputValue.DuplicateMinRecords -and [int]::TryParse([string]$InputValue.DuplicateMinRecords, [ref]$Parsed) -and $Parsed -ge 2) { $Min = $Parsed }
    try {
        $Devices = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/deviceManagement/managedDevices?$select=id,deviceName,serialNumber,lastSyncDateTime,enrolledDateTime,operatingSystem,userPrincipalName,managementState&$top=999' -tenantid $TenantFilter -ErrorAction Stop)
    } catch {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Intune duplicate devices: could not read managed devices: $((Get-CippException -Exception $_).NormalizedError)" -sev Warning
        return
    }
    $Rows = foreach ($Dup in @(Find-CIPPDuplicateDeviceSerials -Devices $Devices | Where-Object { $_.Count -ge $Min })) {
        $Stale = @($Dup.Remove | ForEach-Object { "$($_.DeviceName) (last sync $(Format-CIPPCentralTime $_.LastSync), id $($_.Id))" })
        [pscustomobject]@{
            Id           = $Dup.Id
            SerialNumber = $Dup.Serial
            Records      = $Dup.Count
            Keep         = "$($Dup.Keep.DeviceName) (last sync $(Format-CIPPCentralTime $Dup.Keep.LastSync), id $($Dup.Keep.Id))"
            CleanUp      = $Stale -join '; '
            Message      = "Serial $($Dup.Serial) has $($Dup.Count) Intune records. Recommendation (not applied): keep $($Dup.Keep.DeviceName), the most recently synced, and delete the older record(s) $(@($Dup.Remove.DeviceName) -join ', ') after confirming they are the same physical device re-enrolled."
        }
    }
    Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data @($Rows)
}
