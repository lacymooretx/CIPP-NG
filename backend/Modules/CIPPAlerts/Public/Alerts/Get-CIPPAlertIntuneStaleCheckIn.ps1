function Get-CIPPAlertIntuneStaleCheckIn {
    <#
    .SYNOPSIS
        Alert on Intune managed devices that have not checked in for X days
    .DESCRIPTION
        Reads beta deviceManagement/managedDevices and raises every device whose lastSyncDateTime is older than
        IntuneStaleDays (default 14). Retired, wiped and delete-pending devices are skipped
        (Test-CIPPManagedDeviceActive). This is the Intune check-in signal; StaleEntraDevices covers Entra sign-in
        activity and DeviceCompliance covers compliance state, so neither is duplicated here.
        State mode: rows carry Id = 'Stale|<managed device id>', so a device notifies once and resolves when it
        checks in again (or is retired). Times are US Central. Report only. Aspendora fork addition (Vikunja CIPP-27).
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
    $Days = 14
    $Parsed = 0
    if ($null -ne $InputValue.IntuneStaleDays -and [int]::TryParse([string]$InputValue.IntuneStaleDays, [ref]$Parsed) -and $Parsed -gt 0) { $Days = $Parsed }
    $Now = [datetime]::UtcNow
    $Cutoff = $Now.AddDays(-$Days)
    try {
        $Devices = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,osVersion,serialNumber,userPrincipalName,lastSyncDateTime,enrolledDateTime,managementState,ownerType,joinType&$top=999' -tenantid $TenantFilter -ErrorAction Stop)
    } catch {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Intune stale check-in: could not read managed devices: $((Get-CippException -Exception $_).NormalizedError)" -sev Warning
        return
    }
    $Rows = foreach ($D in $Devices) {
        if (-not $D.id -or -not (Test-CIPPManagedDeviceActive -Device $D)) { continue }
        $Last = if ($D.lastSyncDateTime -is [datetime]) { ([datetime]$D.lastSyncDateTime).ToUniversalTime() } elseif ($D.lastSyncDateTime) { ([datetimeoffset]$D.lastSyncDateTime).UtcDateTime } else { [datetime]::MinValue }
        if ($Last -gt $Cutoff) { continue }
        $Age = if ($Last.Year -gt 1) { [int][math]::Floor(($Now - $Last).TotalDays) } else { $null }
        [pscustomobject]@{
            Id              = "Stale|$($D.id)"
            DeviceName      = [string]$D.deviceName
            User            = [string]$D.userPrincipalName
            OS              = "$($D.operatingSystem) $($D.osVersion)".Trim()
            SerialNumber    = [string]$D.serialNumber
            Ownership       = [string]$D.ownerType
            LastCheckIn     = Format-CIPPCentralTime $D.lastSyncDateTime
            DaysSinceCheckIn = $Age
            Message         = if ($null -ne $Age) { "$($D.deviceName) has not checked in to Intune for $Age days (threshold $Days). Confirm it is still in use; if it was replaced, retire it so it stops counting against compliance and licensing." } else { "$($D.deviceName) has never checked in to Intune." }
        }
    }
    Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data @($Rows)
}
