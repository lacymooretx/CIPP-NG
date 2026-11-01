function Find-CIPPDuplicateDeviceSerials {
    <#
    .SYNOPSIS
        Groups Intune managed devices that share a serial number and recommends which record to keep.
    .DESCRIPTION
        Pure function. Serials are compared trimmed and case-insensitively. Placeholder serials that firmware vendors
        and hypervisors ship (Default string, To be filled by O.E.M., System Serial Number, 0, 0123456789, ...) are
        ignored: they collide across unrelated machines and would only produce noise. Retired / wiped devices are
        ignored (Test-CIPPManagedDeviceActive).
        For each serial with two or more records the most recently synced record is the one to Keep; the others are
        cleanup candidates. Nothing is deleted: this is a report and a recommendation only.
        Returns one object per serial: @{ Id = 'DupSerial|<SERIAL>'; Serial; Count; Keep; Remove; Devices }.
        Aspendora fork addition (Vikunja CIPP-27).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([object[]]$Devices = @())

    $Placeholders = @(
        '', '0', '00000000', '0000000000', '123456789', '0123456789', '1234567890', 'none', 'n/a', 'na', 'null', 'unknown',
        'default string', 'defaultstring', 'to be filled by o.e.m.', 'to be filled by oem', 'system serial number',
        'chassis serial number', 'not applicable', 'not specified', 'invalid', 'oem', 'serial', 'xxxxxxxxxx'
    )
    $Groups = @{}
    foreach ($D in @($Devices)) {
        if ($null -eq $D -or -not $D.id) { continue }
        if (-not (Test-CIPPManagedDeviceActive -Device $D)) { continue }
        $Serial = ([string]$D.serialNumber).Trim()
        if ($Serial.ToLowerInvariant() -in $Placeholders) { continue }
        if ($Serial -match '^0+$') { continue }
        $Key = $Serial.ToUpperInvariant()
        if (-not $Groups.ContainsKey($Key)) { $Groups[$Key] = [System.Collections.Generic.List[object]]::new() }
        $Groups[$Key].Add($D)
    }

    $SyncOf = {
        param($Device)
        $Parsed = [datetime]::MinValue
        # PowerShell 7 ConvertFrom-Json already turns ISO strings into [datetime].
        if ($Device.lastSyncDateTime -is [datetime]) { return ([datetime]$Device.lastSyncDateTime).ToUniversalTime() }
        if ($Device.lastSyncDateTime -and [datetime]::TryParse([string]$Device.lastSyncDateTime, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$Parsed)) { return $Parsed }
        return [datetime]::MinValue
    }

    $Out = [System.Collections.Generic.List[object]]::new()
    foreach ($Key in @($Groups.Keys | Sort-Object)) {
        $Members = @($Groups[$Key])
        if ($Members.Count -lt 2) { continue }
        $Sorted = @($Members | Sort-Object -Property @{ Expression = { & $SyncOf $_ }; Descending = $true }, @{ Expression = { [string]$_.id } })
        $Keep = $Sorted[0]
        $Remove = @($Sorted | Select-Object -Skip 1)
        $Out.Add([pscustomobject]@{
                Id      = "DupSerial|$Key"
                Serial  = $Key
                Count   = $Members.Count
                Keep    = [pscustomobject]@{ Id = [string]$Keep.id; DeviceName = [string]$Keep.deviceName; LastSync = [string]$Keep.lastSyncDateTime }
                Remove  = @($Remove | ForEach-Object { [pscustomobject]@{ Id = [string]$_.id; DeviceName = [string]$_.deviceName; LastSync = [string]$_.lastSyncDateTime } })
                Devices = @($Sorted | ForEach-Object { [string]$_.deviceName })
            })
    }
    return $Out.ToArray()
}
