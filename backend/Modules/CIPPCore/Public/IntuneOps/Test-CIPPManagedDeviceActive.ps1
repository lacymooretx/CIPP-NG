function Test-CIPPManagedDeviceActive {
    <#
    .SYNOPSIS
        True when an Intune managed device is still under management (not retired, wiped or being deleted).
    .DESCRIPTION
        Pure function. managementState values starting retire*, wipe* or delete* mean the device is on its way out
        (retirePending, retireIssued, retireFailed, wipePending, wipeIssued, wipeFailed, deletePending); the
        *Canceled states mean the action was called off and the device is managed again. A device with no
        managementState is treated as active. Used by the Intune operational alerts so retired or wiped devices
        never raise stale, duplicate or compliance findings.
        Aspendora fork addition (Vikunja CIPP-27).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Device)
    $State = [string]$Device.managementState
    if (-not $State) { return $true }
    if ($State -match 'Canceled$') { return $true }
    return -not ($State -match '^(retire|wipe|delete)')
}
