function Get-CIPPAlertIntuneNewDevices {
    <#
    .SYNOPSIS
        Daily digest of devices newly enrolled in Intune
    .DESCRIPTION
        Reads beta deviceManagement/managedDevices and raises every device whose enrolledDateTime falls within the last
        NewDeviceLookbackHours (default 24; run daily). The date is compared client-side, so no unverified $filter is
        relied on. The scheduled alert sends all rows of a run as one notification, which is the digest.
        Event mode (Write-AlertTrace -Append, Id = 'NewDevice|<managed device id>'): each enrollment is announced once
        even when the look-back window overlaps the previous run. Report only. Aspendora fork addition (Vikunja CIPP-27).
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
    $Hours = 24
    $Parsed = 0
    if ($null -ne $InputValue.NewDeviceLookbackHours -and [int]::TryParse([string]$InputValue.NewDeviceLookbackHours, [ref]$Parsed) -and $Parsed -gt 0) { $Hours = $Parsed }
    $Cutoff = [datetime]::UtcNow.AddHours(-$Hours)
    try {
        $Devices = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,osVersion,serialNumber,model,manufacturer,userPrincipalName,enrolledDateTime,deviceEnrollmentType,joinType,ownerType,complianceState&$top=999' -tenantid $TenantFilter -ErrorAction Stop)
    } catch {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Intune new devices: could not read managed devices: $((Get-CippException -Exception $_).NormalizedError)" -sev Warning
        return
    }
    $Rows = foreach ($D in $Devices) {
        if (-not $D.id -or -not $D.enrolledDateTime) { continue }
        $Enrolled = if ($D.enrolledDateTime -is [datetime]) { ([datetime]$D.enrolledDateTime).ToUniversalTime() } else { ([datetimeoffset]$D.enrolledDateTime).UtcDateTime }
        if ($Enrolled -lt $Cutoff) { continue }
        [pscustomobject]@{
            Id             = "NewDevice|$($D.id)"
            DeviceName     = [string]$D.deviceName
            User           = [string]$D.userPrincipalName
            Enrolled       = Format-CIPPCentralTime $D.enrolledDateTime
            OS             = "$($D.operatingSystem) $($D.osVersion)".Trim()
            Model          = "$($D.manufacturer) $($D.model)".Trim()
            SerialNumber   = [string]$D.serialNumber
            EnrollmentType = [string]$D.deviceEnrollmentType
            Ownership      = [string]$D.ownerType
            Compliance     = [string]$D.complianceState
            Message        = "New Intune enrollment: $($D.deviceName) ($($D.operatingSystem), $($D.ownerType)) for $(if ($D.userPrincipalName) { $D.userPrincipalName } else { 'no primary user' })."
        }
    }
    if (@($Rows).Count -eq 0) { return }
    @(Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data @($Rows) -Append | Where-Object { $_ })
}
